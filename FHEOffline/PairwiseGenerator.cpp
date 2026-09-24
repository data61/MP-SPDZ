/*
 * PairwiseGenerator.cpp
 *
 */

#include "FHEOffline/PairwiseGenerator.h"
#include "FHEOffline/PairwiseMachine.h"
#include "FHEOffline/Producer.h"
#include "Protocols/SemiShare.h"
#include "GC/SemiSecret.h"
#include "GC/SemiPrep.h"

#include "Protocols/MAC_Check.hpp"
#include "Protocols/SemiInput.hpp"
#include "Protocols/ReplicatedInput.hpp"
#include "Processor/Input.hpp"
#include "Math/modp.hpp"

template <class FD>
PairwiseGenerator<FD>::PairwiseGenerator(int thread_num,
        PairwiseMachine& machine, Player* player) :
    GeneratorBase(thread_num, machine.N, player),
    producer(machine.setup<FD>().FieldD, P.my_num(),
            thread_num, machine.output, machine.get_prep_dir<FD>(P)),
    EC(P, machine.other_pks, machine.setup<FD>().FieldD, timers, machine, *this),
    MC(machine.setup<FD>().alphai),
    n_ciphertexts(EC.proof.U),
    C(n_ciphertexts, machine.setup<FD>().params), volatile_memory(0),
    machine(machine)
{
    for (int i = 1; i < P.num_players(); i++)
        multipliers.push_back(new Multiplier<FD>(i, *this));
    const FD& FieldD = machine.setup<FD>().FieldD;
    a.resize(n_ciphertexts, FieldD);
    b.resize(n_ciphertexts, FieldD);
    c.resize(n_ciphertexts, FieldD);
    a.allocate_slots(FieldD.get_prime());
    b.allocate_slots(FieldD.get_prime());
    // extra limb for addition
    c.allocate_slots((bigint)FieldD.get_prime() << 64);
    b_mod_q.resize(n_ciphertexts,
    { machine.setup<FD>().params, evaluation, evaluation });
}

template <class FD>
PairwiseGenerator<FD>::~PairwiseGenerator()
{
    for (auto m : multipliers)
        delete m;
}

template <class FD>
void PairwiseGenerator<FD>::run()
{
    CODE_LOCATION
    PRNG G;
    G.ReSeed();
    total = 0;
    producer.triples.clear();

    while (total < machine.nTriplesPerThread)
    {
        timers["Randomization"].start();
        a.randomize(G);
        b.randomize(G);
        timers["Randomization"].stop();
        EC.get_proof().set_session_id(P);
        size_t prover_memory = EC.generate_proof(C, a, ciphertexts, cleartexts);
        timers["Plaintext multiplication"].start();
        c.mul(a, b);
        timers["Plaintext multiplication"].stop();
        timers["FFT of b"].start();
        for (int i = 0; i < n_ciphertexts; i++)
            b_mod_q.at(i).from(b.at(i).get_iterator());
        timers["FFT of b"].stop();
        timers["Proof exchange"].start();
        size_t verifier_memory = EC.create_more(ciphertexts, cleartexts);
        timers["Proof exchange"].stop();
        volatile_memory = max(prover_memory, verifier_memory);

        Rq_Element values({machine.setup<FD>().params, evaluation, evaluation});
        for (int k = 0; k < n_ciphertexts; k++)
        {
            producer.ai = a[k];
            producer.bi = b[k];
            producer.ci = c[k];

            for (int j = 0; j < 3; j++)
            {
                timers["Plaintext multiplication"].start();
                producer.macs[j].mul(machine.setup<FD>().alpha, producer.values[j]);
                timers["Plaintext multiplication"].stop();

                if (j == 1)
                    values = b_mod_q[k];
                else
                {
                    timers["Plaintext conversion"].start();
                    values.from(producer.values[j].get_iterator());
                    timers["Plaintext conversion"].stop();
                }

                for (auto m : multipliers)
                    m->multiply_alpha_and_add(producer.macs[j], values);
            }
            producer.reset();
            total += producer.sacrifice(P, MC);
        }

        timers["Checking"].start();
        MC.Check(P);
        timers["Checking"].stop();
    }

#ifdef FHE_MEMORY
    cerr << "Could save " << 1e-9 * a.report_size(CAPACITY) << " GB" << endl;
#endif
    timers.insert(EC.timers.begin(), EC.timers.end());
    timers.insert(producer.timers.begin(), producer.timers.end());
    timers["Networking"] = P.timer;
}

template <class FD>
void PairwiseGenerator<FD>::generate_inputs(int player)
{
    CODE_LOCATION
    bool mine = player == P.my_num();
    if (mine)
    {
        SeededPRNG G;
        b[0].randomize(G);
        b_mod_q.at(0).from(b.at(0).get_iterator());
        producer.macs[0].mul(machine.setup<FD>().alpha, b[0]);
    }
    else
        producer.macs[0].assign_zero();

    for (auto m : multipliers)
        if (mine or P.get_player(m->get_offset()) == player)
            m->multiply_alpha_and_add(producer.macs[0], b_mod_q[0], mine ? SENDER : RECEIVER);

    inputs.clear();
    Share<T> check_value;
    GlobalPRNG G(P);
    SemiInput<SemiShare<T>> input(0, P);
    input.reset_all(P);
    for (size_t i = 0; i < b[0].num_slots(); i++)
    {
        input.add_mine(b[0].element(i));
    }
    input.exchange();
    for (size_t i = 0; i < b[0].num_slots(); i++)
    {
        Share<T> share(input.finalize(player), producer.macs[0].element(i));
        inputs.push_back({share, b[0].element(i)});
        check_value += G.get<T>() * share;
    }
    inputs.pop_back();
    MC.POpen(check_value, P);
    MC.Check(P);
}

template <class FD>
size_t PairwiseGenerator<FD>::report_size(ReportType type)
{
    size_t res = a.report_size(type) + b.report_size(type) + c.report_size(type);
    for (auto m : multipliers)
        res += m->report_size(type);
    res += producer.report_size(type);
    res += multipliers[0]->report_volatile();
    res += volatile_memory + C.report_size(type);
    res += ciphertexts.get_max_length() + cleartexts.get_max_length();
    res += EC.report_size(type) + EC.volatile_memory;
    res += b_mod_q.report_size(type);
    return res;
}

template <class FD>
size_t PairwiseGenerator<FD>::report_sent()
{
    return P.total_comm().sent;
}

template <class FD>
void PairwiseGenerator<FD>::report_size(ReportType type, MemoryUsage& res)
{
    multipliers[0]->report_size(type, res);
    res.add("shares",
            a.report_size(type) + b.report_size(type) + c.report_size(type));
    res.add("producer", producer.report_size(type));
    res.add("my ciphertexts", C.report_size(CAPACITY));
    res.add("serialized ciphertexts", ciphertexts.get_max_length());
    res.add("serialized cleartexts", cleartexts.get_max_length());
    res.add("generator volatile", volatile_memory);
    res.add("b mod p", b_mod_q.report_size(type));
    res += EC.memory_usage;
}

template class PairwiseGenerator<FFT_Data>;
template class PairwiseGenerator<P2Data>;
