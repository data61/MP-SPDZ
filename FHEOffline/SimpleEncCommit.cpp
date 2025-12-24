/*
 * SimpleEncCommit.cpp
 *
 */

#include <FHEOffline/SimpleEncCommit.h>
#include "FHEOffline/SimpleMachine.h"
#include "FHEOffline/Multiplier.h"
#include "FHEOffline/PairwiseGenerator.h"
#include "Tools/Subroutines.h"
#include "Protocols/MAC_Check.h"

#include "Protocols/MAC_Check.hpp"
#include "Math/modp.hpp"

template<class T, class FD, class S>
SimpleEncCommitBase<T, FD, S>::SimpleEncCommitBase(const MachineBase& machine) :
        EncCommitBase_<FD>(&machine),
        extra_slack(machine.extra_slack), n_rounds(0)
{
}

template<class T,class FD,class S>
SimpleEncCommit<T, FD, S>::SimpleEncCommit(const PlayerBase& P, const FHE_PK& pk,
        const FD& FTD, map<string, Timer>& timers, const MachineBase& machine,
        int thread_num, bool diagonal) :
    NonInteractiveProofSimpleEncCommit<FD>(P, pk, FTD, timers, machine,
            diagonal),
    SimpleEncCommitFactory<FD>(pk)
{
    (void)thread_num;
    this->init(this->proof, FTD);
}

template <class FD>
NonInteractiveProofSimpleEncCommit<FD>::NonInteractiveProofSimpleEncCommit(
        const PlayerBase& P, const FHE_PK& pk, const FD& FTD,
        map<string, Timer>& timers, const MachineBase& machine,
        bool diagonal) :
        SimpleEncCommitBase_<FD>(machine),
        P(P), pk(pk), FTD(FTD),
        proof(machine.sec, pk, machine.extra_slack, diagonal),
#ifdef LESS_ALLOC_MORE_MEM
                r(proof.U, this->pk.get_params()), prover(proof, FTD),
                verifier(proof, FTD),
#endif
                timers(timers)
{
}

template <class FD>
SimpleEncCommitFactory<FD>::SimpleEncCommitFactory(const FHE_PK& pk) :
        cnt(-1), n_calls(0), pk(pk)
{
}

template<class FD>
void SimpleEncCommitFactory<FD>::init(const Proof& proof, const FD& FTD)
{
    int sec = proof.U;
    c.resize(sec, pk.get_params());
    m.resize(sec, FTD);
    for (int i = 0; i < sec; i++)
    {
        m[i].assign_zero(Polynomial);
    }
}

template <class FD>
SimpleEncCommitFactory<FD>::~SimpleEncCommitFactory()
{
#ifdef VERBOSE_HE
    if (n_calls > 0)
        cout << "EncCommit called " << n_calls << " times" << endl;
#endif
}

template<class FD>
void SimpleEncCommitFactory<FD>::next(Plaintext_<FD>& mess, Ciphertext& C)
{
    if (not has_left())
        create_more();
    mess = m[cnt];
    C = c[cnt];

    if (get_proof().use_top_gear(pk))
    {
        mess = mess + mess;
        C = C + C;
    }

    cnt--;
    n_calls++;
}

template <class FD>
void SimpleEncCommitFactory<FD>::prepare_plaintext(PRNG& G)
{
    for (auto& mess : m)
        if (get_proof().get_diagonal())
            mess.randomize(G, Diagonal);
        else
            mess.randomize(G);
}

template<class T,class FD,class S>
void SimpleEncCommitBase<T, FD, S>::generate_ciphertexts(
        AddableVector<Ciphertext>& c, const vector<Plaintext_<FD> >& m,
        Proof::Randomness& r, const FHE_PK& pk, TimerMap& timers,
        Proof& proof)
{
    timers["Generating"].start();
    PRNG G;
    G.ReSeed();
    prepare_plaintext(G);
    Random_Coins rc(pk.get_params());
    c.resize(proof.U, pk);
    r.resize(proof.U, pk);
    for (unsigned i = 0; i < proof.U; i++)
    {
        r[i].sample(G);
        rc.assign(r[i]);
        pk.encrypt(c[i], m.at(i), rc);
    }
    timers["Generating"].stop();
    memory_usage.update("random coins", rc.report_size(CAPACITY));
}

template <class FD>
size_t NonInteractiveProofSimpleEncCommit<FD>::generate_proof(AddableVector<Ciphertext>& c,
        vector<Plaintext_<FD> >& m, octetStream& ciphertexts,
        octetStream& cleartexts)
{
    timers["Proving"].start();
#ifndef LESS_ALLOC_MORE_MEM
    Proof::Randomness r(proof.U, pk.get_params());
#endif
    this->generate_ciphertexts(c, m, r, pk, timers, proof);
#ifndef LESS_ALLOC_MORE_MEM
    Prover<FD, Plaintext_<FD> > prover(proof, FTD);
#endif
    size_t prover_memory = prover.NIZKPoK(proof, ciphertexts, cleartexts,
            pk, c, m, r);
    timers["Proving"].stop();

    if (proof.top_gear)
    {
        c += c;
        for (auto& mm : m)
            mm += mm;
    }

    // cout << "Checking my own proof" << endl;
    // if (!Verifier<gfp>().NIZKPoK(c[P.my_num()], proofs[P.my_num()], pk, false, false))
    // 	throw runtime_error("proof check failed");
    this->memory_usage.update("randomness", r.report_size(CAPACITY));
    prover.report_size(CAPACITY, this->memory_usage);
    return r.report_size(CAPACITY) + prover_memory;
}

template<class T,class FD,class S>
void SimpleEncCommit<T,FD,S>::create_more()
{
    CODE_LOCATION
    cout << "Generating more ciphertexts in round " << this->n_rounds << endl;
    octetStream ciphertexts, cleartexts;
    size_t prover_memory = this->generate_proof(this->c, this->m, ciphertexts, cleartexts);
    size_t verifier_memory =
            NonInteractiveProofSimpleEncCommit<FD>::create_more(ciphertexts,
                    cleartexts);
    cout << "Done checking proofs in round " << this->n_rounds << endl;
    this->n_rounds++;
    this->cnt = this->proof.U - 1;
    this->memory_usage.update("serialized ciphertexts",
            ciphertexts.get_max_length());
    this->memory_usage.update("serialized cleartexts", cleartexts.get_max_length());
    this->volatile_memory = max(prover_memory, verifier_memory)
            + ciphertexts.get_max_length() + cleartexts.get_max_length();
}

template <class FD>
size_t NonInteractiveProofSimpleEncCommit<FD>::create_more(octetStream& ciphertexts,
        octetStream& cleartexts)
{
    CODE_LOCATION
    AddableVector<Ciphertext> others_ciphertexts;
    others_ciphertexts.resize(proof.U, pk.get_params());
    for (int i = 1; i < P.num_players(); i++)
    {
#ifdef VERBOSE_HE
        cerr << "Sending proof with " << 1e-9 * ciphertexts.get_length() << "+"
                << 1e-9 * cleartexts.get_length() << " GB" << endl;
#endif
        timers["Sending"].start();
        P.pass_around(ciphertexts);
        P.pass_around(cleartexts);
        timers["Sending"].stop();
#ifndef LESS_ALLOC_MORE_MEM
        Verifier<FD,S> verifier(proof);
#endif
#ifdef VERBOSE_HE
        cerr << "Checking proof of player " << i << endl;
#endif
        timers["Verifying"].start();
        verifier.NIZKPoK(others_ciphertexts, ciphertexts,
                cleartexts, get_pk_for_verification(i));
        timers["Verifying"].stop();
        add_ciphertexts(others_ciphertexts, i);
        this->memory_usage.update("verifier", verifier.report_size(CAPACITY));
    }
    this->memory_usage.update("cleartexts", cleartexts.get_max_length());
    this->memory_usage.update("others' ciphertexts", others_ciphertexts.report_size(CAPACITY));
#ifdef LESS_ALLOC_MORE_MEM
    return others_ciphertexts.report_size(CAPACITY);
#else
    return others_ciphertexts.report_size(CAPACITY)
            + this->memory_usage.get("verifier");
#endif
}

template<class T, class FD, class S>
void SimpleEncCommit<T, FD, S>::add_ciphertexts(
        vector<Ciphertext>& ciphertexts, int offset)
{
    (void)offset;
    for (unsigned j = 0; j < this->proof.U; j++)
        add(this->c[j], this->c[j], ciphertexts[j]);
}

template<class FD>
SummingEncCommit<FD>::SummingEncCommit(const Player& P, const FHE_PK& pk,
        const FD& FTD, map<string, Timer>& timers, const MachineBase& machine,
        int thread_num, bool diagonal) :
        SimpleEncCommitFactory<FD>(pk), SimpleEncCommitBase_<FD>(
                machine), proof(machine.sec, pk, P.num_players(), diagonal), pk(pk), FTD(
                FTD), P(P), thread_num(thread_num),
#ifdef LESS_ALLOC_MORE_MEM
                prover(proof, FTD), verifier(proof, FTD), preimages(proof.V,
                        this->pk, FTD.get_prime(), P.num_players()),
#endif
                timers(timers)
{
    this->init(proof, FTD);
}

template<class FD>
void SummingEncCommit<FD>::create_more()
{
    CODE_LOCATION
    octetStream cleartexts;
    const Player& P = this->P;
    AddableVector<Ciphertext> commitments;
    size_t prover_size;
    MemoryUsage& memory_usage = this->memory_usage;
    TreeSum<Ciphertext> tree_sum(2, 2, thread_num % P.num_players());
    octetStream& ciphertexts = tree_sum.get_buffer();

    {
#ifdef LESS_ALLOC_MORE_MEM
        Proof::Randomness& r = preimages.r;
#else
        Proof::Randomness r(proof.U, this->pk.get_params());
        Prover<FD, Plaintext_<FD> > prover(proof, this->FTD);
#endif
        this->generate_ciphertexts(this->c, this->m, r, pk, timers, proof);
        this->timers["Stage 1 of proof"].start();
        prover.Stage_1(proof, ciphertexts, this->c, this->pk);
        this->timers["Stage 1 of proof"].stop();

        this->c.unpack(ciphertexts, this->pk);
        commitments.unpack(ciphertexts, this->pk);

        if (OnlineOptions::singleton.has_option("verbose_he"))
            cerr << "Tree-wise sum of " << this->c.size()
                    << " ciphertexts with " << 1e-9 * ciphertexts.get_length()
                    << " GB" << endl;

        this->timers["Exchanging ciphertexts"].start();
        tree_sum.run(this->c, P);
        tree_sum.run(commitments, P);
        this->timers["Exchanging ciphertexts"].stop();

        proof.generate_challenge(P);

        this->timers["Stage 2 of proof"].start();
        prover.Stage_2(proof, cleartexts, this->m, r, pk);
        this->timers["Stage 2 of proof"].stop();

        prover_size = prover.report_size(CAPACITY) + r.report_size(CAPACITY)
                + prover.volatile_memory;
        memory_usage.update("prover", prover.report_size(CAPACITY));
        memory_usage.update("randomness", r.report_size(CAPACITY));
    }

#ifndef LESS_ALLOC_MORE_MEM
    Proof::Preimages preimages(proof.V, this->pk, this->FTD.get_prime(),
        P.num_players());
#endif
    preimages.unpack(cleartexts);

    this->timers["Committing"].start();
    AllCommitments cleartext_commitments(P);
    cleartext_commitments.commit_and_open(cleartexts);
    this->timers["Committing"].stop();

    for (int i = 1; i < P.num_players(); i++)
    {
#ifdef VERBOSE_HE
        cout << "Sending cleartexts with " << 1e-9 * cleartexts.get_length()
                << " GB in round " << i << endl;
#endif
        TimeScope(this->timers["Exchanging cleartexts"]);
        P.pass_around(cleartexts);
        preimages.add(cleartexts);
        cleartext_commitments.check_relative(i, cleartexts);
    }

    ciphertexts.reset_write_head();
    this->c.pack(ciphertexts);
    commitments.pack(ciphertexts);
    cleartexts.clear();
    cleartexts.resize_precise(preimages.report_size(USED));
    preimages.pack(cleartexts);
    this->timers["Verifying"].start();
#ifdef LESS_ALLOC_MORE_MEM
    Verifier<FD>& verifier = this->verifier;
#else
    Verifier<FD> verifier(proof);
#endif
    verifier.Stage_2(this->c, ciphertexts, cleartexts,
            this->pk);
    this->timers["Verifying"].stop();
    this->cnt = proof.U - 1;

    this->volatile_memory =
            + commitments.report_size(CAPACITY) + ciphertexts.get_max_length()
            + cleartexts.get_max_length()
            + max(prover_size, preimages.report_size(CAPACITY))
            + tree_sum.report_size(CAPACITY);
    memory_usage.update("verifier", verifier.report_size(CAPACITY));
    memory_usage.update("preimages", preimages.report_size(CAPACITY));
    memory_usage.update("commitments", commitments.report_size(CAPACITY));
    memory_usage.update("received cleartexts", cleartexts.get_max_length());
    memory_usage.update("tree sum", tree_sum.report_size(CAPACITY));
}

template <class FD>
size_t NonInteractiveProofSimpleEncCommit<FD>::report_size(ReportType type)
{
#ifdef LESS_ALLOC_MORE_MEM
    return r.report_size(type) +
        prover.report_size(type) + verifier.report_size(type);
#else
    (void)type;
    return 0;
#endif
}

template <class FD>
size_t SimpleEncCommitFactory<FD>::report_size(ReportType type)
{
    return m.report_size(type) + c.report_size(type);
}

template<class FD>
void SimpleEncCommitFactory<FD>::report_size(ReportType type, MemoryUsage& res)
{
    res.add("my plaintexts", m.report_size(type));
    res.add("my ciphertexts", c.report_size(type));
}

template<class FD>
size_t SummingEncCommit<FD>::report_size(ReportType type)
{
#ifdef LESS_ALLOC_MORE_MEM
    return prover.report_size(type) + preimages.report_size(type);
#else
    (void)type;
    return 0;
#endif
}

template <class FD>
MultiEncCommit<FD>::MultiEncCommit(const Player& P, const vector<FHE_PK>& pks,
        const FD& FTD, map<string, Timer>& timers, MachineBase& machine,
        PairwiseGenerator<FD>& generator, bool diagonal) :
        NonInteractiveProofSimpleEncCommit<FD>(P, pks[P.my_real_num()], FTD,
                timers, machine, diagonal), pks(pks), P(P), generator(generator)
{
}

template <class FD>
void MultiEncCommit<FD>::add_ciphertexts(vector<Ciphertext>& ciphertexts,
        int offset)
{
    for (unsigned i = 0; i < this->proof.U; i++)
        generator.multipliers[offset - 1]->multiply_and_add(generator.c.at(i),
                ciphertexts.at(i), generator.b_mod_q.at(i));
}

template class SimpleEncCommitBase<gfp, FFT_Data, bigint>;
template class SimpleEncCommit<gfp, FFT_Data, bigint>;
template class SimpleEncCommitFactory<FFT_Data>;
template class SummingEncCommit<FFT_Data>;
template class NonInteractiveProofSimpleEncCommit<FFT_Data>;
template class MultiEncCommit<FFT_Data>;

template class SimpleEncCommitBase<gf2n_short, P2Data, int>;
template class SimpleEncCommit<gf2n_short, P2Data, int>;
template class SimpleEncCommitFactory<P2Data>;
template class SummingEncCommit<P2Data>;
template class NonInteractiveProofSimpleEncCommit<P2Data>;
template class MultiEncCommit<P2Data>;
