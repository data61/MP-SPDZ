/*
 * Multiplier.cpp
 *
 */

#include <FHEOffline/Multiplier.h>
#include "FHEOffline/PairwiseGenerator.h"
#include "FHEOffline/PairwiseMachine.h"

#include "Math/modp.hpp"

template <class FD>
Multiplier<FD>::Multiplier(int offset, PairwiseGenerator<FD>& generator) :
        Multiplier(offset, generator.machine, generator.P, generator.timers)
{
}

template <class FD>
Multiplier<FD>::Multiplier(int offset, PairwiseMachine& machine, Player& P,
        map<string, Timer>& timers) :
    machine(machine),
    P(P, offset),
    num_players(P.num_players()),
    my_num(P.my_num()),
    key_index((my_num + num_players - offset) % num_players),
    timers(timers),
    C(machine.pk), mask(machine.pk),
    product_share(machine.setup<FD>().FieldD), rc(machine.pk),
    volatile_capacity(0)
{
    product_share.allocate_slots(machine.pk.p() << 64);
}

template <class FD>
void Multiplier<FD>::multiply_and_add(Plaintext_<FD>& res,
        const Ciphertext& enc_a, const Plaintext_<FD>& b)
{
    Rq_Element bb(enc_a.get_params(), evaluation, evaluation);
    bb.from(b.get_iterator());
    multiply_and_add(res, enc_a, bb);
}

template <class FD>
void Multiplier<FD>::multiply_and_add(Plaintext_<FD>& res,
        const Ciphertext& enc_a, const Rq_Element& b, OT_ROLE role)
{
    if (role & SENDER)
    {
        timers["Ciphertext multiplication"].start();
        C.mul(enc_a, b);
        timers["Ciphertext multiplication"].stop();
    }

    add(res, C, role);
}

template <class FD>
void Multiplier<FD>::add(Plaintext_<FD>& res, const Ciphertext& c,
        OT_ROLE role, int)
{
    CODE_LOCATION
    o.reset_write_head();

    auto other_pk = machine.other_pks.at(key_index);

    if (role & SENDER)
    {
        PRNG G;
        G.ReSeed();
        timers["Mask randomization"].start();
        product_share.randomize(G);
        mask = c;
        mask.rerandomize(other_pk);
        timers["Mask randomization"].stop();
        mask += product_share;
        mask.pack(o);
        res -= product_share;
    }

    timers["Multiplied ciphertext sending"].start();
    if (role == BOTH)
        P.reverse_exchange(o);
    else if (role == SENDER)
        P.reverse_send(o);
    else if (role == RECEIVER)
        P.receive(o);
    timers["Multiplied ciphertext sending"].stop();

    if (role & RECEIVER)
    {
        timers["Decryption"].start();
        C.unpack(o);
        machine.sk.decrypt_any(product_share, C);
        res += product_share;
        timers["Decryption"].stop();
    }

    memory_usage.update("multiplied ciphertext", C.report_size(CAPACITY));
    memory_usage.update("mask ciphertext", mask.report_size(CAPACITY));
    memory_usage.update("product shares", product_share.report_size(CAPACITY));
    memory_usage.update("masking random coins", rc.report_size(CAPACITY));
}

template <class FD>
void Multiplier<FD>::multiply_alpha_and_add(Plaintext_<FD>& res,
        const Rq_Element& b, OT_ROLE role)
{
    auto& other_enc_alpha = machine.enc_alphas.at(key_index);
    multiply_and_add(res, other_enc_alpha, b, role);
}

template <class FD>
size_t Multiplier<FD>::report_size(ReportType type)
{
    return C.report_size(type) + mask.report_size(type)
            + product_share.report_size(type) + rc.report_size(type);
}

template <class FD>
void Multiplier<FD>::report_size(ReportType type, MemoryUsage& res)
{
    (void)type;
    res += memory_usage;
}

template<class FD>
const vector<Ciphertext>& Multiplier<FD>::get_multiplicands(
        const vector<vector<Ciphertext> >& others_ct, const FHE_PK&)
{
    return others_ct[P.get_full_player().get_player(-P.get_offset())];
}


template class Multiplier<FFT_Data>;
template class Multiplier<P2Data>;
