/*
 * HighGearKeyGen.cpp
 *
 */

#include "HighGearKeyGen.h"
#include "FHE/Rq_Element.h"

#include "LowGearKeyGen.hpp"

template<int L, int M>
HighGearKeyGen<L, M>::HighGearKeyGen(Player& P, const FHE_Params& params) :
        P(P), params(params), proto0(P, params, 0), proto1(P, params, 1)
{
}

/**
 * Generate maBits (authenticated random bits modulo two different primes)
 * using daBits (authenticated random bits modulo a large prime and two)
 */
template<int L, int M>
void HighGearKeyGen<L, M>::buffer_mabits()
{
    CODE_LOCATION
    vector<BT> diffs;
    vector<typename BT::open_type> open_diffs;
    vector<share_type0> my_bits0;
    vector<share_type1> my_bits1;
    int batch_size = 1000;
    auto& bmc = *GC::ShareThread<BT>::s().MC;
    for (int i = 0; i < batch_size; i++)
    {
        share_type0 a0;
        share_type1 a1;
        BT b0, b1;
        proto0.prep->get_dabit(a0, b0);
        proto1.prep->get_dabit(a1, b1);
        my_bits0.push_back(a0);
        my_bits1.push_back(a1);
        diffs.push_back(b0 + b1);
    }
    bmc.POpen(open_diffs, diffs, P);
    bmc.Check(P);
    for (int i = 0; i < batch_size; i++)
    {
        assert(open_diffs.at(i).get_bit(1) == 0);
        bits0.push_back(my_bits0[i]);
        bits1.push_back(
                my_bits1[i]
                        + share_type1::constant(open_diffs.at(i), P.my_num(),
                                proto1.MC->get_alphai())
                        - my_bits1[i] * open_diffs.at(i) * 2);
    }

#ifdef DEBUG_HIGHGEAR_KEYGEN
    proto0.MC->init_open(P);
    proto1.MC->init_open(P);
    auto it0 = bits0.end() - batch_size;
    auto it1 = bits1.end() - batch_size;
    for (int i = 0; i < batch_size; i++)
    {
        proto0.MC->prepare_open(*it0);
        proto1.MC->prepare_open(*it1);
        it0++;
        it1++;
    }
    proto0.MC->exchange(P);
    proto1.MC->exchange(P);
    for (int i = 0; i < batch_size; i++)
    {
        auto x0 = proto0.MC->finalize_open();
        auto x1 = proto1.MC->finalize_open();
        assert(x0.is_bit());
        assert(x1.is_bit());
        assert(x0.is_zero() == x1.is_zero());
    }
#endif
}

template<int L, int M>
template<class FD>
void HighGearKeyGen<L, M>::run(PartSetup<FD>& setup, MachineBase& machine)
{
    CODE_LOCATION
    RunningTimer timer;

    DataPositions prep_usage;
    BT::LivePrep preprocessing(prep_usage);

    bool have_singleton = GC::ShareThread<BT>::has_singleton();

    if (not have_singleton)
    {
        auto tmp = new GC::ShareThread<BT>(preprocessing, P,
                BT::LivePrep::get_mac_key(P));
        assert(tmp == &GC::ShareThread<BT>::s());
    }

    GlobalPRNG global_prng(P);
    auto& fftd = params.FFTD();

    AddableVector<open_type0> a0(params.phi_m()), a0_prime(params.phi_m());
    AddableVector<open_type1> a1(params.phi_m()), a1_prime(params.phi_m());
    a0.randomize(global_prng);
    a1.randomize(global_prng);
    a0_prime.randomize(global_prng);
    a1_prime.randomize(global_prng);

    KeyGenBitFactory<share_type0, HighGearKeyGen<L, M>> factory0(*this, bits0);
    KeyGenBitFactory<share_type1, HighGearKeyGen<L, M>> factory1(*this, bits1);

    vector_type0 sk0;
    vector_type1 sk1;
    proto0.secret_key(sk0, factory0);
    proto1.secret_key(sk1, factory1);

    vector_type0 e0, e0_prime;
    vector_type1 e1, e1_prime;
    proto0.binomial(e0, factory0);
    proto0.binomial(e0_prime, factory0);
    proto1.binomial(e1, factory1);
    proto1.binomial(e1_prime, factory1);

    auto f0 = sk0;
    auto f0_prime = proto0.schur_product(f0, f0);

    Rq_Element a(Ring_Element(fftd[0], evaluation, a0),
            Ring_Element(fftd[1], evaluation, a1));
    Rq_Element Sw_a(Ring_Element(fftd[0], evaluation, a0_prime),
            Ring_Element(fftd[1], evaluation, a1_prime));

    bigint p = setup.FieldD.get_prime();
    bigint p1 = fftd[1].get_prime();
    vector<open_type0> b0, b0_prime;
    vector<open_type1> b1, b1_prime;
    proto0.MC->POpen(b0, sk0 * a0 + e0 * p, P);
    proto1.MC->POpen(b1, sk1 * a1 + e1 * p, P);
    proto0.MC->POpen(b0_prime, sk0 * a0_prime + e0_prime * p - f0_prime * p1, P);
    proto1.MC->POpen(b1_prime, sk1 * a1_prime + e1_prime * p, P);

    Rq_Element b(Ring_Element(fftd[0], evaluation, b0),
            Ring_Element(fftd[1], evaluation, b1));
    Rq_Element Sw_b(Ring_Element(fftd[0], evaluation, b0_prime),
            Ring_Element(fftd[1], evaluation, b1_prime));

    setup.pk.assign(a, b, Sw_a, Sw_b);

    vector<open_type0> s0_shares;
    vector<open_type1> s1_shares;
    for (int i = 0; i < params.phi_m(); i++)
    {
        s0_shares.push_back(sk0.at(i).get_share());
        s1_shares.push_back(sk1.at(i).get_share());
    }
    setup.sk.assign({Ring_Element(fftd[0], evaluation, s0_shares),
            Ring_Element(fftd[1], evaluation, s1_shares)});

    GC::ShareThread<BT>::s().MC->Check(P);

#ifdef DEBUG_HIGHGEAR_KEYGEN
    proto0.MC->POpen(s0_shares, sk0, P);
    proto1.MC->POpen(s1_shares, sk1, P);

    vector<open_type0> e0_open, e0_prime_open;
    vector<open_type1> e1_open, e1_prime_open;
    proto0.MC->POpen(e0_open, e0, P);
    proto0.MC->POpen(e0_prime_open, e0_prime, P);
    proto1.MC->POpen(e1_open, e1, P);
    proto1.MC->POpen(e1_prime_open, e1_prime, P);

    Rq_Element s(fftd, s0_shares, s1_shares);
    Rq_Element e(fftd, e0_open, e1_open);
    assert(b == s * a + e * p);

    Rq_Element e_prime(fftd, e0_prime_open, e1_prime_open);
    assert(Sw_b == s * Sw_a + e_prime * p - s * s * p1);

    cerr << "Revealed secret key for check" << endl;
#endif

    cerr << "Key generation took " << timer.elapsed() << " seconds" << endl;
    timer.reset();

    map<string, Timer> timers;
    SummingEncCommit<FD> EC(P, setup.pk, setup.FieldD, timers, machine, 0, true);
    Plaintext_<FD> alpha(setup.FieldD);
    EC.next(alpha, setup.calpha);
    assert(alpha.is_diagonal());

    setup.alphai = alpha.element(0);

    cerr << "MAC key generation took " << timer.elapsed() << " seconds" << endl;

#ifdef DEBUG_HIGHGEAR_KEYGEN
    auto d = SemiMC<BasicSemiShare<FHE_SK>>().open(setup.sk, P).decrypt(
            setup.calpha, setup.FieldD);
    auto dd = SemiMC<SemiShare<typename FD::T>>().open(setup.alphai, P);
    for (unsigned i = 0; i < d.num_slots(); i++)
        assert(d.element(i) == dd);
    cerr << "Revealed MAC key for check" << endl;
#endif

    if (not have_singleton)
        delete &GC::ShareThread<BT>::s();
}
