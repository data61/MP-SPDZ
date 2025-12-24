/*
 * PairwiseMachine.cpp
 *
 */

#include "FHEOffline/PairwiseMachine.h"
#include "Tools/benchmarking.h"
#include "Protocols/fake-stuff.h"
#include "Tools/Bundle.h"

#include "Protocols/fake-stuff.hpp"

PairwiseMachine::PairwiseMachine(Player& P) :
    P(P),
    other_pks(P.num_players(), {setup_p.params, 0}),
    pk(other_pks[P.my_num()]), sk(pk)
{
}

RealPairwiseMachine::RealPairwiseMachine(int argc, const char** argv) :
    MachineBase(argc, argv), PairwiseMachine(*new PlainPlayer(N, "pairwise"))
{
    init();
}

void RealPairwiseMachine::init()
{
    if (use_gf2n)
    {
        field_size = gf2n_short::DEFAULT_LENGTH;
        gf2n_short::init_field(field_size);
        setup_keys<P2Data>();
    }
    else
    {
        setup_keys<FFT_Data>();
        bigint p = setup_p.FieldD.get_prime();
        gfp::init_field(p);
        ofstream outf;
        if (output)
            gfp::write_setup(get_prep_dir<FFT_Data>(P));
    }

    for (int i = 0; i < nthreads; i++)
        if (use_gf2n)
            generators.push_back(new PairwiseGenerator<P2Data>(i, *this));
        else
            generators.push_back(new PairwiseGenerator<FFT_Data>(i, *this));
}

template <>
PairwiseSetup<FFT_Data>& PairwiseMachine::setup()
{
    return setup_p;
}

template <>
PairwiseSetup<P2Data>& PairwiseMachine::setup()
{
    return setup_2;
}

template <class FD>
void RealPairwiseMachine::setup_keys()
{
    auto& N = P;
    PairwiseSetup<FD>& s = setup<FD>();
    s.init(P, sec, field_size, extra_slack);
    if (output)
        write_mac_key(get_prep_dir<FD>(P), P.my_num(), P.num_players(), s.alphai);
    for (auto& x : other_pks)
        x = FHE_PK(s.params, s.FieldD.get_prime());
    sk = FHE_SK(pk);
    PRNG G;
    G.ReSeed();
    insecure("local key generation");
    KeyGen(pk, sk, G);
    vector<octetStream> os(N.num_players());
    pk.pack(os[N.my_num()]);
    P.Broadcast_Receive(os);
    for (int i = 0; i < N.num_players(); i++)
        if (i != N.my_num())
            other_pks[i].unpack(os[i]);
    set_mac_key(s.alphai);
    Share<typename FD::T>::MAC_Check::setup(P);
}

template <class T>
void RealPairwiseMachine::set_mac_key(T alphai)
{
    typedef typename T::FD FD;
    auto& N = P;
    PairwiseSetup<FD>& s = setup<FD>();
    s.alphai = alphai;
    for (size_t i = 0; i < s.alpha.num_slots(); i++)
        s.alpha.set_element(i, alphai);
    insecure("MAC key generation");
    Ciphertext enc_alpha = pk.encrypt(s.alpha);
    vector<octetStream> os;
    os.clear();
    os.resize(N.num_players());
    enc_alphas.resize(N.num_players(), pk);
    enc_alpha.pack(os[N.my_num()]);
    P.Broadcast_Receive(os);
    for (int i = 0; i < N.num_players(); i++)
        if (i != N.my_num())
            enc_alphas[i].unpack(os[i]);
    for (int i = 0; i < N.num_players(); i++)
        cout << "Player " << i << " has pk "
                << other_pks[i].a().get(0).get_constant().get_limb(0) << " ..."
                << endl;
}

void PairwiseMachine::pack(octetStream& os) const
{
    os.store(other_pks);
    os.store(enc_alphas);
    sk.pack(os);
}

void PairwiseMachine::unpack(octetStream& os)
{
    os.get_no_resize(other_pks);
    os.get(enc_alphas, {pk});
    sk.unpack(os);
}

void PairwiseMachine::check(Player& P) const
{
    Bundle<octetStream> bundle(P);

    try
    {
        bundle.mine.store(other_pks);
        bundle.mine.store(enc_alphas);
    }
    catch (exception&)
    {
    }

    bundle.compare(P);
}

int PairwiseMachine::comp_sec()
{
    return NonInteractiveProof::comp_sec(sec);
}

template void RealPairwiseMachine::setup_keys<FFT_Data>();
template void RealPairwiseMachine::setup_keys<P2Data>();
