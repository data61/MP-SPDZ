/*
 * TemiSetup.cpp
 *
 */

#include "TemiSetup.h"
#include "PairwiseSetup.h"
#include "FHE/NTL-Subs.h"
#include "Protocols/HemiOptions.h"

template<class FD>
TemiSetup<FD>::TemiSetup()
{
    this->params = FHE_Params(0);
    this->pk = {this->params, 0};
    this->sk = {this->params, 0};
    this->calpha = this->params;
    this->params.set_matrix_dim_from_options();
}

template<class FD>
void TemiSetup<FD>::secure_init(Player& P, MachineBase& machine,
        int plaintext_length, int, bool)
{
    ::secure_init(*this, P, machine, plaintext_length, 0, this->params);
}

template<class FD>
void TemiSetup<FD>::generate(Player& P, MachineBase&,
        int plaintext_length, int sec)
{
    generate_semi_setup(plaintext_length, sec, this->params, this->FieldD,
        false, P.num_players());
    this->sk = {this->params, this->FieldD.get_prime()};
    this->pk = {this->params, this->FieldD.get_prime()};
}

template<class FD>
void TemiSetup<FD>::key_and_mac_generation(Player& P, MachineBase&, int,
        true_type)
{
    Rq_Element a(this->params);
    GlobalPRNG GG(P);
    a.randomize(GG);
    SeededPRNG G;
    auto sk = this->pk.sample_secret_key(G);
    this->sk.assign(sk);
    this->pk.partial_key_gen(sk, a, G);
    TreeSum<Rq_Element> ts;
    vector<Rq_Element> pks;
    pks.push_back(this->pk.b());
    ts.run(pks, P);
    this->pk.assign(this->pk.a(), pks[0]);
}

template class TemiSetup<FFT_Data>;
template class TemiSetup<P2Data>;
