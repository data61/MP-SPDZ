/*
 * TemiPrep.hppg
 *
 *
 */

#ifndef PROTOCOLS_TEMIPREP_HPP_
#define PROTOCOLS_TEMIPREP_HPP_

#include "TemiPrep.h"
#include "FHEOffline/SimpleMachine.h"

#include "FHEOffline/DataSetup.hpp"

template<class T>
TemiSetup<typename T::clear::FD>* TemiPrep<T>::setup;

template<class T>
Lock TemiPrep<T>::lock;

template<class T>
void TemiPrep<T>::basic_setup(Player& P)
{
    assert(not setup);
    setup = new TemiSetup<FD>;
    MachineBase machine;
    setup->params.set_sec(OnlineOptions::singleton.security_parameter);
    secure_init(*setup, P, machine, typename T::clear(), 0);
    read_or_generate_secrets(*setup, P, machine, 1, true_type());
    T::clear::template init<typename FD::T>();
}

template<class T>
void TemiPrep<T>::teardown()
{
    if (setup)
        delete setup;
}

template<class T>
const typename T::clear::FD& TemiPrep<T>::get_FTD()
{
    assert(setup);
    return setup->FieldD;
}

template<class T>
inline const FHE_PK& TemiPrep<T>::get_pk()
{
    assert(setup);
    return setup->pk;
}

template<class T>
const TemiSetup<typename T::clear::FD>& TemiPrep<T>::get_setup()
{
    assert(setup);
    return *setup;
}

template<class T>
void TemiPrep<T>::buffer_triples()
{
    CODE_LOCATION
    lock.lock();
    if (setup == 0)
    {
        PlainPlayer P(this->proc->P.N, "Temi" + T::type_string());
        basic_setup(P);
        BaseMachine::add_one_off(P.total_comm());
    }
    lock.unlock();

    auto& P = this->proc->P;
    auto& FieldD = setup->FieldD;

    Plaintext_<FD> a(FieldD), b(FieldD), c(FieldD);

    SeededPRNG G;
    a.randomize(G);
    b.randomize(G);

    TreeSum<Ciphertext> ts;
    auto C = ts.run(setup->pk.encrypt(a), P);
    C = ts.run(C * b + setup->pk.template encrypt<FD>(FieldD), P);
    c = SimpleDistDecrypt<FD>(P, *setup).reshare(C);

    for (unsigned i = 0; i < a.num_slots(); i++)
        this->triples.push_back({{a.element(i), b.element(i), c.element(i)}});
}

template<class T>
vector<TemiMultiplier<T>*>& TemiPrep<T>::get_multipliers()
{
    assert(setup);
    assert(
            OnlineOptions::singleton.batch_size
                    <= setup->params.get_matrix_dim());
    assert(this->proc);
    if (multipliers.empty())
        multipliers.push_back(new TemiMultiplier<T>(this->proc->P));
    return multipliers;
}

template<class T>
TemiMultiplier<T>::TemiMultiplier(Player& P) : P(P)
{
}

template<class T>
TemiPrep<T>::~TemiPrep()
{
    for (auto& x : multipliers)
        delete x;
}

template<class T>
vector<Ciphertext>& TemiMultiplier<T>::get_multiplicands(
        vector<vector<Ciphertext> >& ciphertexts, const FHE_PK& pk)
{
    multiplicands.clear();
    multiplicands.resize(ciphertexts[0].size(), pk);
    for (size_t j = 0; j < multiplicands.size(); j++)
        for (size_t i = 0; i < ciphertexts.size(); i++)
            multiplicands[j] += ciphertexts[i].at(j);
    return multiplicands;
}

template<class T>
void TemiMultiplier<T>::add(Plaintext_<FD>& res, const Ciphertext& C,
        OT_ROLE, int)
{
    TreeSum<Ciphertext> ts;
    SimpleDistDecrypt<FD> dd(P, TemiPrep<T>::get_setup());
    auto zero = TemiPrep<T>::get_pk().template encrypt<FD>(TemiPrep<T>::get_FTD());
    res += dd.reshare(ts.run(C + zero, P));
}

#endif /* PROTOCOLS_TEMIPREP_HPP_ */
