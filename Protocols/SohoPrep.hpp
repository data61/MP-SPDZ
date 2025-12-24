/*
 * SohoPrep.cpp
 *
 */

#include "SohoPrep.h"
#include "FHEOffline/DataSetup.h"

#include "ReplicatedPrep.hpp"
#include "FHEOffline/DataSetup.hpp"

template<class T>
PartSetup<typename SohoPrep<T>::FD>* SohoPrep<T>::setup = 0;

template<class T>
Lock SohoPrep<T>::lock;

template<class T>
void SohoPrep<T>::basic_setup(Player& P)
{
    assert(not setup);
    setup = new PartSetup<FD>;
    MachineBase machine;
    setup->params.set_sec(OnlineOptions::singleton.security_parameter);
    secure_init(*setup, P, machine, typename T::clear(), 0);
    read_or_generate_secrets(*setup, P, machine, 1, true_type());
    T::clear::template init<typename FD::T>();
}

template<class T>
void SohoPrep<T>::teardown()
{
    if (setup)
        delete setup;
}

template<class T>
void SohoPrep<T>::buffer_triples()
{
    CODE_LOCATION
    auto& proc = this->proc;
    assert(proc != 0);
    lock.lock();
    if (not setup)
    {
        PlainPlayer P(proc->P.N, "Soho" + T::type_string());
        basic_setup(P);
        BaseMachine::add_one_off(P.total_comm());
    }
    lock.unlock();

    Plaintext_<FD> ai(setup->FieldD), bi(setup->FieldD);
    SeededPRNG G;
    ai.randomize(G);
    bi.randomize(G);
    Ciphertext Ca = setup->pk.encrypt(ai);
    Ciphertext Cb = setup->pk.encrypt(bi);
    octetStream os;
    Ca.pack(os);
    Cb.pack(os);

    for (int i = 1; i < proc->P.num_players(); i++)
    {
        proc->P.pass_around(os);
        Ca.add(os);
        Cb.add(os);
    }

    Ciphertext Cc = Ca.mul(setup->pk, Cb);
    Plaintext_<FD> ci(setup->FieldD);
    SimpleDistDecrypt<FD> dd(proc->P, *setup);
    EncCommitBase_<FD> EC;
    dd.reshare(ci, Cc, EC);

    for (unsigned i = 0; i < ai.num_slots(); i++)
        this->triples.push_back({{ai.element(i), bi.element(i),
            ci.element(i)}});
}

template<class T>
void SohoPrep<T>::buffer_squares()
{
    CODE_LOCATION
    auto& proc = this->proc;
    assert(proc != 0);
    lock.lock();
    if (not setup)
    {
        PlainPlayer P(proc->P.N, "Soho" + T::type_string());
        basic_setup(P);
        BaseMachine::add_one_off(P.total_comm());
    }
    lock.unlock();

    Plaintext_<FD> ai(setup->FieldD);
    SeededPRNG G;
    ai.randomize(G);
    Ciphertext Ca = setup->pk.encrypt(ai);
    octetStream os;
    Ca.pack(os);

    for (int i = 1; i < proc->P.num_players(); i++)
    {
        proc->P.pass_around(os);
        Ca.add(os);
    }

    Ciphertext Cc = Ca.mul(setup->pk, Ca);
    Plaintext_<FD> ci(setup->FieldD);
    SimpleDistDecrypt<FD> dd(proc->P, *setup);
    EncCommitBase_<FD> EC;
    dd.reshare(ci, Cc, EC);

    for (unsigned i = 0; i < ai.num_slots(); i++)
        this->squares.push_back({{ai.element(i), ci.element(i)}});
}

template<class T>
void SohoPrep<T>::buffer_bits()
{
    buffer_bits_from_squares(*this);
}

template<>
void SohoPrep<SohoShare<gf2n_short>>::buffer_bits()
{
    buffer_bits_without_check();
}
