/*
 * MaliciousRepMC.cpp
 *
 */

#ifndef PROTOCOLS_MALICIOUSREPMC_HPP_
#define PROTOCOLS_MALICIOUSREPMC_HPP_

#include "MaliciousRepMC.h"
#include "GC/Machine.h"
#include "Math/BitVec.h"

#include "ReplicatedMC.hpp"
#include "MAC_Check_Base.hpp"

#include <stdlib.h>

template<class T>
void MaliciousRepMC<T>::POpen_Begin(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    super::POpen_Begin(values, S, P);
}

template<class T>
HashMaliciousRepMC<T>::HashMaliciousRepMC()
{
    reset();
}

template<class T>
void HashMaliciousRepMC<T>::reset()
{
    hash.reset();
    needs_checking = false;
}

template<class T>
HashMaliciousRepMC<T>::~HashMaliciousRepMC()
{
    if (needs_checking)
    {
        cerr << endl << "SECURITY BUG: insufficient checking" << endl;
        terminate();
    }
}

template<class T>
void HashMaliciousRepMC<T>::POpen(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    prepare(S, P);
    P.send_receive_all(to_send, to_receive);
    finalize(values, S, P);
}

template<class T>
void HashMaliciousRepMC<T>::prepare(const vector<T>& secrets, const Player& P)
{
    to_send.resize(3);
    auto& value_buffer = to_send.at(P.get_player(-1));
    value_buffer.reset_write_head();
    hash_buffer.reset_write_head();
    for (auto& x : secrets)
    {
        x[0].pack(value_buffer);
        x[1].pack(hash_buffer);
    }
    hash_buffer.hash(to_send[P.get_player(1)]);
}

template<class T>
void HashMaliciousRepMC<T>::finalize(vector<typename T::open_type>& values,
        const vector<T>& secrets, const Player& P)
{
    auto& received_values = to_receive.at(P.get_player(1));
    values.clear();
    for (auto& x : secrets)
    {
        values.push_back(
                x.sum() + received_values.get<typename T::open_type>());
    }
    received_values.hash(hash_buffer);
    if (hash_buffer != to_receive.at(P.get_player(-1)))
        throw mac_fail("check hash mismatch");
}

template<class T>
void HashMaliciousRepMC<T>::POpen_Begin(vector<typename T::open_type>&,
        const vector<T>& S, const Player& P)
{
    prepare(S, P);
    P.send_all(to_send);
}

template<class T>
void HashMaliciousRepMC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    P.receive_all(to_receive);
    finalize(values, S, P);
}

template<class T>
void HashMaliciousRepMC<T>::exchange(const Player& P)
{
    POpen(this->values, this->secrets, P);
}

template<class T>
typename T::open_type HashMaliciousRepMC<T>::finalize_raw()
{
    return MAC_Check_Base<T>::finalize_raw();
}

template<class T>
void HashMaliciousRepMC<T>::update()
{
    hash.update(os);
    needs_checking = true;
}

template<class T>
void HashMaliciousRepMC<T>::CheckFor(const typename T::open_type& value,
        const vector<T>& check_shares, const Player& P)
{
    os.reset_write_head();
    for (auto& share : check_shares)
    {
        typename T::value_type shares[3];
        for (int i = 0; i < 3; i++)
        {
            int j = (i + P.my_num()) % 3;
            if (j < 2)
                shares[i] = share[j];
            else
                shares[i] = value - share.sum();
        }
        for (auto& x : shares)
            x.pack(os);
    }
    update();
    Check(P);
}

template<class T>
void HashMaliciousRepMC<T>::Check(const Player& P)
{
    if (needs_checking)
    {
        CODE_LOCATION
        vector<octetStream> os(P.num_players());
        hash.final(os[P.my_num()]);
        reset();
        P.Broadcast_Receive(os);
        for (int i = 0; i < P.num_players(); i++)
            if (os[i] != os[P.my_num()])
                throw mac_fail("check hash mismatch");
    }
}

template<class T>
void CommMaliciousRepMC<T>::POpen(vector<typename T::clear>& values,
        const vector<T>& S, const Player& P)
{
    POpen_Begin(values, S, P);
    POpen_End(values, S, P);
}

template<class T>
void CommMaliciousRepMC<T>::POpen_Begin(vector<typename T::clear>& values,
        const vector<T>& S, const Player& P)
{
    assert(T::vector_length == 2);
    (void)values;
    os.resize(2);
    for (auto& o : os)
        o.reset_write_head();
    for (auto& x : S)
        for (int i = 0; i < 2; i++)
            x[i].pack(os[1 - i]);
    P.pass_around(os[0], 1);
    P.pass_around(os[1], 2);
}

template<class T>
void CommMaliciousRepMC<T>::POpen_End(vector<typename T::clear>& values,
        const vector<T>& S, const Player& P)
{
    (void) P;
    if (os[0] != os[1])
        throw mac_fail();
    values.clear();
    for (auto& x : S)
        values.push_back(os[0].template get<BitVec>() + x.sum());
}

template<class T>
void CommMaliciousRepMC<T>::Check(const Player& P)
{
    (void)P;
}

#endif
