/*
 * ReplicatedMC.cpp
 *
 */

#ifndef PROTOCOLS_REPLICATEDMC_HPP_
#define PROTOCOLS_REPLICATEDMC_HPP_

#include "ReplicatedMC.h"

template<class T>
void ReplicatedMC<T>::POpen(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    CODE_LOCATION
    prepare(S);
    P.pass_around(to_send, o, -1);
    finalize(values, S);
}

template<class T>
void ReplicatedMC<T>::POpen_Begin(vector<typename T::open_type>&,
        const vector<T>& S, const Player& P)
{
    CODE_LOCATION
    prepare(S);
    P.send_relative(-1, to_send);
}

template<class T>
void ReplicatedMC<T>::prepare(const vector<T>& S)
{
    assert(T::vector_length == 2);
    o.reset_write_head();
    to_send.reset_write_head();
    to_send.reserve(S.size() * T::value_type::size());
    for (auto& x : S)
        x[0].pack(to_send);
    this->values_opened += S.size();
}

template<class T>
void ReplicatedMC<T>::exchange(const Player& P)
{
    CODE_LOCATION
    prepare(this->secrets);
    P.pass_around(to_send, o, -1);
}

template<class T>
void ReplicatedMC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    P.receive_relative(1, o);
    finalize(values, S);
}

template<class T>
void ReplicatedMC<T>::finalize(vector<typename T::open_type>& values,
        const vector<T>& S)
{
    values.resize(S.size());
    for (size_t i = 0; i < S.size(); i++)
    {
        typename T::open_type tmp;
        tmp.unpack(o);
        values[i] = S[i].sum() + tmp;
    }
}

template<class T>
typename T::open_type ReplicatedMC<T>::finalize_raw()
{
    auto a = this->secrets.next().sum();
    return a + o.get<typename T::open_type>();
}

template<class T>
array<typename T::open_type*, 2> ReplicatedMC<T>::finalize_several(size_t n)
{
    if (this->values.empty())
        finalize(this->values, this->secrets);
    return MAC_Check_Base<T>::finalize_several(n);
}

#endif
