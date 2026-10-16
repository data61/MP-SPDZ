/*
 * SemiMC.cpp
 *
 */

#ifndef PROTOCOLS_SEMIMC_HPP_
#define PROTOCOLS_SEMIMC_HPP_

#include "SemiMC.h"

#include "MAC_Check.hpp"

template<class T>
void SemiMC<T>::init_open(const Player& P, int n)
{
    MAC_Check_Base<T>::init_open(P, n);
    this->lengths.clear();
    this->lengths.reserve(n);
}

template<class T>
void SemiMC<T>::prepare_open(const T& secret, int n_bits)
{
    this->values.push_back(secret);
    this->lengths.push_back(n_bits);
}

template<class T>
void SemiMC<T>::exchange(const Player& P)
{
    this->run(this->values, P);
}

template<class T>
void DirectSemiMC<T>::POpen_(vector<typename T::open_type>& values,
        const vector<T>& S, const PlayerBase& P)
{
    this->values.clear();
    this->values.reserve(S.size());
    this->lengths.clear();
    this->lengths.reserve(S.size());
    for (auto& secret : S)
        this->prepare_open(secret);
    if (this->lengths.empty())
        exchange_<false>(P);
    else
        exchange_<true>(P);
    values = this->values;
}

template<class T>
void DirectSemiMC<T>::exchange(const Player& P)
{
    if (this->lengths.empty())
        exchange_<false>(P);
    else
        exchange_<true>(P);
}

template<class T>
template<bool USE_LENGTHS>
void DirectSemiMC<T>::exchange_(const PlayerBase& P)
{
    CODE_LOCATION
    Bundle<octetStream> oss(P);
    oss.mine.reserve(this->values.size());
    if (USE_LENGTHS)
        assert(this->values.size() == this->lengths.size());
    for (size_t i = 0; i < this->values.size(); i++)
        this->values[i].pack(oss.mine, USE_LENGTHS ? this->lengths[i] : -1);
    oss.mine.append(0);
    P.unchecked_broadcast(oss);
    size_t n = P.num_players();
    size_t me = P.my_num();
    for (size_t i = 0; i < this->values.size(); i++)
        for (size_t j = 0; j < n; j++)
            if (j != me)
            {
                T tmp;
                tmp.unpack(oss[j], USE_LENGTHS ? this->lengths[i] : -1);
                this->values[i] += tmp;
            }
}

template<class T>
void DirectSemiMC<T>::POpen_Begin(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P)
{
    values.clear();
    values.insert(values.begin(), S.begin(), S.end());
    send(P, values);
}

template<class T>
void DirectSemiMC<T>::start_exchange(const Player& P)
{
    send(P, this->values);
}

template<class T>
void DirectSemiMC<T>::send(const Player& P,
        vector<typename T::open_type>& values)
{
    octetStream os;
    for (auto& x : values)
        x.pack(os);
    P.send_all(os);
}

template<class T>
void DirectSemiMC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>&, const Player& P)
{
    Bundle<octetStream> oss(P);
    P.receive_all(oss);
    direct_add_openings<typename T::open_type>(values, P, oss);
}

#endif
