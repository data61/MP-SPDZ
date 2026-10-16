/*
 * Beaver.cpp
 *
 */

#ifndef PROTOCOLS_BEAVER_HPP_
#define PROTOCOLS_BEAVER_HPP_

#include "Beaver.h"

#include "Replicated.hpp"

#include <array>

template<class T>
typename T::Protocol Beaver<T>::branch()
{
    typename T::Protocol res(P);
    res.prep = prep;
    res.MC = MC;
    res.init_mul();
    return res;
}

template<class T>
void Beaver<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC)
{
    this->prep = &prep;
    this->MC = &MC;
}

template<class T>
void Beaver<T>::init_mul()
{
    assert(this->prep);
    assert(this->MC);
    shares.clear();
    opened.clear();
    triples.clear();
    lengths.clear();
    multiplicands.clear();
}

template<class T>
void Beaver<T>::set_fast_mode(bool change)
{
    fast_mode = change;
    assert(shares.empty());
    assert(multiplicands.empty());
}

template<class T>
void Beaver<T>::prepare_mul(const T& x, const T& y, int n)
{
    if (not T::clear::binary or fast_mode)
    {
        prepare_mul_fast(x, y);
        return;
    }

    (void) n;
    triples.push_back({{}});
    auto& triple = triples.back();
    triple = prep->get_triple(n);
    shares.push_back(x - triple[0]);
    shares.push_back(y - triple[1]);
    lengths.push_back(n);
}

template<class T>
void Beaver<T>::prepare_mul_fast(const T& x, const T& y)
{
    multiplicands.push_back({x, y});
}

template<class T>
void Beaver<T>::pre_fast_exchange()
{
    assert(shares.empty());
    for (auto& x : multiplicands)
    {
        auto triple = prep->get_triple(T::clear::length());
        triples.push_back(triple);
        for (int i = 0; i < 2; i++)
            MC->prepare_open(x[i] - triple[i]);
    }
}

template<class T>
void Beaver<T>::exchange()
{
    CODE_LOCATION
    size_t n_mults = lengths.size() + multiplicands.size();
    MC->init_open(P, n_mults);
    if (not T::clear::binary or fast_mode)
    {
        pre_fast_exchange();
    }
    else
    {
        assert(shares.size() == 2 * lengths.size());
        for (size_t i = 0; i < shares.size(); i++)
            MC->prepare_open(shares[i], lengths[i / 2]);
    }
    MC->exchange(P);

    if (not T::clear::binary or fast_mode)
    {
        post_fast_exchange();
    }
    else
    {
        for (size_t i = 0; i < 2 * n_mults; i++)
            opened.push_back(MC->finalize_raw());
        it = opened.begin();
        triple = triples.begin();
        assert(opened.size() == 2 * n_mults);
        assert(triples.size() == n_mults);
    }
}

template<class T>
void Beaver<T>::post_fast_exchange()
{

    int my_num = P.my_num();
    results.clear();
    for (auto& triple : triples)
    {
        this->add_mul(-1);
        // assignments necessary for GCC
        auto eps = MC->finalize_raw();
        auto delta = MC->finalize_raw();
        results.push_back(finalize(triple, eps, delta, my_num));
    }
    assert(results.size() == multiplicands.size());
}

template<class T>
void Beaver<T>::start_exchange()
{
    if (not T::clear::binary or fast_mode)
    {
        MC->init_open(P, multiplicands.size());
        pre_fast_exchange();
        MC->start_exchange(P);
    }
    else
        MC->POpen_Begin(opened, shares, P);
}

template<class T>
void Beaver<T>::stop_exchange()
{
    if (not T::clear::binary or fast_mode)
    {
        MC->stop_exchange(P);
        post_fast_exchange();
    }
    else
    {
        MC->POpen_End(opened, shares, P);
        it = opened.begin();
        triple = triples.begin();
    }
}

template<class T>
T Beaver<T>::finalize_mul(int n)
{
    if (not T::clear::binary or fast_mode)
        return finalize_mul_fast();
    else
    {
        this->add_mul(n);
        // deliberately complicated to work around GCC bug
        it += 2;
        return finalize(*triple++, *(it - 2), *(it - 1), P.my_num());
    }
}

template<class T>
T Beaver<T>::finalize_mul_fast()
{
    return results.next();
}

template<class T>
T Beaver<T>::finalize(array<T, 3>& triple, const open_type& eps,
        const open_type& delta, int my_num)
{
    T& tmp = triple[2];
    tmp += eps * triple[1];
    tmp += triple[0] * delta;
    tmp += T::constant(eps * delta, my_num, MC->get_alphai());
    return tmp;
}

template<class T>
void Beaver<T>::check()
{
    assert(MC);
    MC->Check(P);
}

#endif
