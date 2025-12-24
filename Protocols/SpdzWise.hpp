/*
 * SpdzWise.cpp
 *
 */

#include "SpdzWise.h"

#include "BufferScope.h"

#include "mac_key.hpp"

template<class T>
SpdzWise<T>::SpdzWise(Player& P) :
        internal(P), internal2(P), P(P)
{
    results.reserve(OnlineOptions::singleton.batch_size);
}

template<class T>
SpdzWise<T>::~SpdzWise()
{
    check();
}

template<class T>
typename T::Protocol SpdzWise<T>::branch()
{
    typename T::Protocol res(P);
    res.mac_key = mac_key;
    return res;
}

template<class T>
void SpdzWise<T>::init(Preprocessing<T>&, typename T::MAC_Check& MC)
{
    mac_key = MC.get_alphai();
}

template<class T>
void SpdzWise<T>::maybe_check()
{
    assert(not mac_key.is_zero());
    if ((int) results.size() >= OnlineOptions::singleton.batch_size)
        check();
}

template<class T>
void SpdzWise<T>::init_mul()
{
    maybe_check();
    internal.init_mul();
    internal2.init_mul();
}

template<class T>
void SpdzWise<T>::prepare_mul(const T& x, const T& y, int)
{
    internal.prepare_mul(x.get_share(), y.get_share());
    internal.prepare_mul(x.get_mac(), y.get_share());
}

template<class T>
T SpdzWise<T>::finalize_mul(int)
{
    T res;
    res.set_share(internal.finalize_mul());
    res.set_mac(internal.finalize_mul());
    results.push_back(res);
    return res;
}

template<class T>
void SpdzWise<T>::exchange()
{
    internal.exchange();
    internal2.exchange();
}

template<class T>
void SpdzWise<T>::init_dotprod()
{
    maybe_check();
    internal.init_dotprod();
    internal2.init_dotprod();
}

template<class T>
void SpdzWise<T>::prepare_dotprod(const T& x, const T& y)
{
    internal.prepare_dotprod(x.get_share(), y.get_share());
    internal2.prepare_dotprod(x.get_mac(), y.get_share());
}

template<class T>
void SpdzWise<T>::next_dotprod()
{
    internal.next_dotprod();
    internal2.next_dotprod();
}

template<class T>
T SpdzWise<T>::finalize_dotprod(int length)
{
    T res;
    res.set_share(internal.finalize_dotprod(length));
    res.set_mac(internal2.finalize_dotprod(length));
    results.push_back(res);
    return res;
}

template<class T>
void SpdzWise<T>::add_to_check(const T& x)
{
    results.push_back(x);
}

template<class T>
void SpdzWise<T>::check()
{
    if (results.empty())
        return;

    CODE_LOCATION
    internal.init_dotprod();
    coefficients.clear();

    // need one extra in zero_check
    BufferScope _(internal, results.size() + 1);

    for (auto& res : results)
    {
        coefficients.push_back(internal.get_random());
        internal.prepare_dotprod(res.get_share(), coefficients.back());
    }
    internal.next_dotprod();

    for (size_t i = 0; i < results.size(); i++)
        internal.prepare_dotprod(results[i].get_mac(), coefficients[i]);
    internal.next_dotprod();

    internal.exchange();
    auto w = internal.finalize_dotprod(results.size());
    auto u = internal.finalize_dotprod(results.size());
    auto t = u - internal.mul(mac_key, w);
    zero_check(t);
    results.clear();
}

template<class T>
void SpdzWise<T>::zero_check(check_type t)
{
    assert(T::clear::invertible);
    check_field_size<typename T::clear>();
    auto r = internal.get_random();
    internal.init_mul();
    internal.prepare_mul(t, r);
    internal.exchange();
    typename T::part_type::MAC_Check MC;
    MC.CheckFor(0, {internal.finalize_mul()}, P);
}

template<class T>
void SpdzWise<T>::buffer_random()
{
    CODE_LOCATION
    // proxy for initialization
    assert(mac_key != 0);
    auto batch_size = this->buffer_size;
    if (OnlineOptions::singleton.has_option("verbose_random"))
        fprintf(stderr, "generating %d random elements\n", batch_size);
    vector<typename T::part_type> rs;
    rs.reserve(batch_size);
    // cannot use member instance
    typename T::part_type::Honest::Protocol internal(P);
    BufferScope scope(internal, batch_size);
    internal.init_mul();
    for (int i = 0; i < batch_size; i++)
    {
        rs.push_back(internal.get_random());
        internal.prepare_mul(rs.back(), mac_key);
    }
    internal.exchange();
    for (int i = 0; i < batch_size; i++)
    {
        this->random.push_back({rs[i], internal.finalize_mul()});
        results.push_back(this->random.back());
    }
}

template<class T>
void SpdzWise<T>::randoms_inst(StackedVector<T>& S,
        const Instruction& instruction)
{
    CODE_LOCATION
    internal.init_mul();
    for (int i = 0; i < instruction.get_size(); i++)
    {
        typename T::share_type res;
        internal.randoms(res, instruction.get_n());
        internal.prepare_mul(res, mac_key);
        S[instruction.get_r(0) + i].set_share(res);
    }
    internal.exchange();
    for (int i = 0; i < instruction.get_size(); i++)
    {
        auto& res = S[instruction.get_r(0) + i];
        res.set_mac(internal.finalize_mul());
    }
}
