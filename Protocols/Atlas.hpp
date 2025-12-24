/*
 * Atlas.hpp
 *
 */

#ifndef PROTOCOLS_ATLAS_HPP_
#define PROTOCOLS_ATLAS_HPP_

#include "Atlas.h"
#include "BufferScope.h"

template<class T>
Atlas<T>::~Atlas()
{
#ifdef VERBOSE
    if (not double_sharings.empty())
        cerr << double_sharings.size() << " double sharings left" << endl;
#endif
}

template<class T>
array<T, 2> Atlas<T>::get_double_sharing()
{
    if (double_sharings.empty())
    {
        SeededPRNG G;
        PRNG G2 = G;
        BufferScope scope(shamir, this->buffer_size);
        BufferScope scope2(shamir2, this->buffer_size);
        auto random = shamir.get_randoms(G, 0);
        auto random2 = shamir2.get_randoms(G2, 0);
        assert(random.size() == random2.size());
        assert(random.size() % P.num_players() == 0);
        for (size_t i = 0; i < random.size(); i++)
            double_sharings.push_back({{random2.at(i), random.at(i)}});
    }

    auto res = double_sharings.back();
    double_sharings.pop_back();
    return res;
}

template<class T>
void Atlas<T>::init_mul()
{
    oss.reset();
    oss2.reset();
    masks.clear();
    base_king = next_king;
    this->buffer_size = BaseMachine::batch_size<T>(DATA_TRIPLE,
            this->buffer_size);
}

template<class T>
void Atlas<T>::prepare_mul(const T& x, const T& y, int)
{
    prepare(x * y);
}

template<class T>
void Atlas<T>::prepare(const typename T::open_type& product)
{
    auto r = get_double_sharing();
    (product + r[0]).pack(oss2[next_king]);
    next_king = (next_king + 1) % P.num_players();
    masks.push_back(r[1]);
}

template<class T>
void Atlas<T>::exchange()
{
    CODE_LOCATION
    P.send_receive_all(oss2, oss);
    oss.mine = oss2.mine;

    int t = ShamirMachine::s().threshold;
    if (reconstruction.empty())
        for (int i = 0; i < 2 * t + 1; i++)
            reconstruction.push_back(Shamir<T>::get_rec_factor(i, 2 * t + 1));
    resharing.reset_all(P);

    for (size_t j = P.get_player(-base_king); j < masks.size();
            j += P.num_players())
    {
        typename T::open_type e;
        for (int i = 0; i < 2 * t + 1; i++)
        {
            auto tmp = oss[i].template get<T>();
            e += tmp * reconstruction.at(i);
        }
        resharing.add_mine(e);
    }

    for (size_t i = 0; i < min(masks.size(), size_t(P.num_players())); i++)
    {
        int j = (base_king + i) % P.num_players();
        resharing.add_sender(j);
    }

    resharing.exchange();
}

template<class T>
T Atlas<T>::finalize_mul(int)
{
    T res = resharing.finalize(base_king) - masks.next();
    base_king = (base_king + 1) % P.num_players();
    return res;
}

template<class T>
void Atlas<T>::init_dotprod()
{
    init_mul();
    dotprod_share = 0;
}

template<class T>
void Atlas<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share += x * y;
}

template<class T>
void Atlas<T>::next_dotprod()
{
    prepare(dotprod_share);
    dotprod_share = 0;
}

template<class T>
T Atlas<T>::finalize_dotprod(int)
{
    return finalize_mul();
}

template<class T>
T Atlas<T>::get_random()
{
    BufferScope scope(shamir, this->buffer_size);
    return shamir.get_random();
}

#endif /* PROTOCOLS_ATLAS_HPP_ */
