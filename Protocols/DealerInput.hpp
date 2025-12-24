/*
 * DealerInput.hpp
 *
 */

#ifndef PROTOCOLS_DEALERINPUT_HPP_
#define PROTOCOLS_DEALERINPUT_HPP_

#include "DealerInput.h"

template<class T>
DealerInput<T>::DealerInput(SubProcessor<T>& proc, typename T::MAC_Check&) :
        DealerInput(&proc, proc.P)
{
}

template<class T>
DealerInput<T>::DealerInput(typename T::MAC_Check&, Preprocessing<T>&,
        Player& P, typename T::Protocol*) :
        DealerInput(P)
{
}

template<class T>
DealerInput<T>::DealerInput(Player& P) :
        DealerInput(0, P)
{
}

template<class T>
DealerInput<T>::DealerInput(SubProcessor<T>* proc, Player& P) :
        InputBase<T>(proc),
        P(P), from_dealer(false), sub_player(P), king(0)
{
    if (is_dealer())
        internal = 0;
    else
        internal = new SemiInput<SemiShare<typename T::clear>>(0, sub_player);
    my_num = P.my_num();
}

template<class T>
DealerInput<T>::~DealerInput()
{
    if (internal)
        delete internal;
}

template<class T>
int DealerInput<T>::dealer_player()
{
    return P.num_players() - 1;
}

template<class T>
bool DealerInput<T>::is_dealer(int player)
{
    int dealer_player = this->dealer_player();
    if (player == -1)
        return P.my_num() == dealer_player;
    else
        return player == dealer_player;
}

template<class T>
bool DealerInput<T>::is_king()
{
    assert(not is_dealer());
    return king == P.my_num();
}

template<class T>
void DealerInput<T>::reset(int player)
{
    if (is_dealer(player))
    {
        octetStreams to_send, to_receive;
        vector<bool> senders(P.num_players());
        senders.back() = true;

        if (is_dealer())
        {
            to_send.reset(P);
            if (dealer_prngs.empty())
            {
                dealer_prngs.resize(P.num_players() - 1);
                dealer_random_prngs.resize(dealer_prngs.size());
                for (int i = 0; i < P.num_players() - 1; i++)
                {
                    to_send[i].append(dealer_prngs[i].get_seed(), SEED_SIZE);
                    dealer_random_prngs[i].SetSeed(dealer_prngs[i]);
                }
                P.send_receive_all(senders, to_send, to_receive);
            }
        }
        else if (not non_dealer_prng.is_initialized())
        {
            P.send_receive_all(senders, to_send, to_receive);
            non_dealer_prng.SetSeed(
                    to_receive.at(dealer_player()).consume(SEED_SIZE));
            non_dealer_random_prng.SetSeed(non_dealer_prng);
        }

        os.reset_write_head();
        shares.clear();
        random_shares.clear();
        from_dealer = false;
        king = (king + 1) % (P.num_players() - 1);
    }
    else if (not is_dealer())
        internal->reset(player);
}

template<class T>
void DealerInput<T>::add_mine(const typename T::open_type& input,
        int)
{
    if (is_dealer())
    {
        add_from_dealer(input);
    }
    else
        internal->add_mine(input);
}

template<class T>
void DealerInput<T>::add_other(int player, int)
{
    if (is_dealer(player))
        add_n_from_dealer(1);
    else if (not is_dealer())
        internal->add_other(player);
}

template<class T>
void DealerInput<T>::add_from_dealer(const typename T::open_type& input)
{
    add_from_dealer(vector<typename T::open_type>({input}));
}

template<class T>
void DealerInput<T>::add_from_dealer(const vector<typename T::open_type>& inputs)
{
    int n = P.num_players() - 1;
    os.reserve(inputs.size() * T::open_type::size());

    for (auto& input : inputs)
    {
        auto rest = input;
        for (int i = 0; i < n; i++)
            if (i != king)
            {
                auto r = dealer_prngs[i].template get<T>();
                rest -= r;
            }

        os.append_no_resize((octet*) rest.get_ptr(),
                T::open_type::size());
    }

    from_dealer = true;
}

template<class T>
void DealerInput<T>::add_n_from_dealer(size_t n_inputs, bool random)
{
    if (random)
        for (size_t i = 0; i < n_inputs; i++)
            random_shares.push_back(non_dealer_random_prng.get<T>());
    else
    {
        if (my_num != king)
            for (size_t i = 0; i < n_inputs; i++)
                shares.push_back(non_dealer_prng.get<T>());
        from_dealer = true;
    }
}

template<class T>
typename T::open_type DealerInput<T>::random_for_dealer()
{
    T res;
    for (auto& prng : dealer_random_prngs)
    {
        auto share = prng.template get<typename T::open_type>();
        res += share;
    }
    return res;
}

template<class T>
void DealerInput<T>::exchange()
{
    CODE_LOCATION
    if (from_dealer)
    {
        if (is_dealer())
            P.send_to(king, os);
        else if (P.my_num() == king)
            P.receive_player(dealer_player(), os);
        else
            shares.reset();
        random_shares.reset();
    }
    else if (not is_dealer())
        internal->exchange();
}

template<class T>
T DealerInput<T>::finalize(int player, int)
{
    if (is_dealer())
        return {};
    else
    {
        if (is_dealer(player))
            return finalize_from_dealer();
        else
            return internal->finalize(player);
    }
}

template<class T>
T DealerInput<T>::finalize_from_dealer()
{
    if (king == P.my_num())
        return os.get<T>();
    else
        return shares.next();
}

template<class T>
T DealerInput<T>::finalize_random()
{
    return random_shares.next();
}

template<class T>
void DealerInput<T>::require(size_t n_inputs)
{
    assert(not is_dealer());

    if (my_num == king)
        os.require<T>(n_inputs);
    else
        shares.require(n_inputs);
}

template<class T>
template<bool IS_KING, bool RANDOM>
T DealerInput<T>::finalize_no_check()
{
    if (RANDOM)
    {
        return finalize_random();
    }

    if (IS_KING)
    {
        return os.get_no_check<T>();
    }
    else
        return shares.next();
}

template<class T>
template<bool IS_KING, int N, bool RANDOM>
array<T, N> DealerInput<T>::finalize_no_check()
{
    array<T, N> res;
    for (int i = 0; i < N - 1; i++)
        res[i] = finalize_no_check<IS_KING, RANDOM>();
    res[N - 1] = finalize_no_check<IS_KING, false>();
    return res;
}

#endif /* PROTOCOLS_DEALERINPUT_HPP_ */
