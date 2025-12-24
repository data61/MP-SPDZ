/*
 * DealerInput.h
 *
 */

#ifndef PROTOCOLS_DEALERINPUT_H_
#define PROTOCOLS_DEALERINPUT_H_

#include "../Networking/AllButLastPlayer.h"
#include "Processor/Input.h"

template<class T>
class DealerInput : public InputBase<T>
{
    Player& P;
    SeededPRNG G;
    bool from_dealer;
    AllButLastPlayer sub_player;
    SemiInput<SemiShare<typename T::clear>>* internal;
    int king;
    vector<SeededPRNG> dealer_prngs;
    vector<PRNG> dealer_random_prngs;
    PRNG non_dealer_prng, non_dealer_random_prng;
    octetStream os;
    IteratorVector<T> shares, random_shares;
    int my_num;

public:
    DealerInput(SubProcessor<T>& proc, typename T::MAC_Check&);
    DealerInput(typename T::MAC_Check&, Preprocessing<T>&, Player& P,
            typename T::Protocol* = 0);
    DealerInput(Player& P);
    DealerInput(SubProcessor<T>*, Player& P);
    ~DealerInput();

    int dealer_player();
    bool is_dealer(int player = -1);
    bool is_king();

    void reset(int player);
    void add_mine(const typename T::open_type& input, int n_bits = -1);
    void add_other(int player, int n_bits = -1);
    void add_from_dealer(const typename T::open_type& input);
    void add_from_dealer(const vector<typename T::open_type>& input);
    void add_n_from_dealer(size_t n_inputs, bool random = false);
    typename T::open_type random_for_dealer();
    void exchange();
    T finalize(int player, int n_bits = -1);
    T finalize_from_dealer();
    template<bool IS_KING, bool RANDOM>
    T finalize_no_check();
    template<bool IS_KING, int N, bool RANDOM>
    array<T, N> finalize_no_check();
    T finalize_random();
    void require(size_t n_inputs);
};

#endif /* PROTOCOLS_DEALERINPUT_H_ */
