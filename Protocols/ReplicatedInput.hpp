/*
 * ReplicatedInput.cpp
 *
 */

#ifndef PROTOCOLS_REPLICATEDINPUT_HPP_
#define PROTOCOLS_REPLICATEDINPUT_HPP_

#include "ReplicatedInput.h"
#include "Processor/Processor.h"

#include "Processor/Input.hpp"

template<class T>
template<class U>
ReplicatedInput<T>::ReplicatedInput(SubProcessor<T>* proc,
        const AstraPrepProtocol<U>& protocol) :
        ReplicatedInput(proc, protocol.prng_protocol)
{
}

template<class T>
void ReplicatedInput<T>::reset(int player)
{
    InputBase<T>::reset(player);
    assert(P.num_players() == 3);
    if (player == P.my_num())
    {
        this->shares.clear();
        os.resize(2);
        for (auto& o : os)
            o.reset_write_head();
    }
    expect[player] = false;
    to_send = 0;
}

template<class T>
inline void ReplicatedInput<T>::add_mine(const typename T::open_type& input, int n_bits)
{
    auto& shares = this->shares;
    T my_share;
    if (T::clear::binary)
    {
        my_share[0].randomize(protocol.shared_prngs[0], n_bits);
        my_share[1] = input - my_share[0];
        my_share[1].pack(os[1], n_bits);
    }
    else
    {
        my_share[1] = input;
    }
    shares.push_back(my_share);
}

template<class T>
void ReplicatedInput<T>::add_mine(const span<T>& shares,
        const span<const typename T::clear>& inputs)
{
    assert(shares.size() == inputs.size());
    auto& o = os[1];
    o.reserve(T::open_type::size() * inputs.size());
    auto share = shares.begin();
    for (auto& input : inputs)
    {
        T& my_share = *share;
        share++;
        my_share[0].randomize(protocol.shared_prngs[0]);
        my_share[1] = input - my_share[0];
        o.append_no_resize((octet*) my_share[1].get_ptr(), T::open_type::size());
    }
    this->values_input += inputs.size();
    to_send = &o;
}

template<class T>
void ReplicatedInput<T>::add_other(int player, int)
{
    expect[player] = true;
}

template<class T>
void ReplicatedInput<T>::send_mine()
{
    for (auto& x : os)
        x.append(0);
    P.send_relative(os);
}

template<class T>
void ReplicatedInput<T>::prepare(size_t n_inputs)
{
    os[1].reserve(n_inputs * T::clear::size());
    to_send = &os[1];
}

template<class T>
void ReplicatedInput<T>::add_mine_prepared(T& share,
        const typename T::open_type& input)
{
    share[0].randomize(protocol.shared_prngs[0]);
    share[1] = input;
    share[1] -= share[0];
    to_send->store_no_resize(share[1]);
}

template<class T>
void ReplicatedInput<T>::exchange()
{
    CODE_LOCATION
    if (not T::clear::binary and not to_send)
    {
        prepare(this->shares.size());
        for (auto& share : this->shares)
        {
            add_mine_prepared(share, share[1]);
        }
    }

    this->values_input += this->shares.size();
    for (auto& x : os)
        x.append(0);
    bool receive = expect[P.get_player(1)];
    bool send = not os[1].empty();
    if (send)
        if (receive)
            P.pass_around(os[1], dest, -1);
        else
            P.send_to(P.get_player(-1), os[1]);
    else
        if (receive)
            P.receive_player(P.get_player(1), dest);
    this->shares.reset();
}

template<class T>
inline void ReplicatedInput<T>::finalize_other(int player, T& target,
        octetStream&, int n_bits)
{
    int offset = player - this->my_num;
    if (offset == 1 or offset == -2)
    {
        typename T::value_type t;
        t.unpack(dest, n_bits);
        target[0] = t;
        target[1] = 0;
    }
    else
    {
        target[0] = 0;
        target[1].randomize(protocol.shared_prngs[1], n_bits);
    }
}

template<class T>
T ReplicatedInput<T>::finalize_offset(int offset)
{
    T res;
    switch (offset)
    {
    case 0:
        return this->finalize_mine();
    case 1:
    case -2:
        res[0] = dest.get_no_check<typename T::value_type>();
        break;
    case 2:
    case -1:
        res[1].randomize(protocol.shared_prngs[1]);
    }
    return res;
}

template<class T>
void ReplicatedInput<T>::finalize_vector_sum(const vector<int>& players,
        const span<T>& target)
{
    assert(players.size() == 2);
    bool im_in = P.my_num() == players[0] or P.my_num() == players[1];

    if (P.get_offset(players[0]) == 1 or P.get_offset(players[1]) == 1)
    {
        auto values = new char[target.size() * sizeof(typename T::open_type)];
        auto i_value = (typename T::open_type*) values;
        dest.unserialize(i_value, target.size());
        if (im_in)
            for (auto& x : target)
                x[0] += *i_value++;
        else
            for (auto& x : target)
                x[0] = *i_value++;
        delete[] values;
    }

    if (P.get_offset(players[0]) == 2 or P.get_offset(players[1]) == 2)
    {
        auto& G = protocol.shared_prngs[1];
        if (im_in)
            for (auto& x : target)
                x[1] += G.get<typename T::open_type>();
        else
            for (auto& x : target)
                x[1] = G.get<typename T::open_type>();
    }
}

template<class T>
T PrepLessInput<T>::finalize_mine()
{
    return this->shares.next();
}

#endif
