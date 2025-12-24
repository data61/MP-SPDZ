/*
 * Rep4Input.cpp
 *
 */

#include "Rep4Input.h"

template<class T>
Rep4Input<T>::Rep4Input(SubProcessor<T>& proc, MAC_Check_Base<T>&) :
        InputBase<T>(&proc), protocol(proc.P), P(proc.P)
{
    assert(P.num_players() == 4);
}

template<class T>
Rep4Input<T>::Rep4Input(MAC_Check_Base<T>&, Preprocessing<T>&, Player& P,
        Rep4<T>*) :
        protocol(P), P(P)
{
}

template<class T>
Rep4Input<T>::~Rep4Input()
{
    check();
    for (auto& hash : hashes)
        assert(hash.size == 0);
}

template<class T>
void Rep4Input<T>::reset(int player)
{
    if (player == P.my_num())
        to_send.reset_write_head();
}

template<class T>
void Rep4Input<T>::add_mine(const typename T::open_type& input, int)
{
    auto& prot = protocol;
    T res;
    res[0] = prot.rep_prngs[0].get();
    res[2] = prot.rep_prngs[2].get();
    res[1] = input - res[0] - res[2];
    res[1].pack(to_send);
    results[P.my_num()].push_back(res);
}

template<class T>
void Rep4Input<T>::add_other(int player, int)
{
    auto& prot = protocol;
    T res;
    switch (P.get_offset(player))
    {
    case 1:
    case 3:
        res[1] = prot.rep_prngs[1].get();
        break;
    case 2:
        for (int i = 0; i < 3; i += 2)
            res[i] = prot.rep_prngs[i].get();
        break;
    default:
        throw out_of_range("wrong player number");
    }
    results[player].push_back(res);
}

template<class T>
void Rep4Input<T>::exchange()
{
    P.pass_around(to_send, to_receive[0], -1);
    P.pass_around(to_send, to_receive[1], 1);

    if (not OnlineOptions::singleton.semi_honest)
        for (int i = 0; i < 2; i++)
            hashes[i].update(to_receive[i]);
}

template<class T>
void Rep4Input<T>::check()
{
    CODE_LOCATION
    bool check_needed = false;
    for (auto& hash : hashes)
        check_needed |= hash.size != 0;
    if (not check_needed)
        return;

    octetStream os[2][2];
    for (int i = 0; i < 2; i++)
    {
        hashes[i].final(os[0][i]);
        P.pass_around(os[0][i], os[1][i], 2);
    }
    for (int i = 0; i < 2; i++)
        if (os[0][i] != os[1][1 - i])
            throw mac_fail();
}

template<class T>
T Rep4Input<T>::finalize_mine()
{
    return results[P.my_num()].next();
}

template<class T>
void Rep4Input<T>::finalize_other(int player, T& target, octetStream&, int)
{
    target = results[player].next();
    switch (P.get_offset(player))
    {
    case 1:
        target[2].unpack(to_receive[0]);
        break;
    case 3:
        target[0].unpack(to_receive[1]);
        break;
    }
}
