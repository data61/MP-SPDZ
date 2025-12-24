/*
 * AllButZeroPlayer.h
 *
 */

#ifndef NETWORKING_ALLBUTLASTPLAYER_H_
#define NETWORKING_ALLBUTLASTPLAYER_H_

#include "Player.h"

class AllButLastPlayer : public Player
{
    const Player& P;
    Names* N;

public:
    AllButLastPlayer(const Player& P) :
            Player(*(N = new Names(P.my_num(), P.num_players() - 1))), P(P)
    {
    }

    ~AllButLastPlayer()
    {
        delete N;
    }

    void send_to(int player, const octetStream& o) const
    {
        P.send_to(player, o);
    }

    void receive_player(int i, octetStream& o) const
    {
        P.receive_player(i, o);
    }

    void send_to_no_stats(int, const octetStream&) const
    {
        throw not_implemented();
    }

    void receive_player_no_stats(int, octetStream&) const
    {
        throw not_implemented();
    }

    void send_receive_all_no_stats(const vector<vector<bool>>& channels,
            const vector<octetStream>& to_send,
            vector<octetStream>& to_receive) const
    {
        auto my_channels = channels;
        my_channels.resize(P.num_players());
        for (auto& x : my_channels)
            x.resize(P.num_players());
        auto my_to_send = to_send;
        if (P.my_num() != P.num_players() - 1)
            P.send_receive_all(my_channels, my_to_send, to_receive);
        to_receive.resize(P.num_players() - 1);
    }

    void Broadcast_Receive_no_stats(vector<octetStream>& os) const
    {
        vector<bool> senders(P.num_players(), true), receivers(P.num_players(),
                true);
        senders.back() = false;
        receivers.back() = false;
        P.partial_broadcast(senders, receivers, os);
        os.resize(num_players());
    }
};

#endif
