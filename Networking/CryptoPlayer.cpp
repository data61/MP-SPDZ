/*
 * CryptoPlayer.cpp
 *
 */

#include "CryptoPlayer.h"
#include "Math/Setup.h"
#include "Tools/Bundle.h"

void check_ssl_file(string filename)
{
    if (not ifstream(filename))
        exit_error("Cannot access " + filename
                        + ". Have you set up SSL?\n"
                        "You can use `Scripts/setup-ssl.sh <nparties>`.");
}

void ssl_error(string side, string other, string me, exception& e)
{
    cerr << side << "-side handshake with " << other
            << " failed. Make sure both sides "
            << " have the necessary certificate (" << SSL_DIR << me
            << ".pem in the default configuration on their side and "
            << SSL_DIR << other << ".pem on ours),"
            << " and run `c_rehash <directory>` on its location." << endl
            << "The certificates should be the same on every host. "
            << "Also make sure that it's still valid. Certificates generated "
            << "with `Scripts/setup-ssl.sh` expire after a month." << endl;
    cerr << "See also "
            "https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html"
            "#handshake-failures" << endl;

    string ids[2];
    ids[side == "Client"] = other;
    ids[side != "Client"] = me;
    cerr << "Signature (should match the other side): ";
    for (int i = 0; i < 2; i++)
    {
        auto filename = SSL_DIR + ids[i] + ".pem";
        ifstream cert(filename);
        stringstream buffer;
        buffer << cert.rdbuf();
        if (buffer.str().empty())
            cerr << "<'" << filename << "' not found>";
        else
            cerr << octetStream(buffer.str()).hash();
        if (i == 0)
            cerr << "/";
    }
    cerr << endl;
    cerr << "SSL error: " << e.what() << endl;
    exit(1);
}

CryptoPlayer::CryptoPlayer(const Names& Nms, const string& id_base) :
        MultiPlayer<ssl_socket*>(Nms, id_base),
        ctx("P" + to_string(my_num()))
{
    sockets.resize(num_players());
    other_sockets.resize(num_players());
    senders.resize(num_players());
    receivers.resize(num_players());

    vector<int> plaintext_sockets[2];

    for (int i = 0; i < 2; i++)
    {
        PlainPlayer player(Nms, id_base + (i ? "recv" : ""));
        plaintext_sockets[i] = player.sockets;
        close_client_socket(player.socket(my_num()));
        player.sockets.clear();
    }

    for (auto& other : balanced_others())
        connect(other, plaintext_sockets);

    for (int i = 0; i < num_players(); i++)
    {
        if (i == my_num())
        {
            sockets[i] = 0;
            senders[i] = 0;
            other_sockets[i] = 0;
            receivers[i] = 0;
            continue;
        }

        senders[i] = new Sender<ssl_socket*>(
                i < my_num() ? sockets[i] : other_sockets[i], i);
        receivers[i] = new Receiver<ssl_socket*>(
                i < my_num() ? other_sockets[i] : sockets[i], i);
    }
}

void CryptoPlayer::connect(int i, vector<int>* plaintext_sockets)
{
    sockets[i] = new ssl_socket(io_service, ctx, plaintext_sockets[0][i],
            "P" + to_string(i), "P" + to_string(my_num()), i < my_num());
    other_sockets[i] = new ssl_socket(io_service, ctx, plaintext_sockets[1][i],
            "P" + to_string(i), "P" + to_string(my_num()), i < my_num());

}

CryptoPlayer::CryptoPlayer(const Names& Nms, int id_base) :
        CryptoPlayer(Nms, to_string(id_base))
{
}

CryptoPlayer::~CryptoPlayer()
{
    for (int i = 0; i < num_players(); i++)
    {
        delete sockets[i];
        delete other_sockets[i];
        delete senders[i];
        delete receivers[i];
    }
}

void CryptoPlayer::send_to_no_stats(int other, const octetStream& o) const
{
    assert(other != my_num());
    senders[other]->request(o);
    senders[other]->wait(o);
}

void CryptoPlayer::receive_player_no_stats(int other, octetStream& o) const
{
    assert(other != my_num());
    receivers[other]->request(o);
    receivers[other]->wait(o);
}

size_t CryptoPlayer::send_no_stats(int player, const PlayerBuffer& buffer,
        bool block) const
{
    assert(player != my_num());
    auto socket = senders.at(player)->get_socket();
    if (block)
    {
        send(socket, buffer.data, buffer.size);
        return buffer.size;
    }
    else
        return send_non_blocking(socket, buffer.data, buffer.size);
}

size_t CryptoPlayer::recv_no_stats(int player, const PlayerBuffer& buffer,
        bool block) const
{
    assert(player != my_num());
    auto socket = receivers.at(player)->get_socket();
    if (block)
    {
        receive(socket, buffer.data, buffer.size);
        return buffer.size;
    }
    else
        return receive_non_blocking(socket, buffer.data, buffer.size);
}

void CryptoPlayer::exchange_no_stats(int other, const octetStream& to_send,
        octetStream& to_receive) const
{
    assert(other != my_num());
    if (&to_send == &to_receive)
    {
        MultiPlayer<ssl_socket*>::exchange_no_stats(other, to_send, to_receive);
    }
    else
    {
        senders[other]->request(to_send);
        receivers[other]->request(to_receive);
        senders[other]->wait(to_send);
        receivers[other]->wait(to_receive);
    }
}

void CryptoPlayer::pass_around_no_stats(const octetStream& to_send,
        octetStream& to_receive, int offset) const
{
    assert(get_player(offset) != my_num());
    if (&to_send == &to_receive)
    {
        MultiPlayer<ssl_socket*>::pass_around_no_stats(to_send, to_receive, offset);
    }
    else
    {
#ifdef TIME_ROUNDS
        Timer recv_timer;
        TimeScope ts(recv_timer);
#endif
        senders[get_player(offset)]->request(to_send);
        receivers[get_player(-offset)]->request(to_receive);
        senders[get_player(offset)]->wait(to_send);
        receivers[get_player(-offset)]->wait(to_receive);
#ifdef TIME_ROUNDS
        cout << "Exchange time: " << recv_timer.elapsed() << " seconds to receive "
            << 1e-3 * to_receive.get_length() << " KB" << endl;
#endif
    }
}

void CryptoPlayer::send_receive_all_no_stats(const vector<vector<bool>>& channels,
        const vector<octetStream>& to_send,
        vector<octetStream>& to_receive) const
{
    to_receive.resize(num_players());
    bool global = channels.empty();
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = global or channels[other][my_num()];
        if (global or channels[my_num()][other])
            this->senders[other]->request(to_send[other]);
        if (receive)
            this->receivers[other]->request(to_receive[other]);
    }
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = global or channels[other][my_num()];
        if (global or channels[my_num()][other])
            this->senders[other]->wait(to_send[other]);
        if (receive)
            this->receivers[other]->wait(to_receive[other]);
    }
}

void CryptoPlayer::partial_broadcast_no_stats(const vector<bool>& my_senders,
        const vector<bool>& my_receivers,
        vector<octetStream>& os) const
{
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = my_senders.at(other);
        if (my_receivers.at(other))
        {
            this->senders[other]->request(os[my_num()]);
            sent += os[my_num()].get_length();
        }
        if (receive)
            this->receivers[other]->request(os[other]);
    }
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        bool receive = my_senders[other];
        if (my_receivers[other])
            this->senders[other]->wait(os[my_num()]);
        if (receive)
            this->receivers[other]->wait(os[other]);
    }
}

void CryptoPlayer::Broadcast_Receive_no_stats(vector<octetStream>& os) const
{
    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        this->senders[other]->request(os[my_num()]);
        receivers[other]->request(os[other]);
    }

    for (int offset = 1; offset < num_players(); offset++)
    {
        int other = get_player(offset);
        this->senders[other]->wait(os[my_num()]);
        receivers[other]->wait(os[other]);
    }
}

Player* CryptoPlayer::fresh_fork(string suffix)
{
    return new CryptoPlayer(N, get_id() + "-" + suffix);
}
