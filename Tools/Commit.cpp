
#include "Commit.h"
#include "random.h"
#include "int.h"

CommitSession::CommitSession() :
        session_id(0)
{
}

CommitSession::CommitSession(const PlayerBase& P)
{
    session_id = P.get_session_id();
}

void CommitSession::Commit(octetStream& comm, octetStream& open, const octetStream& message,
        int send_player)
{
    if (session_id)
        open.store(session_id);

    open.store(send_player);
    open.append(message.get_data(), message.get_length());
    open.append_random(SEED_SIZE);
    comm = open.hash();
}


bool CommitSession::Open(octetStream& message, const octetStream& comm, octetStream& open,
        int send_player)
{
    octetStream h = open.hash();

    // first 4 bytes are player no.
    int open_player;
    try
    {
        if (session_id and open.get<word>() != session_id)
            throw runtime_error("wrong session id");

        open_player = open.get<int>();
    }
    catch (exception& e)
    {
        throw invalid_commitment(send_player, e.what());
    }

    if (!(h.equals(comm) && open_player == send_player)
            or open.left() <= SEED_SIZE)
    {
        throw invalid_commitment(send_player);
    }
    message.reset_write_head();
    message.append(open.consume(0), open.left() - SEED_SIZE);
    return true;
}

Commitment::Commitment(word session_id, int send_player) :
        session_id(session_id), send_player(send_player)
{
}

void Commitment::commit(const octetStream& message)
{
    open.reset_write_head();
    open.append_random(SEED_SIZE);
    commit(message, open);
}

void Commitment::commit(const octetStream& message, const octetStream& open)
{
    Hash hash;
    hash.update(&session_id, sizeof(session_id));
    hash.update(&send_player, sizeof(send_player));
    hash.update(message);
    hash.update(open);
    hash.final(comm);
}

void Commitment::check(const octetStream& message, const octetStream& comm,
        const octetStream& open)
{
    if (open.empty())
        throw invalid_commitment(send_player, "empty opening");
    commit(message, open);
    if (!(comm == this->comm))
        throw invalid_commitment(send_player);
}

AllCommitments::AllCommitments(const Player& P) :
        P(P), comms(P.num_players()), opens(P.num_players()),
        session_id(P.get_session_id())
{
}

void AllCommitments::commit_and_open(const octetStream& message)
{
    commit(message);
    open();
}

void AllCommitments::commit(const octetStream& message)
{
    Commitment mine(session_id, P.my_num());
    mine.commit(message);
    comms[P.my_num()] = mine.comm;
    opens[P.my_num()] = mine.open;
    P.Broadcast_Receive(comms);
}

void AllCommitments::open()
{
    P.Broadcast_Receive(opens);
}

void AllCommitments::open(const octetStream& message)
{
    messages.resize(P.num_players());
    messages[P.my_num()] = message;
    P.Broadcast_Receive(messages);
    open();
    for (int i = 0; i != P.my_num(); i++)
        check(i, messages[i]);
}

void AllCommitments::check(int player, const octetStream& message)
{
    Commitment(session_id, player).check(message, comms[player], opens[player]);
}

void AllCommitments::check_relative(int diff, const octetStream& message)
{
    check((P.my_num() + P.num_players() - diff) % P.num_players(), message);
}
