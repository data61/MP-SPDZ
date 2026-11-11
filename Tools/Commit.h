#ifndef _Commit
#define _Commit

/* Define the hash based commitment scheme */

#include "Tools/octetStream.h"
#include "Networking/Player.h"

class CommitSession
{
    friend void Create_Random_Seed(octet* seed, const PlayerBase& P, int len,
            const vector<bool>& parties);

    word session_id;

    CommitSession();

public:
    CommitSession(const PlayerBase& P);

    /*
     * Commit using comm = hash(send_player || message || r)
     * where r is SEED_SIZE random bytes
     */
    void Commit(octetStream& comm, octetStream& open,
            const octetStream& message, int send_player);

    bool Open(octetStream& message, const octetStream& comm, octetStream& open,
            int send_player);

    /* Run just the Open Protocol for data[i][j] of type octetStream
     *   0 <= i < num_runs
     *   0 <= j < num_players
     * On output data[i][j] contains all the data
     * If dont!=-1 then dont open this run
     */
    void Open(vector<vector<octetStream> >& data,
            const vector<vector<octetStream> >& Comm_data,
            const vector<octetStream>& My_Open_data, const Player& P,
            int num_runs, int dont = -1);

    /* This one takes a vector open which contains 0 and 1
     * If 1 then we open this value, otherwise we do not
     */
    void Open(vector<vector<octetStream> >& data,
            const vector<vector<octetStream> >& Comm_data,
            const vector<octetStream>& My_Open_data, const vector<int> open,
            const Player& P, int num_runs);

    template<class T>
    void Commit(vector<vector<octetStream> >& Comm_data,
            vector<octetStream>& Open_data, const vector<vector<T> >& data,
            const Player& P, int num_runs);

    template<class T>
    void Open(vector<vector<T> >& data,
            const vector<vector<octetStream> >& Comm_data,
            const vector<octetStream>& My_Open_data, const Player& P,
            int num_runs, int dont = -1);

    void Commit(vector<vector<octetStream> >& Comm_data,
            vector<octetStream>& Open_data,
            const vector<vector<octetStream> >& data, const Player& P,
            int num_runs);

    void Commit_To_Challenge(vector<unsigned int>& e,
            vector<octetStream>& Comm_e, vector<octetStream>& Open_e,
            const Player& P, int num_runs);

    int Open_Challenge(vector<unsigned int>& e, vector<octetStream>& Open_e,
            const vector<octetStream>& Comm_e, const Player& P, int num_runs);

    /* Functions to Commit to Seed Values
     *  This also initialises the PRNG's in G
     */
    void Commit_To_Seeds(vector<PRNG>& G, vector<vector<octetStream> >& seeds,
            vector<vector<octetStream> >& Comm_seeds,
            vector<octetStream>& Open_seeds, const Player& P, int num_runs);
};

// same as above using less memory
class Commitment
{
    word session_id;
    int send_player;

public:
    // open only contains the randomness
    octetStream comm, open;

    Commitment(word session_id, int send_player);
    void commit(const octetStream& message);
    void commit(const octetStream& message, const octetStream& open);
    void check(const octetStream& message, const octetStream& comm,
            const octetStream& open);
};

class AllCommitments
{
    const Player& P;
    vector<octetStream> comms, opens;
    word session_id;

public:
    vector<octetStream> messages;

    AllCommitments(const Player& P);
    // no checks yet
    void commit_and_open(const octetStream& message);
    void commit(const octetStream& message);
    // only open randomness
    void open();
    // open and check everything
    void open(const octetStream& message);
    void check(int player, const octetStream& message);
    void check_relative(int diff, const octetStream& message);
};

#endif

