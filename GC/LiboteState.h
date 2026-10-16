/*
 * LiboteState.h
 *
 */

#ifndef GC_LIBOTESTATE_H_
#define GC_LIBOTESTATE_H_

#include "Networking/PlayerCoSocket.h"

#include <secure-join/CorGenerator/CorGenerator.h>

namespace GC
{

template<class T>
class SemiSecureStateBase
{
    WaitQueue<const void*> job_queue, res_queue;

    pthread_t thread;

    static void* run_thread(void* state);

    void run();

public:
    macoro::thread_pool pools[2];
    macoro::thread_pool::work works[2];
    osuCrypto::PRNG prngs[2] = {osuCrypto::sysRandomSeed(), osuCrypto::sysRandomSeed()};
    secJoin::CorGenerator oles[2];

    array<PlayerCoSocket*, 4> co_sockets;
    Player& P;

    osuCrypto::BitVector base_bits;
    array<vector<array<PRNG, 2>>, 2> G_sender;
    array<vector<PRNG>, 2> G_receiver;

    SemiSecureStateBase(Player& P);
    ~SemiSecureStateBase();

    template<class U>
    void set_sender_base_ots(int role, U& sender);
    template<class U>
    void set_receiver_base_ots(int role, U& receiver);

    vector<osuCrypto::block> base_receiver_ots(int role, size_t size = 128);
    vector<array<osuCrypto::block, 2>> base_sender_ots(int role, size_t size =
            128);

    void generate(const void* job);
};

class SemiSecureShuffleState : public SemiSecureStateBase<SemiSecureShuffleState>
{
public:
    typedef const vector<SemiSecurePerm*> shuffle_gen_type;
    typedef pair<size_t, shuffle_gen_type> job_type;

    void generate_role(job_type& job, int role);
};

class SemiSecureTripleState : public SemiSecureStateBase<SemiSecureTripleState>
{
public:
    typedef pair<int, array<vector<array<SemiSecret, 3>>, 2>> job_type;

    void generate_role(job_type& job, int role);
};

}

#endif /* GC_LIBOTESTATE_H_ */
