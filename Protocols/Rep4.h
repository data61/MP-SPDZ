/*
 * Rep4.h
 *
 */

#ifndef PROTOCOLS_REP4_H_
#define PROTOCOLS_REP4_H_

#include "Replicated.h"

/**
 * Four-party protocol with malicious security via replication
 */
template<class T>
class Rep4 : public ProtocolBase<T>
{
    friend class Rep4RingPrep<T>;

    typedef typename T::open_type open_type;
    typedef array<ElementPRNG<typename T::open_type>, 3> prngs_type;

    octetStreams send_os;
    octetStreams receive_os;
    vector<vector<bool>> channels;
    array<array<Hash, 4>, 4> send_hashes, receive_hashes;

    array<vector<open_type>, 5> add_shares;
    array<open_type, 5> dotprod_shares;
    vector<int> bit_lengths;

    class ResTuple
    {
    public:
        T res;
        open_type r;
    };

    PointerVector<ResTuple> results;

    int my_num;

    bool malicious;

    array<open_type, 5> get_addshares(const T& x, const T& y);

    void reset_joint_input(int n_inputs);
    void prepare_joint_input(int sender, int backup, int receiver,
            int outsider, vector<open_type>& inputs);
    void prepare_joint_input(int sender, int backup, int receiver, int outsider,
            vector<open_type>& inputs, vector<ResTuple>& results);
    void finalize_joint_input(int sender, int backup, int receiver,
            int outsider);
    void finalize_joint_input(int sender, int backup, int receiver,
            int outsider, vector<ResTuple>& results);

    int get_player(int offset);

    template<int = 0>
    T finalize_mul(int n_bits, true_type);
    template<int = 0>
    T finalize_mul(int n_bits, false_type);

    void must_check();

public:
    static const bool uses_triples = false;

    prngs_type rep_prngs;
    Player& P;

    Rep4(Player& P);
    Rep4(Player& P, prngs_type& prngs);
    ~Rep4();

    Rep4 branch();

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);
    void check();

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    T get_random();
    void randoms(T& res, int n_bits);

    template<int = 0>
    void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc,
            true_type);
    template<int = 0>
    void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc,
            false_type);

    template<class U>
    void split(StackedVector<T>& dest, const vector<int>& regs, int n_bits,
            const U* source, int n_inputs);

    int get_n_relevant_players() { return 2; }
};

#endif /* PROTOCOLS_REP4_H_ */
