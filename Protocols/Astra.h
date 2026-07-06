/*
 * Astra.h
 *
 */

#ifndef PROTOCOLS_ASTRA_H_
#define PROTOCOLS_ASTRA_H_

#include "Replicated.h"

template<class T> class TrioPrepShare;
template<class T> class AstraPrepShare;
template<class T> class AstraShare;
template<class T> class AstraPrepInput;

template <class T>
class AstraBase : public ProtocolBase<T>
{
    friend class AstraShare<typename T::clear>;

protected:
    vector<typename T::open_type> inputs;
    vector<array<T, 2>> input_pairs;
    IteratorVector<T> results;
    size_t n_mults;

    string suffix;

    // for trunc_pr
    static const int gen_player = 0;
    static const int comp_player = 1;

    IteratorVector<T> gen_values;

    string get_filename(bool create, const char* name = "Protocol");
    string get_output_filename();

    void debug();

    virtual int my_astra_num() = 0;

    virtual bool local_mul_for(int player) = 0;
    void prepare_exchange();

    virtual void init_reduced_mul(size_t n_mul) = 0;
    virtual void exchange_reduced_mul(size_t n_mul) = 0;

    virtual void init_input0(size_t n_mul) = 0;
    virtual void exchange_input0(size_t n_mul) = 0;
    virtual void finalize_input0(size_t n_mul) = 0;

    template<int MY_NUM>
    void trunc_pr_small_gap_finish(const TruncPrTupleList<T>& infos,
            int size, SubProcessor<T>& proc);

public:
    Player& P;

    AstraBase(Player& P);
    virtual ~AstraBase();

    virtual void init_prep() = 0;

    /// Initialize multiplication round
    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1) final;
    void prepare_mul_fast(const T& x, const T& y)
    {
        prepare_mul(x, y);
    }

    /// Initialize dot product round
    void init_dotprod();
    /// Add operand pair to current dot product
    void prepare_dotprod(const T& x, const T& y);
    /// Finish dot product
    void next_dotprod();
    /// Get next dot product result
    T finalize_dotprod(int length);

    template<int = 0>
    void trunc_pr_small_gap(const TruncPrTupleList<T>& infos, int size,
            SubProcessor<T>& proc);

    int get_n_relevant_players()
    {
        return 2;
    }

    void set_suffix(const string& suffix);

    Player& branch()
    {
        throw not_implemented();
    }
};

template<class T>
class AstraOnlineBase : public AstraBase<T>
{
    typedef typename T::open_type open_type;
    typedef open_type value_type;

protected:
    ifstream prep;
    ofstream outputs;
    int astra_num;

    octetStream cs_prep;

    int my_astra_num()
    {
        return astra_num;
    }

    bool local_mul_for(int player)
    {
        return player == my_astra_num();
    }

    void init_input0(size_t)
    {
    }

    void exchange_input0(size_t);

    void finalize_input0(size_t)
    {
    }

public:
    AstraOnlineBase(Player& P);

    void init_prep();

    template<class U>
    U read();
    void read(octetStream& os);

    template<class U>
    void sync(vector<U>& values, Player& P);
    template<class U>
    void forward_sync(vector<U>& values);

    T get_random();
    void randoms_inst(StackedVector<T>&, const Instruction&);

    template<int = 0>
    void trunc_pr(const ArgVector& regs, int size, SubProcessor<T>& proc,
            false_type);

    template<int = 0>
    void trunc_pr_big_gap(const TruncPrTupleList<T>& infos, int size,
            SubProcessor<T>& proc);

    void unsplit(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);
    virtual void unsplit1(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction) = 0;
};

template<class T>
class Astra : public AstraOnlineBase<T>
{
    friend class AstraShare<typename T::clear>;

    typedef typename T::open_type open_type;
    typedef typename T::clear clear;
    typedef open_type value_type;

    octetStream os, os_prep, recv_os;

    T pre(const open_type& input);

    void init_reduced_mul(size_t n_mul);
    void exchange_reduced_mul(size_t n_mul);

    void unsplit1(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);

public:
    Astra(Player& P);

    /// Run multiplication protocol
    void exchange();
    /// Get next multiplication result
    T finalize_mul(int n = -1) final;
    T finalize_mul_fast()
    {
        return finalize_mul();
    }
};

template<class T>
class AstraPrepProtocol : public AstraBase<T>
{
    friend class AstraPrepInput<T>;
    friend class AstraPrepShare<typename T::clear>;
    friend class TrioPrepShare<typename T::clear>;
    friend class ReplicatedInput<T>;

    typedef typename T::open_type open_type;
    typedef open_type value_type;

    octetStream os_prep;
    octetStream cs, cs_prep;

    ReplicatedInput<Rep3Share<typename T::clear>>* unsplit_input;

    template<int MY_NUM>
    void unsplit_finish(StackedVector<T>& dest, const Instruction& instruction);

    void init_reduced_mul(size_t n_mul);
    void exchange_reduced_mul(size_t n_mul);

    void init_input0(size_t n_mul);
    void exchange_input0(size_t n_mul);
    void finalize_input0(size_t n_mul);

protected:
    ofstream prep;
    ifstream outputs;
    ReplicatedBase prng_protocol;
    ReplicatedBase prng_protocol_for_input0;
    int my_num;
    octetStream os;

    int my_astra_num()
    {
        return my_num;
    }

    int rep_index(int i);
    int rep_index(int i, int my_num);

    void add_gen(octetStream& cs, const typename T::open_type& value);

    template<int my_num>
    void pre();
    template<int my_num>
    void pre_element(T& res);
    template<int my_num>
    void pre_gamma(T& res, open_type& gamma, const open_type& input);

    void post(T& res, const open_type& gamma);

public:
    AstraPrepProtocol(Player& P);
    ~AstraPrepProtocol();

    void init_prep();

    virtual bool local_mul_for(int player)
    {
        return player == my_astra_num();
    }

    /// Run multiplication protocol
    void exchange();

    T finalize_mul(int n = -1) final;
    T finalize_mul_fast()
    {
        return finalize_mul();
    }

    template<class U>
    void store(const U& value);
    void store(const octetStream& os);

    template<class U>
    void sync(vector<U>& values, Player& P);
    template<class U>
    void forward_sync(vector<U>& values);

    T get_random();
    void randoms_inst(StackedVector<T>&, const Instruction&);

    template<int = 0>
    void trunc_pr(const ArgVector& regs, int size, SubProcessor<T>& proc,
            false_type);

    template<int = 0>
    void trunc_pr_big_gap(const TruncPrTupleList<T>& infos, int size,
            SubProcessor<T>& proc);

    template<class U>
    AstraPrepShare<U> from_rep3(const FixedVec<U, 2>& x);
    template<class U>
    AstraPrepShare<U> from_rep3(const FixedVec<U, 2>& x, int my_num);

    void unsplit(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);
    void unsplit1(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);
};

#endif /* PROTOCOLS_ASTRA_H_ */
