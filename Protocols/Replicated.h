/*
 * Replicated.h
 *
 */

#ifndef PROTOCOLS_REPLICATED_H_
#define PROTOCOLS_REPLICATED_H_

#include <assert.h>
#include <vector>
#include <array>
using namespace std;

#include "Tools/octetStream.h"
#include "Tools/random.h"
#include "Tools/PointerVector.h"
#include "Networking/Player.h"
#include "Processor/Memory.h"
#include "Math/FixedVec.h"
#include "Processor/TruncPrTuple.h"

template<class T> class SubProcessor;
template<class T> class ReplicatedMC;
template<class T> class ReplicatedInput;
template<class T> class Preprocessing;
template<class T> class SecureShuffle;
template<class T> class Rep3Shuffler;
class Instruction;

/**
 * Base class for replicated three-party protocols
 */
class ReplicatedBase
{
public:
    mutable array<PRNG, 2> shared_prngs;

    Player& P;

    ReplicatedBase(Player& P);
    ReplicatedBase(Player& P, array<PRNG, 2>& prngs);
    virtual ~ReplicatedBase() {}

    ReplicatedBase branch() const;

    template<class T>
    FixedVec<T, 2> get_random();
    template<class T>
    void randomize(FixedVec<T, 2>& res);

    int get_n_relevant_players() { return P.num_players() - 1; }

    template<class T>
    void output_time();

    virtual double randomness_time();
};

/**
 * Abstract base class for multiplication protocols
 */
template <class T>
class ProtocolBase
{
    virtual void buffer_random() { throw not_implemented(); }

protected:
    vector<T> random;

    void add_mul(int n);

public:
    typedef T share_type;

    typedef SecureShuffle<T> Shuffler;

    long trunc_pr_counter, trunc_pr_big_counter;
    long rounds, trunc_rounds;
    long dot_counter;
    long bit_counter;
    long counter;

    int buffer_size;

    template<class U>
    static void sync(vector<U>& x, Player& P);

    ProtocolBase();
    virtual ~ProtocolBase();

    void mulrs(const vector<int>& reg, SubProcessor<T>& proc);

    void multiply(vector<T>& products, vector<pair<T, T>>& multiplicands,
            int begin, int end, SubProcessor<T>& proc);

    /// Single multiplication
    T mul(const T& x, const T& y);

    /// Initialize protocol if needed (repeated call possible)
    virtual void init(Preprocessing<T>&, typename T::MAC_Check&) {}

    /// Initialize multiplication round
    virtual void init_mul() = 0;
    /// Schedule multiplication of operand pair
    virtual void prepare_mul(const T& x, const T& y, int n = -1) = 0;
    virtual void prepare_mult(const T& x, const T& y, int n, bool repeat);
    /// Run multiplication protocol
    virtual void exchange() = 0;
    /// Get next multiplication result
    virtual T finalize_mul(int n = -1) = 0;
    /// Store next multiplication result in ``res``
    virtual void finalize_mult(T& res, int n = -1);

    void prepare_mul_fast(const T& x, const T& y) { prepare_mul(x, y); }
    T finalize_mul_fast() { return finalize_mul(); }

    /// Initialize dot product round
    void init_dotprod() { init_mul(); }
    /// Add operand pair to current dot product
    void prepare_dotprod(const T& x, const T& y) { prepare_mul(x, y); }
    /// Finish dot product
    void next_dotprod() {}
    /// Get next dot product result
    T finalize_dotprod(int length);

    virtual T get_random();

    virtual void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc,
            true_type)
    { (void) regs, (void) size; (void) proc; throw runtime_error("trunc_pr not implemented"); }
    virtual void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc,
            false_type)
    { (void) regs, (void) size; (void) proc; throw runtime_error("trunc_pr not implemented"); }

    virtual void randoms(T&, int) { throw runtime_error("randoms not implemented"); }
    virtual void randoms_inst(StackedVector<T>&, const Instruction&);

    template<int = 0>
    void matmulsm(SubProcessor<T> & proc, MemoryPart<T>& source,
            const Instruction& instruction)
    { proc.matmulsm(source, instruction.get_start()); }

    template<int = 0>
    void conv2ds(SubProcessor<T>& proc, const Instruction& instruction)
    { proc.conv2ds(instruction); }

    virtual void start_exchange() { exchange(); }
    virtual void stop_exchange() {}

    virtual void check() {}

    virtual void cisc(SubProcessor<T>&, const Instruction&)
    { throw runtime_error("CISC instructions not implemented"); }

    virtual vector<int> get_relevant_players();

    virtual int get_buffer_size() { return 0; }

    virtual void set_suffix(const string&) {}

    template<class U>
    void forward_sync(vector<U>&) {}

    void unsplit(StackedVector<T>&,
            StackedVector<typename T::bit_type>&, const Instruction&)
    { throw runtime_error("unsplitting not implemented"); }

    virtual void set_fast_mode(bool) {}

    double randomness_time() { return 0; }

    TimerWithComm prep_time() { return {}; }
};

/**
 * Semi-honest replicated three-party protocol
 */
template <class T>
class Replicated : public ReplicatedBase, public ProtocolBase<T>
{
    typedef typename T::clear value_type;

    array<octetStream, 2> os;
    IteratorVector<typename T::clear> add_shares;
    typename T::clear dotprod_share;

    bool fast_mode;

    void prepare_exchange();
    void check_received();

    static const int gen_player = 2;
    static const int comp_player = 1;

    vector<ReplicatedInput<T>*> helper_inputs;

    template<int MY_NUM>
    void trunc_pr_finish(TruncPrTupleList<T>& infos, ReplicatedInput<T>& input);

    template<int MY_NUM>
    void unsplit_finish(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);

public:
    static const bool uses_triples = false;

    typedef Rep3Shuffler<T> Shuffler;

    Replicated(Player& P);
    Replicated(const ReplicatedBase& other);
    ~Replicated();

    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
    }

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1) final;
    void exchange();
    T finalize_mul(int n = -1) final;

    void prepare_reshare(const typename T::clear& share, int n = -1);
    void prepare_mul_fast(const T& x, const T& y);
    T finalize_mul_fast();

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    T get_random();
    void randoms(T& res, int n_bits);

    void start_exchange();
    void stop_exchange();

    void set_fast_mode(bool change);

    template<int = 0>
    void unsplit(StackedVector<T>& dest,
            StackedVector<typename T::bit_type>& source,
            const Instruction& instruction);

    ReplicatedInput<T>& get_helper_input(size_t i = 0);

    virtual double randomness_time();
};

#endif /* PROTOCOLS_REPLICATED_H_ */
