/*
 * Replicated.cpp
 *
 */

#ifndef PROTOCOLS_REPLICATED_HPP_
#define PROTOCOLS_REPLICATED_HPP_

#include "Replicated.h"
#include "Processor/Processor.h"
#include "Processor/TruncPrTuple.h"
#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"
#include "Tools/DoubleRange.h"
#include "Tools/ranges.h"

#include "ReplicatedInput.h"
#include "Rep3Share2k.h"
#include "Astra.h"

#include "ReplicatedPO.hpp"
#include "Math/Z2k.hpp"

template<class T>
ProtocolBase<T>::ProtocolBase() :
        trunc_pr_counter(0), trunc_pr_big_counter(0),
        rounds(0), trunc_rounds(0), dot_counter(0),
        bit_counter(0), counter(0)
{
    buffer_size = OnlineOptions::singleton.batch_size;
}

template<class T>
Replicated<T>::Replicated(Player& P) :
        ReplicatedBase(P), fast_mode(false)
{
    assert(T::vector_length == 2);
}

template<class T>
Replicated<T>::Replicated(const ReplicatedBase& other) :
        Replicated(other.P)
{
}

template<class T>
Replicated<T>::~Replicated()
{
    for (auto x : helper_inputs)
        delete x;
    output_time<T>();
}

template<class T>
void ReplicatedBase::output_time()
{
#ifdef VERBOSE
    if (OnlineOptions::singleton.verbose)
    {
        auto time = randomness_time();
        if (time)
            cout << T::type_string() << " randomness: " << time << " seconds" << endl;
    }
#endif
}

inline
double ReplicatedBase::randomness_time()
{
    return shared_prngs[0].timer.elapsed() + shared_prngs[1].timer.elapsed();
}

template<class T>
double Replicated<T>::randomness_time()
{
    auto res = ReplicatedBase::randomness_time();
    for (auto& x : helper_inputs)
        res += x->randomness_time();
    return res;
}

inline ReplicatedBase::ReplicatedBase(Player& P) : P(P)
{
    assert(P.num_players() == 3);
	if (not P.is_encrypted())
		insecure("unencrypted communication", false);

	shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.pass_around(os, 1);
	shared_prngs[1].SetSeed(os.get_data());
}

inline ReplicatedBase::ReplicatedBase(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++)
        shared_prngs[i].SetSeed(prngs[i]);
}

inline ReplicatedBase ReplicatedBase::branch() const
{
    return {P, shared_prngs};
}

template<class T>
ProtocolBase<T>::~ProtocolBase()
{
#ifdef VERBOSE_COUNT
    if (counter or rounds)
        cerr << "Number of " << T::type_string() << " multiplications: "
                << counter << " (" << bit_counter << " bits) in " << rounds
                << " rounds" << endl;
    if (counter or rounds)
        cerr << "Number of " << T::type_string() << " dot products: " << dot_counter << endl;
    if (trunc_pr_counter or trunc_rounds)
        cerr << "Number of probabilistic truncations: " << trunc_pr_counter << " in " << trunc_rounds << " rounds" << endl;
#endif
}

template<class T>
void ProtocolBase<T>::mulrs(const vector<int>& reg,
        SubProcessor<T>& proc)
{
    proc.mulrs(reg);
}

template<class T>
void ProtocolBase<T>::multiply(vector<T>& products,
        vector<pair<T, T> >& multiplicands, int begin, int end,
        SubProcessor<T>& proc)
{
#ifdef VERBOSE_CENTRAL
    fprintf(stderr, "multiply from %d to %d in %d\n", begin, end,
            BaseMachine::thread_num);
#endif

    init(proc.DataF, proc.MC);
    init_mul();
    for (int i = begin; i < end; i++)
        prepare_mul(multiplicands[i].first, multiplicands[i].second);
    exchange();
    for (int i = begin; i < end; i++)
        products[i] = finalize_mul();
}

template<class T>
T ProtocolBase<T>::mul(const T& x, const T& y)
{
    init_mul();
    prepare_mul(x, y);
    exchange();
    return finalize_mul();
}

template<class T>
void ProtocolBase<T>::prepare_mult(const T& x, const T& y, int n,
		bool)
{
    prepare_mul(x, y, n);
}

template<class T>
void ProtocolBase<T>::finalize_mult(T& res, int n)
{
    res = finalize_mul(n);
}

template<class T>
T ProtocolBase<T>::finalize_dotprod(int length)
{
    counter += length;
    dot_counter++;
    T res;
    for (int i = 0; i < length; i++)
        res += finalize_mul();
    return res;
}

template<class T>
T ProtocolBase<T>::get_random()
{
    if (random.empty())
    {
        buffer_random();
        assert(not random.empty());
    }

    auto res = random.back();
    random.pop_back();
    return res;
}

template<class T>
vector<int> ProtocolBase<T>::get_relevant_players()
{
    vector<int> res;
    int n = dynamic_cast<typename T::Protocol&>(*this).P.num_players();
    for (int i = 0; i < T::threshold(n) + 1; i++)
        res.push_back(i);
    return res;
}

template<class T>
void Replicated<T>::init_mul()
{
    if (os[1].left() or add_shares.left())
        throw runtime_error("unused data in Rep3");

    for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template<class T>
void Replicated<T>::set_fast_mode(bool change)
{
    fast_mode = change;
}

template<class T>
void Replicated<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    typename T::value_type add_share = x.local_mul(y);
    if (not T::clear::binary or fast_mode)
        add_shares.push_back(add_share);
    else
        prepare_reshare(add_share, n);
}

template<class T>
void Replicated<T>::prepare_mul_fast(const T& x,
        const T& y)
{
    add_shares.push_back(x.local_mul(y));
}

template<class T>
void Replicated<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    if (T::clear::binary)
    {
        typename T::value_type tmp[2];
        for (int i = 0; i < 2; i++)
            tmp[i].randomize(shared_prngs[i], n);
        auto add_share = share + tmp[0] - tmp[1];
        add_shares.push_back(add_share);
        add_share.pack(os[0], n);
    }
    else
        add_shares.push_back(share);
}

template<class T>
void Replicated<T>::prepare_exchange()
{
    if (not T::clear::binary or fast_mode)
    {
        os[0].reserve(add_shares.size() * T::clear::size());
        for (auto& add_share : add_shares)
        {
            add_share += shared_prngs[0];
            add_share -= shared_prngs[1];
            os[0].append_no_resize((octet*) add_share.get_ptr(),
                    add_share.size());
        }
    }
    add_shares.reset();
}

template<class T>
void Replicated<T>::exchange()
{
    CODE_LOCATION
    prepare_exchange();
    os[0].append(0);
    if (os[0].get_length() > 0)
        P.pass_around(os[0], os[1], 1);
    this->rounds++;
    check_received();
}

template<class T>
void Replicated<T>::start_exchange()
{
    prepare_exchange();
    os[0].append(0);
    P.send_relative(1, os[0]);
    this->rounds++;
}

template<class T>
void Replicated<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
    check_received();
}

template<class T>
void Replicated<T>::check_received()
{
    if (not T::clear::binary or fast_mode)
        if (os[1].left() < T::clear::size() * add_shares.left())
            throw runtime_error("insufficient information received in Rep3");
}

template<class T>
void ProtocolBase<T>::add_mul(int n)
{
    // counted in SubProcessor
    // this->counter++;
    if (T::clear::binary)
        this->bit_counter += n < 0 ? T::default_length : n;
}

template<class T>
inline T Replicated<T>::finalize_mul(int n)
{
    this->add_mul(n);
    T result;
    result[0] = add_shares.next();
    if (T::clear::binary and not fast_mode)
        result[1].unpack(os[1], n);
    else
        result[1].assign(os[1].consume_no_check(T::clear::size()));
    return result;
}

template<class T>
T Replicated<T>::finalize_mul_fast()
{
    this->add_mul(-1);
    T result;
    result[0] = add_shares.next();
    result[1].assign(os[1].consume_no_check(T::clear::size()));
    return result;
}

template<class T>
inline void Replicated<T>::init_dotprod()
{
    init_mul();
    dotprod_share.assign_zero();
}

template<class T>
inline void Replicated<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Replicated<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T Replicated<T>::finalize_dotprod(int length)
{
    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

template<class T>
T Replicated<T>::get_random()
{
    return ReplicatedBase::get_random<typename T::open_type>();
}

template<class T>
FixedVec<T, 2> ReplicatedBase::get_random()
{
    FixedVec<T, 2> res;
    randomize(res);
    return res;
}

template<class T>
void ReplicatedBase::randomize(FixedVec<T, 2>& res)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
}

template<class T>
void ProtocolBase<T>::randoms_inst(StackedVector<T>& S,
		const Instruction& instruction)
{
    for (int j = 0; j < instruction.get_size(); j++)
    {
        auto& res = S[instruction.get_r(0) + j];
        randoms(res, instruction.get_n());
    }
}

template<class T>
void Replicated<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
ReplicatedInput<T>& Replicated<T>::get_helper_input(size_t i)
{
    while (i >= helper_inputs.size())
        helper_inputs.push_back(new ReplicatedInput<T>(0, *this));
    return *helper_inputs.at(i);
}

template<class T>
template<class U>
void Replicated<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        false_type)
{
    CODE_LOCATION
    assert(regs.size() % 4 == 0);
    assert(proc.P.num_players() == 3);
    assert(proc.Proc != 0);
    bool generate = P.my_num() == gen_player;
    bool compute = P.my_num() == comp_player;
    auto& S = proc.get_S();
    TruncPrTupleList<T> infos(regs, S, size);

    octetStream cs;

    auto& input = get_helper_input();
    input.reset_all(P);

    // use https://eprint.iacr.org/2018/403
    bool have_big_gap = infos.have_big_gap();

    for (auto info : infos)
        if (info.small_gap())
        {
            this->trunc_pr_counter += size;
        }
        else
        {
            have_big_gap = true;
            this->trunc_pr_big_counter += size;
        }

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
        {
            if (info.big_gap())
            {
                auto dest_it = info.dest_range.begin();
                cs.reserve(size * value_type::size());
                for (auto& x : info.source_range)
                {
                    auto& y = *dest_it++;
                    auto r = this->shared_prngs[0].template get<value_type>();
                    y[1] = x.sum().signed_rshift(info.m) - r;
                    cs.store_no_resize(y[1]);
                    y[0] = r;
                }
            }
        }

        if (have_big_gap)
            P.send_to(comp_player, cs);
    }

    if (compute)
    {
        if (have_big_gap)
            P.receive_player(gen_player, cs);
        for (auto info : infos)
        {
            if (info.small_gap())
                for (auto& x: info.source_range)
                {
                    auto c = x.sum() + info.add_before() - 1;
                    input.add_mine(c >> info.m);
                    input.add_mine(c.msb());
                }
            else
            {
                auto dest_it = info.dest_range.begin();
                if (cs.left() < size_t(value_type::size() * size))
                    throw runtime_error("insufficient data in trunc_pr");

                for (auto& x: info.source_range)
                {
                    auto& y = *dest_it++;
                    y[0] = cs.get_no_check<value_type>();
                    y[1] = x[1].signed_rshift(info.m);
                }
            }
        }
    }

    if (have_big_gap and not (compute or generate))
    {
        for (auto info : infos)
            if (info.big_gap())
                for (int i = 0; i < size; i++)
                {
                    auto& x = S[info.source_base + i];
                    auto& y = S[info.dest_base + i];
                    y[0] = x[0].signed_rshift(info.m);
                    y[1] = this->shared_prngs[1].template get<value_type>();
                }
    }

#define X(I) if (P.my_num() == I) trunc_pr_finish<I>(infos, input);
    X(0) X(1) X(2)
#undef X
}

template<class T>
template<int MY_NUM>
void Replicated<T>::trunc_pr_finish(TruncPrTupleList<T>& infos,
        ReplicatedInput<T>& input)
{
    if (infos.have_small_gap())
    {
        input.add_other(comp_player);
        input.exchange();
        auto& input2 = get_helper_input(1);
        input2.reset_all(P);

        for (auto info : infos)
            if (info.small_gap())
            {
                auto it = info.source_range.begin();
                for (auto& y : info.dest_range)
                {
                    const int comp_offset = comp_player - MY_NUM;
                    auto c_prime = input.finalize_offset(comp_offset);
                    auto c_dprime = input.finalize_offset(comp_offset);

                    T r_prime, r_msb;
                    if (MY_NUM != comp_player)
                    {
                        int index = MY_NUM == 2 ? 0 : 1;
                        auto r = (*it++)[index];
                        r_prime[index] = r >> info.m;
                        r_msb[index] = r.msb();
                        input2.add_mine(r_msb.local_mul(c_dprime));
                    }

                    y = c_prime + r_prime;
                    y -= info.correction_shift(r_msb + c_dprime);
                }
            }

        input2.add_other(0);
        input2.add_other(2);
        input2.exchange();

        for (auto info : infos)
            if (info.small_gap())
                for (auto &y : info.dest_range)
                    y += info.correction_shift(input2.finalize_offset(2 - MY_NUM)
                            + input2.finalize_offset(0 - MY_NUM))
                            - T::constant(info.subtract_after() - 1, MY_NUM);
    }
}

template<class T>
template<class U>
void Replicated<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Replicated<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

template<class T>
template<int>
void Replicated<T>::unsplit(StackedVector<T>& dest,
        StackedVector<typename T::bit_type>& source,
        const Instruction& instruction)
{
    CODE_LOCATION
    int n_bits = instruction.get_size();
    assert(instruction.get_start().size() > 0);
    assert(instruction.get_start().size() <= 2);
    auto& P = this->P;

    auto& input = get_helper_input();
    input.reset_all(P);

    if (P.my_num() == 0)
    {
        auto range = BlockRange(source, instruction.get_r(0), n_bits);
        input.prepare(n_bits);
        auto dest_it = dest.iterator_for_size(instruction.get_start()[0],
                n_bits);
        for (auto& x : range)
            for (auto bit : BitLeftRange(x.sum(), x, range))
                input.add_mine_prepared(*dest_it++, bit);
    }
    else
        input.add_other(0);

#define X(I) if (P.my_num() == I) unsplit_finish<I>(dest, source, instruction);
    X(0) X(1) X(2)
#undef X
}

template<class T>
template<int MY_NUM>
void Replicated<T>::unsplit_finish(StackedVector<T>& dest,
        StackedVector<typename T::bit_type>& source,
        const Instruction& instruction)
{
    int n_bits = instruction.get_size();

    auto& input = get_helper_input();
    input.exchange();
    auto range = BlockRange(source, instruction.get_r(0), n_bits);

    if (instruction.get_start().size() == 2)
    {
        if (MY_NUM != 0)
        {
            for (auto it : DoubleRange(dest, instruction.get_start()[0],
                    instruction.get_start()[1], n_bits))
            {
                auto& x = it.first;
                x = input.finalize_offset(-MY_NUM);
                it.second = {};
            }

            auto dest_it = dest.iterator_for_size(instruction.get_start()[1], n_bits);
            for (auto& x : range)
                for (auto bit : BitLeftRange(x[MY_NUM - 1], x, range))
                    (*dest_it++)[MY_NUM - 1] = bit;
        }
    }
    else
    {
        auto& input2 = get_helper_input(1);
        input2.reset_all(P);

        if (MY_NUM != 0)
        {
            auto dest_it = dest.iterator_for_size(instruction.get_start()[0],
                    n_bits);
            input2.prepare(n_bits);
            for (auto& x : range)
                for (auto bit : BitLeftRange(x[MY_NUM - 1], x, range))
                {
                    T a, c;
                    a[MY_NUM - 1] = bit;
                    T b = input.finalize_offset(-MY_NUM);
                    input2.add_mine_prepared(c, a.local_mul(b));
                    (*dest_it++) = a + b - 2 * c;
                }
        }

        input2.add_other(1);
        input2.add_other(2);
        input2.exchange();

        auto dest_range = Range(dest, instruction.get_start()[0], n_bits);
        if (MY_NUM == 0)
            for (auto& x : dest_range)
            {
                x -= 2
                        * (input2.finalize_offset(1 - MY_NUM)
                                + input2.finalize_offset(2 - MY_NUM));
            }
        else
        {
            for (auto& x : dest_range)
                x -= 2 * input2.finalize_offset(MY_NUM == 1 ? 1 : -1);
        }
    }
}

#endif
