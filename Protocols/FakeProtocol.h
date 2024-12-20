/*
 * FakeProtocol.h
 *
 */

#ifndef PROTOCOLS_FAKEPROTOCOL_H_
#define PROTOCOLS_FAKEPROTOCOL_H_

#include "Replicated.h"
#include "SecureShuffle.h"
#include "Math/Z2k.h"
#include "Processor/Instruction.h"
#include "Processor/TruncPrTuple.h"

#include <cmath>

template<class T>
class FakeShuffle
{
public:
    typedef ShuffleStore<int> store_type;

    map<long, long> stats;

    FakeShuffle(SubProcessor<T>&)
    {
    }

    FakeShuffle(StackedVector<T>& a, size_t n, int unit_size, size_t output_base,
            size_t input_base, SubProcessor<T>&)
    {
        apply(a, n, unit_size, output_base, input_base, 0, 0);
    }

    size_t generate(size_t, store_type& store)
    {
        return store.add();
    }

    void apply(StackedVector<T>& a, size_t n, size_t unit_size, size_t output_base,
            size_t input_base, size_t, bool)
    {
        auto source = a.begin() + input_base;
        auto dest = a.begin() + output_base;
        for (size_t i = 0; i < n; i++)
            // just copy
            *dest++ = *source++;

        if (n > 1)
        {
            // swap first two to pass check
            for (size_t i = 0; i < unit_size; i++)
                swap(a[output_base + i], a[output_base + i + unit_size]);
        }
    }

    void inverse_permutation(StackedVector<T> &, size_t, size_t, size_t) {
        throw runtime_error("inverse permutation not implemented");
    };

    void apply_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &destinations,
                                    vector<size_t> &sources,
                                    vector<size_t> &unit_sizes, vector<size_t> &handles, vector<bool> &reverses,
                                    store_type&) {
        const auto n_shuffles = sizes.size();
        assert(sources.size() == n_shuffles);
        assert(destinations.size() == n_shuffles);
        assert(unit_sizes.size() == n_shuffles);
        assert(handles.size() == n_shuffles);
        assert(reverses.size() == n_shuffles);

        for (size_t i = 0; i < n_shuffles; i++) {
            this->apply(a, sizes[i], unit_sizes[i], destinations[i], sources[i], handles[i], reverses[i]);
        }
    }
};

template<class T>
class FakeProtocol : public ProtocolBase<T>
{
    PointerVector<T> results;
    SeededPRNG G;

    T dot_prod;

    T trunc_max;

    int fails;

    vector<size_t> trunc_stats;

    map<string, size_t> cisc_stats;
    map<int, size_t> ltz_stats;

public:
    typedef FakeShuffle<T> Shuffler;

    Player& P;

    FakeProtocol(Player& P) :
            fails(0), trunc_stats(T::MAX_N_BITS + 1), P(P)
    {
    }

#ifdef VERBOSE
    ~FakeProtocol()
    {
        output_trunc_max<0>(T::invertible);
        double expected = 0;
        for (int i = 0; i <= T::MAX_N_BITS; i++)
        {
            if (trunc_stats[i] != 0)
                cerr << i << ": " << trunc_stats[i] << endl;
            expected += trunc_stats[i] * exp2(i - T::MAX_N_BITS);
        }
        if (expected != 0)
            cerr << "Expected truncation failures: " << expected << endl;
        for (auto& x : cisc_stats)
        {
            cerr << x.second << " " << x.first << endl;
        }
        for (auto& x : ltz_stats)
            cerr << "LTZ " << x.first << ": " << x.second << endl;
    }

    template<int>
    void output_trunc_max(false_type)
    {
        if (trunc_max != T())
            cerr << "Maximum bit length in truncation: "
                << (bigint(typename T::clear(trunc_max)).numBits() + 1)
                << " (" << trunc_max << ")" << endl;
    }

    template<int>
    void output_trunc_max(true_type)
    {
    }
#endif

    FakeProtocol branch()
    {
        return P;
    }

    void init_mul()
    {
        results.clear();
    }

    void prepare_mul(const T& x, const T& y, int = -1)
    {
        results.push_back(x * y);
    }

    void exchange()
    {
    }

    T finalize_mul(int = -1)
    {
        return results.next();
    }

    void init_dotprod()
    {
        init_mul();
        dot_prod = {};
    }

    void prepare_dotprod(const T& x, const T& y)
    {
        dot_prod += x * y;
    }

    void next_dotprod()
    {
        results.push_back(dot_prod);
        dot_prod = 0;
    }

    T finalize_dotprod(int)
    {
        return finalize_mul();
    }

    void randoms(T& res, int n_bits)
    {
        res.randomize_part(G, n_bits);
    }

    int get_n_relevant_players()
    {
        return 1;
    }

    void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc)
    {
        trunc_pr<0>(regs, size, proc, T::characteristic_two);
    }

    template<int>
    void trunc_pr(const vector<int>&, int, SubProcessor<T>&, true_type)
    {
        throw not_implemented();
    }

    template<int>
    void trunc_pr(const vector<int>& regs, int size, SubProcessor<T>& proc, false_type)
    {
        this->trunc_rounds++;
        this->trunc_pr_counter += size * regs.size() / 4;
        for (size_t i = 0; i < regs.size(); i += 4)
            for (int l = 0; l < size; l++)
            {
                auto& res = proc.get_S_ref(regs[i] + l);
                auto& source = proc.get_S_ref(regs[i + 1] + l);
                T tmp = source;
                tmp = tmp < T() ? (T() - tmp) : tmp;
                trunc_max = max(trunc_max, tmp);
#ifdef TRUNC_PR_EMULATION_STATS
                trunc_stats.at(tmp == T() ? 0 : tmp.bit_length())++;
#endif
#ifdef CHECK_BOUNDS_IN_TRUNC_PR_EMULATION
                auto test = (source >> (regs[i + 2]));
                if (test != 0 and test != T(-1) >> regs[i + 2])
                {
                    cerr << typename T::clear(source) << " has more than "
                            << regs[i + 2]
                            << " bits in " << regs[i + 3]
                            << "-bit truncation (test value "
                            << typename T::clear(test) << ")" << endl;
                    fails++;
                    if (fails > 1000)
                        throw runtime_error("trunc_pr overflow");
                }
#endif
                int n_shift = regs[i + 3];
#ifdef ROUND_NEAREST_IN_EMULATION
                res = source >> n_shift;
                if (n_shift > 0)
                {
                    bool overflow = T(source >> (n_shift - 1)).get_bit(0);
                    res += overflow;
                }
#else
                if (TruncPrTupleWithGap<typename T::clear>(regs, i).big_gap())
                {
                    T r;
                    r.randomize(G);

                    if (source.negative())
                        res = -T(((-source + r) >> n_shift) - (r >> n_shift));
                    else
                        res = ((source + r) >> n_shift) - (r >> n_shift);
                }
                else
                {
                    T r;
                    r.randomize_part(G, n_shift);
                    res = (source + r) >> n_shift;
                }
#endif
            }
    }

    void cisc(SubProcessor<T>& processor, const Instruction& instruction)
    {
        cisc(processor, instruction, T::characteristic_two);
    }

    template<int = 0>
    void cisc(SubProcessor<T>&, const Instruction&, true_type)
    {
        throw not_implemented();
    }

    template<int = 0>
    void cisc(SubProcessor<T>& processor, const Instruction& instruction, false_type)
    {
        int r0 = instruction.get_r(0);
        string tag((char*)&r0, 4);
        cisc_stats[tag.c_str()]++;
        auto& args = instruction.get_start();
        if (tag == string("LTZ\0", 4))
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                ltz_stats[args[i + 4]] += args[i + 1];
                assert(i + args[i] <= args.size());
                assert(args[i] >= 5);
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    res = T(processor.get_S()[args[i + 3] + j]).get_bit(
                            args[i + 4] - 1);
                }
            }
        }
        else if (tag == string("EQZ\0", 4))
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                assert(i + args[i] <= args.size());
                assert(args[i] >= 5);
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    res = processor.get_S()[args[i + 3] + j] == 0;
                }
            }
        }
        else if (tag == "Trun")
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                assert(i + args[i] <= args.size());
                assert(args[i] == 7);
                int k = args[i + 4];
                int m = args[i + 5];
                int s = args[i + 6];
                assert((s == 0) or (s == 1));
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    res = ((T(processor.get_S()[args[i + 3] + j])
                            + (T(s) << (k - 1))) >> m) - (T(s) << (k - m - 1));
                }
            }
        }
        else if (tag == "FPDi")
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                assert(i + args[i] <= args.size());
                int f = args.at(i + 6);
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    mpf_class a[2];
                    for (int k = 0; k < 2; k++)
                        a[k] = bigint(typename T::clear(
                                processor.get_S()[args[i + 3 + k] + j]));
                    if (a[1] != 0)
                        res = bigint(a[0] / a[1] * exp2(f));
                    else
                        res = 0;
                }
            }
        }
        else if (tag == "exp2")
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                assert(i + args[i] <= args.size());
                int f = args.at(i + 5);
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    auto a = bigint(typename T::clear(
                                    processor.get_S()[args[i + 3] + j]));
                    res = bigint(round(exp2(mpf_class(a).get_d() / exp2(f) + f)));
                }
            }
        }
        else if (tag == "log2")
        {
            for (size_t i = 0; i < args.size(); i += args[i])
            {
                assert(i + args[i] <= args.size());
                int f = args.at(i + 5);
                for (int j = 0; j < args[i + 1]; j++)
                {
                    auto& res = processor.get_S()[args[i + 2] + j];
                    auto a = bigint(typename T::clear(
                                    processor.get_S()[args[i + 3] + j]));
                    res = bigint(round((log2(mpf_class(a).get_d()) - f) * exp2(f)));
                }
            }
        }
        else
            throw runtime_error("unknown CISC instruction: " + tag);
    }
};

#endif /* PROTOCOLS_FAKEPROTOCOL_H_ */
