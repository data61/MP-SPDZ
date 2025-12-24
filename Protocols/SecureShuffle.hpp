/*
 * SecureShuffle.hpp
 *
 */

#ifndef PROTOCOLS_SECURESHUFFLE_HPP_
#define PROTOCOLS_SECURESHUFFLE_HPP_

#include "SecureShuffle.h"
#include "Tools/Waksman.h"
#include "Tools/CodeLocations.h"

#include <math.h>
#include <algorithm>

template<class T>
class ShuffleTuple
{
    typedef typename T::Protocol::Shuffler::shuffle_type shuffle_type;

public:
    size_t size, dest, source, unit_size;
    const shuffle_type& shuffle;
    bool reverse;

    ShuffleTuple(size_t size, size_t dest, size_t source, size_t unit_size,
            const shuffle_type& shuffle, bool reverse) :
            size(size), dest(dest), source(source), unit_size(unit_size),
            shuffle(shuffle), reverse(reverse)
    {
    }

    ShuffleTuple(size_t size, size_t dest, size_t source, size_t unit_size,
            const typename ShuffleStore<shuffle_type>::store_type& stored,
            bool reverse) :
            ShuffleTuple(size, dest, source, unit_size, stored.second, reverse)
    {
        if (stored.first == 0)
            throw runtime_error("shuffle has been deleted");
        if (stored.first != size / unit_size)
            throw runtime_error("wrong shuffle size");
    }
};

template<class T>
void ShuffleStore<T>::lock()
{
    store_lock.lock();
}

template<class T>
void ShuffleStore<T>::unlock()
{
    store_lock.unlock();
}

template<class T>
int ShuffleStore<T>::add(unsigned n_shuffles)
{
    lock();
    int res = shuffles.size();
    shuffles.push_back({n_shuffles, {}});
    unlock();
    return res;
}

template<class T>
typename ShuffleStore<T>::store_type& ShuffleStore<T>::get(int handle)
{
    lock();
    auto& res = shuffles.at(handle);
    unlock();
    return res;
}

template<class T>
void ShuffleStore<T>::del(int handle)
{
    lock();
    shuffles.at(handle) = {};
    unlock();
}

template<class T>
SecureShuffle<T>::SecureShuffle(SubProcessor<T>& proc) :
        proc(proc)
{
}

template<class T>
void SecureShuffle<T>::apply_multiple(StackedVector<T> &a,
        vector<ShuffleTuple<T>>& shuffles)
{
    CODE_LOCATION

    // SecureShuffle works by making t players create and "secret-share" a permutation.
    // Then each permutation is applied in a pass. As long as one of these permutations was created by an honest party,
    // the resulting combined shuffle is hidden.
    const auto n_passes = proc.protocol.get_relevant_players().size();

    // Initialize the shuffles.
    vector is_exact(shuffles.size(), false);
    vector<vector<T>> to_shuffle;
    int max_depth = prep_multiple(a, shuffles, to_shuffle, is_exact);

    // Apply the shuffles.
    for (size_t pass = 0; pass < n_passes; pass++)
    {
        for (int depth = 0; depth < max_depth; depth++)
            parallel_waksman_round(pass, depth, true, to_shuffle, shuffles);
        for (int depth = max_depth - 1; depth >= 0; depth--)
            parallel_waksman_round(pass, depth, false, to_shuffle, shuffles);
    }

    // Write the shuffled results into memory.
    finalize_multiple(a, shuffles, to_shuffle, is_exact);
}


template<class T>
void SecureShuffle<T>::inverse_permutation(StackedVector<T> &stack, size_t n, size_t output_base,
                                           size_t input_base) {
    CODE_LOCATION
    int alice = 0;
    int bob = 1;

    auto &P = proc.P;
    auto &input = proc.input;

    // This method only supports two players
    if (P.num_players() != 2)
        throw runtime_error("inverse permutation only implemented for two players");
    // The current implementation assumes a semi-honest environment
    if (T::malicious)
        throw runtime_error("inverse permutation only implemented for semi-honest protocols");

    vector<vector<T>> to_shuffle;
    vector<bool> is_exact(1, false);

    // We are dealing directly with permutations, so the unit_size will always be 1.
    shuffle_type shuffle;
    vector<ShuffleTuple<T>> shuffles({{n, output_base, input_base, 1, shuffle, true}});

    prep_multiple(stack, shuffles, to_shuffle, is_exact);

    size_t shuffle_size = to_shuffle.at(0).size() / shuffles.at(0).unit_size;
    // Alice generates stack local permutation and shares the waksman configuration bits secretly to Bob.
    vector<int> perm_alice(shuffle_size);
    if (P.my_num() == alice) {
        perm_alice = generate_random_permutation(n);
    }
    auto config = configure(alice, &perm_alice, n);
    shuffle = { config, config };

    // Apply perm_alice to perm_alice to get perm_bob,
    // stack permutation that we can reveal to Bob without Bob learning anything about perm_alice (since it is masked by perm_a)
    for (int depth = 0; depth < log2(shuffle_size); depth++)
        parallel_waksman_round(0, depth, true, to_shuffle, shuffles);
    for (int depth = log2(shuffle_size); depth >= 0; depth--)
        parallel_waksman_round(0, depth, false, to_shuffle, shuffles);

    // Store perm_bob at stack[output_base]
    finalize_multiple(stack, shuffles, to_shuffle, is_exact);

    // Reveal permutation perm_bob = perm_a * perm_alice
    // Since this permutation is masked by perm_a, Bob learns nothing about perm
    vector<int> perm_bob(shuffle_size);
    typename T::PrivateOutput output(proc);
    for (size_t i = 0; i < n; i++)
        output.prepare_sending(stack[output_base + i], bob);
    output.exchange();
    for (size_t i = 0; i < n; i++) {
        // TODO: Is there a better way to convert a T::clear to int?
        bigint val;
        output.finalize(bob).to(val);
        perm_bob[i] = (int) val.get_si();
    }

    vector<int> perm_bob_inv(shuffle_size);
    if (P.my_num() == bob) {
        for (int i = 0; i < (int) n; i++)
            perm_bob_inv[perm_bob[i]] = i;
        // Pad the permutation to n_pow2
        // Required when using waksman networks
        for (int i = (int) n; i < (int) shuffle_size; i++)
            perm_bob_inv[i] = i;
    }

    // Alice secret shares perm_a with bob
    // perm_a is stored in the stack at output_base
    input.reset_all(P);
    if (P.my_num() == alice) {
        for (int i = 0; i < (int) n; i++)
            input.add_mine(perm_alice[i]);
    }
    input.exchange();
    for (int i = 0; i < (int) n; i++)
        stack[output_base + i] = input.finalize(alice);

    // The two parties now jointly compute perm_a * perm_bob_inv to obtain perm_inv
    to_shuffle.clear();
    shuffles.at(0).source = shuffles.at(0).dest;
    prep_multiple(stack, shuffles, to_shuffle, is_exact);

    config = configure(bob, &perm_bob_inv, n);
    shuffle = { config, config };

    for (int i = 0; i < log2(shuffle_size); i++)
        parallel_waksman_round(0, i, true, to_shuffle, shuffles);
    for (int i = log2(shuffle_size) - 2; i >= 0; i--)
        parallel_waksman_round(0, i, false, to_shuffle, shuffles);

    // Store perm_bob at stack[output_base]
    finalize_multiple(stack, shuffles, to_shuffle, is_exact);
}

template<class T>
int SecureShuffle<T>::prep_multiple(StackedVector<T> &a,
        vector<ShuffleTuple<T>> &shuffles, vector<vector<T>> &to_shuffle,
        vector<bool> &is_exact)
{
    int max_depth = 0;
    const size_t n_shuffles = shuffles.size();

    for (size_t currentShuffle = 0; currentShuffle < n_shuffles; currentShuffle++) {
        auto& shuffle = shuffles[currentShuffle];
        const size_t input_base = shuffle.source;
        const size_t n = shuffle.size;
        const size_t unit_size = shuffle.unit_size;

        assert(n % unit_size == 0);

        const size_t n_shuffle = n / unit_size;
        const int shuffle_depth = ceil(log2(n_shuffle));
        const size_t n_shuffle_pow2 = 1u << shuffle_depth;
        const bool exact = (n_shuffle_pow2 == n_shuffle) or not T::malicious;

        vector<T> tmp;
        if (exact)
        {
            tmp.resize(n_shuffle_pow2 * unit_size);
            for (size_t i = 0; i < n; i++)
                tmp[i] = a[input_base + i];
        }
        else
        {
            // Pad n_shuffle to n_shuffle_pow2. To reduce this back to n_shuffle after-the-fact, a flag bit is
            // added to every real entry.
            const size_t shuffle_unit_size = unit_size + 1;
            tmp.resize(shuffle_unit_size * n_shuffle_pow2);
            for (size_t i = 0; i < n_shuffle; i++)
            {
                for (size_t j = 0; j < unit_size; j++)
                    tmp[i * shuffle_unit_size + j] = a[input_base + i * unit_size + j];
                tmp[(i + 1) * shuffle_unit_size - 1] = T::constant(1, proc.P.my_num(), proc.MC.get_alphai());
            }
            for (size_t i = n_shuffle * shuffle_unit_size; i < tmp.size(); i++)
                tmp[i] = T::constant(0, proc.P.my_num(), proc.MC.get_alphai());
            shuffle.unit_size = shuffle_unit_size;
        }

        to_shuffle.push_back(tmp);
        is_exact[currentShuffle] = exact;

        if (shuffle_depth > max_depth)
            max_depth = shuffle_depth;
    }

    return max_depth;
}

template<class T>
void SecureShuffle<T>::finalize_multiple(StackedVector<T> &a,
        vector<ShuffleTuple<T>> &shuffles, vector<vector<T>> &to_shuffle,
        vector<bool> &isExact)
{
    const size_t n_shuffles = shuffles.size();
    for (size_t currentShuffle = 0; currentShuffle < n_shuffles; currentShuffle++) {
        auto& shuffle = shuffles[currentShuffle];
        const size_t n = shuffle.size;
        const size_t shuffled_unit_size = shuffle.unit_size;
        const size_t output_base = shuffle.dest;

        const vector<T>& shuffledData = to_shuffle[currentShuffle];

        if (isExact[currentShuffle])
            for (size_t i = 0; i < n; i++)
                a[output_base + i] = shuffledData[i];
        else
        {
            const size_t original_unit_size = shuffled_unit_size - 1;
            const size_t n_shuffle = n / original_unit_size;
            const size_t n_shuffle_pow2 = shuffledData.size() / shuffled_unit_size;

            // Reveal the "real element" flags.
            auto& MC = proc.MC;
            MC.init_open(proc.P);
            for (size_t i = 0; i < n_shuffle_pow2; i++) {
                MC.prepare_open(shuffledData.at((i + 1) * shuffled_unit_size - 1));
            }
            MC.exchange(proc.P);

            // Filter out the real elements.
            size_t i_shuffle = 0;
            for (size_t i = 0; i < n_shuffle_pow2; i++)
            {
                auto bit = MC.finalize_open();
                if (bit == 1)
                {
                    // only output real elements
                    for (size_t j = 0; j < original_unit_size; j++)
                        a.at(output_base + i_shuffle * original_unit_size + j) =
                                shuffledData.at(i * shuffled_unit_size + j);
                    i_shuffle++;
                }
            }
            if (i_shuffle != n_shuffle)
                throw runtime_error("incorrect shuffle");
        }
    }
}

template<class T>
vector<int> SecureShuffle<T>::generate_random_permutation(int n) {
    vector<int> perm;
    int n_pow2 = 1 << int(ceil(log2(n)));
    int shuffle_size = n;
    for (int j = 0; j < n_pow2; j++)
        perm.push_back(j);
    SeededPRNG G;
    for (int i = 0; i < shuffle_size; i++) {
        int j = G.get_uint(shuffle_size - i);
        swap(perm[i], perm[i + j]);
    }

    return perm;
}

template<class T>
void SecureShuffle<T>::generate(int n_shuffle, shuffle_type& shuffle)
{
    for (auto i: proc.protocol.get_relevant_players()) {
        vector<int> perm;
        if (proc.input.is_me(i))
            perm = generate_random_permutation(n_shuffle);
        auto config = configure(i, &perm, n_shuffle);
        shuffle.push_back(config);
    }
}

template<class T>
vector<vector<T>> SecureShuffle<T>::configure(int config_player, vector<int> *perm, int n) {
    CODE_LOCATION
    auto &P = proc.P;
    auto &input = proc.input;
    input.reset_all(P);
    int n_pow2 = 1 << int(ceil(log2(n)));
    Waksman waksman(n_pow2);

    // The player specified by config_player configures the shared waksman network
    // using its personal permutation
    if (input.is_me(config_player)) {
        auto config_bits = waksman.configure(*perm);
        for (size_t i = 0; i < config_bits.size(); i++) {
            auto &x = config_bits[i];
            for (size_t j = 0; j < x.size(); j++)
                if (waksman.matters(i, j) and not waksman.is_double(i, j))
                    input.add_mine(int(x[j]));
                else if (waksman.is_double(i, j))
                    assert(x[j] == x[j - 1]);
                else
                    assert(x[j] == 0);
        }
        // The other player waits for its share of the configured waksman network
    } else
        for (size_t i = 0; i < waksman.n_bits(); i++)
            input.add_other(config_player);

    input.exchange();
    vector<vector<T>> config;
    typename T::Protocol checker(P);
    checker.init(proc.DataF, proc.MC);
    checker.init_dotprod();
    auto one = T::constant(1, P.my_num(), proc.MC.get_alphai());
    for (size_t i = 0; i < waksman.n_rounds(); i++)
    {
        config.push_back({});
        for (int j = 0; j < n_pow2; j++)
        {
            if (waksman.matters(i, j) and not waksman.is_double(i, j))
            {
                config.back().push_back(input.finalize(config_player));
                if (T::malicious)
                    checker.prepare_dotprod(config.back().back(),
                            one - config.back().back());
            }
            else if (waksman.is_double(i, j))
                config.back().push_back(config.back().back());
            else
                config.back().push_back({});
        }
    }

    if (T::malicious)
    {
        checker.next_dotprod();
        checker.exchange();
        assert(
                typename T::clear(
                        proc.MC.open(checker.finalize_dotprod(waksman.n_bits()),
                                P)) == 0);
        checker.check();
    }

    return config;
}

template<class T>
void SecureShuffle<T>::parallel_waksman_round(size_t pass, int depth,
        bool inwards, vector<vector<T>> &toShuffle,
        vector<ShuffleTuple<T>> &shuffles)
{
    const auto n_passes = proc.protocol.get_relevant_players().size();
    const auto n_shuffles = shuffles.size();

    vector<vector<array<int, 5>>> allIndices;
    proc.protocol.init_mul();

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles;
            current_shuffle++)
    {
        auto& shuffle = shuffles[current_shuffle];
        int n = toShuffle[current_shuffle].size() / shuffle.unit_size;
        if (depth >= log2(n) - !inwards) {
            allIndices.push_back({});
            continue;
        }

        const auto isReverse = shuffle.reverse;
        size_t configIdx = pass;
        if (isReverse)
            configIdx = n_passes - pass - 1;

        auto& config = shuffle.shuffle[configIdx];

        vector<array<int, 5>> indices = waksman_round_init(
            toShuffle[current_shuffle],
            shuffle.unit_size,
            depth,
            config,
            inwards,
            isReverse
        );
        allIndices.push_back(indices);
    }
    proc.protocol.exchange();
    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        auto& shuffle = shuffles[current_shuffle];
        int n = toShuffle[current_shuffle].size() / shuffle.unit_size;
        if (depth >= log2(n) - !inwards) {
            continue;
        }
        waksman_round_finish(toShuffle[current_shuffle], shuffle.unit_size, allIndices[current_shuffle]);
    }
}

template<class T>
vector<array<int, 5>> SecureShuffle<T>::waksman_round_init(vector<T> &toShuffle,
        size_t shuffle_unit_size, int depth,
        const vector<vector<T>> &iter_waksman_config, bool inwards,
        bool reverse)
{
    int n = toShuffle.size() / shuffle_unit_size;
    assert((int) iter_waksman_config.at(depth).size() == n);
    int n_blocks = 1 << depth;
    int size = n / (2 * n_blocks);
    bool outwards = !inwards;
    vector<array<int, 5>> indices;
    indices.reserve(n / 2);
    Waksman waksman(n);
    for (int k = 0; k < n / 2; k++)
    {
        int j = k % size;
        int i = k / size;
        int base = 2 * i * size;
        int in1 = base + j + j * inwards;
        int in2 = in1 + inwards + size * outwards;
        int out1 = base + j + j * outwards;
        int out2 = out1 + outwards + size * inwards;
        int i_bit = base + j + size * (outwards ^ reverse);
        bool run = waksman.matters(depth, i_bit);
        if (run)
        {
            for (size_t l = 0; l < shuffle_unit_size; l++)
                proc.protocol.prepare_mul(iter_waksman_config.at(depth).at(i_bit),
                        toShuffle.at(in1 * shuffle_unit_size + l) - toShuffle.at(in2 * shuffle_unit_size + l));
        }
        indices.push_back({in1, in2, out1, out2, run});
    }
    return indices;
}

template<class T>
void SecureShuffle<T>::waksman_round_finish(vector<T> &toShuffle, size_t unit_size, vector<array<int, 5>> indices) {
    int n = toShuffle.size() / unit_size;

    vector<T> tmp(toShuffle.size());
    for (int k = 0; k < n / 2; k++)
    {
        auto idx = indices.at(k);
        for (size_t l = 0; l < unit_size; l++)
        {
            T diff;
            if (idx[4])
                diff = proc.protocol.finalize_mul();
            tmp.at(idx[2] * unit_size + l) = toShuffle.at(
                    idx[0] * unit_size + l) - diff;
            tmp.at(idx[3] * unit_size + l) = toShuffle.at(
                    idx[1] * unit_size + l) + diff;
        }
    }

    swap(tmp, toShuffle);
}


#endif /* PROTOCOLS_SECURESHUFFLE_HPP_ */
