/*
 * SecureShuffle.hpp
 *
 */

#ifndef PROTOCOLS_SECURESHUFFLE_HPP_
#define PROTOCOLS_SECURESHUFFLE_HPP_

#include "SecureShuffle.h"
#include "Tools/Waksman.h"

#include <math.h>
#include <algorithm>

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
int ShuffleStore<T>::add()
{
    lock();
    int res = shuffles.size();
    shuffles.push_back({});
    unlock();
    return res;
}

template<class T>
typename ShuffleStore<T>::shuffle_type& ShuffleStore<T>::get(int handle)
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
SecureShuffle<T>::SecureShuffle(StackedVector<T>& a, size_t n, int unit_size,
        size_t output_base, size_t input_base, SubProcessor<T>& proc) :
        proc(proc)
{
    store_type store;
    int handle = generate(n / unit_size, store);

    vector<size_t> sizes{n};
    vector<size_t> unit_sizes{static_cast<size_t>(unit_size)};
    vector<size_t> destinations{output_base};
    vector<size_t> sources{input_base};
    vector<shuffle_type> shuffles{store.get(handle)};
    vector<bool> reverses{true};
    this->apply_multiple(a, sizes, destinations, sources, unit_sizes, shuffles, reverses);
}

template<class T>
void SecureShuffle<T>::apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                                    vector<size_t>& unit_sizes, vector<size_t>& handles, vector<bool>& reverse, store_type& store) {
    vector<shuffle_type> shuffles;
    for (size_t &handle : handles)
        shuffles.push_back(store.get(handle));

    this->apply_multiple(a, sizes, destinations, sources, unit_sizes, shuffles, reverse);
}

template<class T>
void SecureShuffle<T>::apply_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &destinations,
    vector<size_t> &sources, vector<size_t> &unit_sizes, vector<shuffle_type> &shuffles, vector<bool> &reverse) {
    const auto n_shuffles = sizes.size();
    assert(sources.size() == n_shuffles);
    assert(destinations.size() == n_shuffles);
    assert(unit_sizes.size() == n_shuffles);
    assert(shuffles.size() == n_shuffles);
    assert(reverse.size() == n_shuffles);

    // SecureShuffle works by making t players create and "secret-share" a permutation.
    // Then each permutation is applied in a pass. As long as one of these permutations was created by an honest party,
    // the resulting combined shuffle is hidden.
    const auto n_passes = proc.protocol.get_relevant_players().size();

    // Initialize the shuffles.
    vector is_exact(n_shuffles, false);
    vector<vector<T>> to_shuffle;
    int max_depth = prep_multiple(a, sizes, sources, unit_sizes, to_shuffle, is_exact);

    // Apply the shuffles.
    for (size_t pass = 0; pass < n_passes; pass++)
    {
        for (int depth = 0; depth < max_depth; depth++)
            parallel_waksman_round(pass, depth, true, to_shuffle, unit_sizes, reverse, shuffles);
        for (int depth = max_depth - 1; depth >= 0; depth--)
            parallel_waksman_round(pass, depth, false, to_shuffle, unit_sizes, reverse, shuffles);
    }

    // Write the shuffled results into memory.
    finalize_multiple(a, sizes, unit_sizes, destinations, is_exact, to_shuffle);
}


template<class T>
void SecureShuffle<T>::inverse_permutation(StackedVector<T> &stack, size_t n, size_t output_base,
                                           size_t input_base) {
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

    vector<size_t> sizes { n };
    vector<size_t> unit_sizes { 1 }; // We are dealing directly with permutations, so the unit_size will always be 1.
    vector<size_t> destinations { output_base };
    vector<size_t> sources { input_base };
    vector<bool> reverse { true };
    vector<vector<T>> to_shuffle;
    vector<bool> is_exact(1, false);

    prep_multiple(stack, sizes, sources, unit_sizes, to_shuffle, is_exact);

    size_t shuffle_size = to_shuffle[0].size() / unit_sizes[0];
    // Alice generates stack local permutation and shares the waksman configuration bits secretly to Bob.
    vector<int> perm_alice(shuffle_size);
    if (P.my_num() == alice) {
        perm_alice = generate_random_permutation(n);
    }
    auto config = configure(alice, &perm_alice, n);
    vector<shuffle_type> shuffles {{ config, config }};

    // Apply perm_alice to perm_alice to get perm_bob,
    // stack permutation that we can reveal to Bob without Bob learning anything about perm_alice (since it is masked by perm_a)
    for (int depth = 0; depth < log2(shuffle_size); depth++)
        parallel_waksman_round(0, depth, true, to_shuffle, unit_sizes, reverse, shuffles);
    for (int depth = log2(shuffle_size); depth >= 0; depth--)
        parallel_waksman_round(0, depth, false, to_shuffle, unit_sizes, reverse, shuffles);

    // Store perm_bob at stack[output_base]
    finalize_multiple(stack, sizes, unit_sizes, destinations, is_exact, to_shuffle);

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
    prep_multiple(stack, sizes, destinations, unit_sizes, to_shuffle, is_exact);

    config = configure(bob, &perm_bob_inv, n);
    shuffles[0] = { config, config };

    for (int i = 0; i < log2(shuffle_size); i++)
        parallel_waksman_round(0, i, true, to_shuffle, unit_sizes, reverse, shuffles);
    for (int i = log2(shuffle_size) - 2; i >= 0; i--)
        parallel_waksman_round(0, i, false, to_shuffle, unit_sizes, reverse, shuffles);

    // Store perm_bob at stack[output_base]
    finalize_multiple(stack, sizes, unit_sizes, destinations, is_exact, to_shuffle);
}

template<class T>
int SecureShuffle<T>::prep_multiple(StackedVector<T> &a, vector<size_t> &sizes,
    vector<size_t> &sources, vector<size_t> &unit_sizes, vector<vector<T>> &to_shuffle, vector<bool> &is_exact) {
    int max_depth = 0;
    const size_t n_shuffles = sizes.size();

    for (size_t currentShuffle = 0; currentShuffle < n_shuffles; currentShuffle++) {
        const size_t input_base = sources[currentShuffle];
        const size_t n = sizes[currentShuffle];
        const size_t unit_size = unit_sizes[currentShuffle];

        assert(n % unit_size == 0);

        const size_t n_shuffle = n / unit_size;
        const size_t n_shuffle_pow2 = (1u << int(ceil(log2(n_shuffle))));
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
            unit_sizes[currentShuffle] = shuffle_unit_size;
        }

        to_shuffle.push_back(tmp);
        is_exact[currentShuffle] = exact;

        const int shuffle_depth = tmp.size() / unit_size;
        if (shuffle_depth > max_depth)
            max_depth = shuffle_depth;
    }

    return max_depth;
}

template<class T>
void SecureShuffle<T>::finalize_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &unit_sizes,
    vector<size_t> &destinations, vector<bool> &isExact, vector<vector<T>> &to_shuffle) {
    const size_t n_shuffles = sizes.size();
    for (size_t currentShuffle = 0; currentShuffle < n_shuffles; currentShuffle++) {
        const size_t n = sizes[currentShuffle];
        const size_t shuffled_unit_size = unit_sizes[currentShuffle];
        const size_t output_base = destinations[currentShuffle];

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
int SecureShuffle<T>::generate(int n_shuffle, store_type& store)
{
    int res = store.add();
    auto& shuffle = store.get(res);

    for (auto i: proc.protocol.get_relevant_players()) {
        vector<int> perm;
        if (proc.P.my_num() == i)
            perm = generate_random_permutation(n_shuffle);
        auto config = configure(i, &perm, n_shuffle);
        shuffle.push_back(config);
    }

    return res;
}

template<class T>
vector<vector<T>> SecureShuffle<T>::configure(int config_player, vector<int> *perm, int n) {
    auto &P = proc.P;
    auto &input = proc.input;
    input.reset_all(P);
    int n_pow2 = 1 << int(ceil(log2(n)));
    Waksman waksman(n_pow2);

    // The player specified by config_player configures the shared waksman network
    // using its personal permutation
    if (P.my_num() == config_player) {
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
void SecureShuffle<T>::parallel_waksman_round(size_t pass, int depth, bool inwards, vector<vector<T>> &toShuffle,
    vector<size_t> &unit_sizes, vector<bool> &reverse, vector<shuffle_type> &shuffles)
{
    const auto n_passes = proc.protocol.get_relevant_players().size();
    const auto n_shuffles = shuffles.size();

    vector<vector<array<int, 5>>> allIndices;
    proc.protocol.init_mul();

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        int n = toShuffle[current_shuffle].size() / unit_sizes[current_shuffle];
        if (depth >= log2(n) - !inwards) {
            allIndices.push_back({});
            continue;
        }

        const auto isReverse = reverse[current_shuffle];
        size_t configIdx = pass;
        if (isReverse)
            configIdx = n_passes - pass - 1;

        auto& config = shuffles[current_shuffle][configIdx];

        vector<array<int, 5>> indices = waksman_round_init(
            toShuffle[current_shuffle],
            unit_sizes[current_shuffle],
            depth,
            config,
            inwards,
            isReverse
        );
        allIndices.push_back(indices);
    }
    proc.protocol.exchange();
    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        int n = toShuffle[current_shuffle].size() / unit_sizes[current_shuffle];
        if (depth >= log2(n) - !inwards) {
            continue;
        }
        waksman_round_finish(toShuffle[current_shuffle], unit_sizes[current_shuffle], allIndices[current_shuffle]);
    }
}

template<class T>
vector<array<int, 5>> SecureShuffle<T>::waksman_round_init(vector<T> &toShuffle, size_t shuffle_unit_size, int depth, vector<vector<T>> &iter_waksman_config, bool inwards, bool reverse) {
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
