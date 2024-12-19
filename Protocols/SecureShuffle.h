/*
 * SecureShuffle.h
 *
 */

#ifndef PROTOCOLS_SECURESHUFFLE_H_
#define PROTOCOLS_SECURESHUFFLE_H_

#include <vector>
using namespace std;

#include "Tools/Lock.h"

template<class T> class SubProcessor;

template<class T>
class ShuffleStore
{
    typedef T shuffle_type;

    deque<shuffle_type> shuffles;

    Lock store_lock;

    void lock();
    void unlock();

public:
    int add();
    shuffle_type& get(int handle);
    void del(int handle);
};

template<class T>
class SecureShuffle
{
public:
    typedef vector<vector<vector<T>>> shuffle_type;
    typedef ShuffleStore<shuffle_type> store_type;

private:
    SubProcessor<T>& proc;

    /**
     * Generates and returns a newly generated random permutation. This permutation is generated locally.
     *
     * @param n The size of the permutation to generate.
     * @return A vector representing a permutation, a shuffled array of integers 0 through n-1.
     */
    vector<int> generate_random_permutation(int n);

    /**
     * Configure a shared waksman network from a permutation known only to config_player.
     * Note that although the configuration bits of the waksman network are secret shared,
     * the player that generated the permutation (config_player) knows the value of these bits.
     *
     * A permutation is a mapping represented as a vector.
     * Each item in the vector represents the output of mapping(i) where i is the index of that item.
     *      e.g. [2, 4, 0, 3, 1] -> perm(1) = 4
     *
     * @param config_player The player tasked with generating the random permutation from which to configure the waksman network.
     * @param n The size of the permutation to generate.
     */
    vector<vector<T>> configure(int config_player, vector<int>* perm, int n);

    int prep_multiple(StackedVector<T>& a, vector<size_t> &sizes, vector<size_t> &sources, vector<size_t> &unit_sizes, vector<vector<T>>& to_shuffle, vector<bool> &exact);
    void finalize_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& unit_sizes, vector<size_t>& destinations, vector<bool>& isExact, vector<vector<T>>& to_shuffle);

    void parallel_waksman_round(size_t pass, int depth, bool inwards, vector<vector<T>>& toShuffle, vector<size_t>& unit_sizes, vector<bool>& reverse, vector<shuffle_type>& shuffles);
    vector<array<int, 5>> waksman_round_init(vector<T>& toShuffle, size_t shuffle_unit_size, int depth, vector<vector<T>>& iter_waksman_config, bool inwards, bool reverse);
    void waksman_round_finish(vector<T>& toShuffle, size_t unit_size, vector<array<int, 5>> indices);

public:
    map<long, long> stats;

    SecureShuffle(StackedVector<T>& a, size_t n, int unit_size,
            size_t output_base, size_t input_base, SubProcessor<T>& proc);

    SecureShuffle(SubProcessor<T>& proc);

    int generate(int n_shuffle, store_type& store);

    void apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                       vector<size_t>& unit_sizes, vector<size_t>& handles, vector<bool>& reverse, store_type& store);
    void apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                       vector<size_t>& unit_sizes, vector<shuffle_type>& shuffles, vector<bool>& reverse);

    /**
     * Calculate the secret inverse permutation of stack given secret permutation.
     *
     * This method is given in [1], based on stack technique in [2]. It is used in the Compiler (high-level) implementation of Square-Root ORAM.
     *
     * [1] Samee Zahur, Xiao Wang, Mariana Raykova, Adrià Gascón, Jack Doerner, David Evans, and Jonathan Katz. 2016. Revisiting Square Root ORAM: Efficient Random Access in Multi-Party Computation. In IEEE S&P.
     * [2] Ivan Damgård, Matthias Fitzi, Eike Kiltz, Jesper Buus Nielsen, and Tomas Toft. Unconditionally Secure Constant-rounds Multi-Party Computation for Equality, Comparison, Bits and Exponentiation. In Theory of Cryptography, 2006.
     *
     * @param stack The vector or registers representing the stack (?)
     * @param n The size of the input vector for which to calculate the inverse permutation
     * @param output_base The starting address of the output vector (i.e. the location to write the inverted permutation to)
     * @param input_base The starting address of the input vector (i.e. the location from which to read the permutation)
     */
    void inverse_permutation(StackedVector<T>& stack, size_t n, size_t output_base, size_t input_base);
};

#endif /* PROTOCOLS_SECURESHUFFLE_H_ */
