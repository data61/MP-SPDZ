/*
 * Rep3Shuffler.h
 *
 */

#ifndef PROTOCOLS_REP3SHUFFLER_H_
#define PROTOCOLS_REP3SHUFFLER_H_

#include "SecureShuffle.h"

template<class T>
class Rep3Shuffler
{
public:
    typedef array<vector<int>, 2> shuffle_type;
    typedef ShuffleStore<shuffle_type> store_type;

private:
    SubProcessor<T>& proc;

public:
    map<long, long> stats;

    Rep3Shuffler(StackedVector<T>& a, size_t n, int unit_size, size_t output_base,
            size_t input_base, SubProcessor<T>& proc);

    Rep3Shuffler(SubProcessor<T>& proc);

    int generate(int n_shuffle, store_type& store);

    void apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                       vector<size_t>& unit_sizes, vector<size_t>& handles, vector<bool>& reverse, store_type& store);
    void apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                       vector<size_t>& unit_sizes, vector<shuffle_type>& shuffles, vector<bool>& reverse);

    void inverse_permutation(StackedVector<T>& stack, size_t n, size_t output_base,
            size_t input_base);
};

#endif /* PROTOCOLS_REP3SHUFFLER_H_ */
