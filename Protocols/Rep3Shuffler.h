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

    Rep3Shuffler(SubProcessor<T>& proc);

    void generate(int n_shuffle, shuffle_type& shuffle);

    void apply_multiple(StackedVector<T>& a, vector<ShuffleTuple<T>> &shuffles);

    void inverse_permutation(StackedVector<T>& stack, size_t n, size_t output_base,
            size_t input_base);
};

#endif /* PROTOCOLS_REP3SHUFFLER_H_ */
