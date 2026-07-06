/*
 * Rep3Shuffler.h
 *
 */

#ifndef PROTOCOLS_REP3SHUFFLER_H_
#define PROTOCOLS_REP3SHUFFLER_H_

#include "SecureShuffle.h"

template<class T>
class Rep3Shuffler : public SecureShuffleBase<T>
{
public:
    typedef array<CheckVector<int>, 2> shuffle_type;
    typedef ShuffleStore<shuffle_type> store_type;

private:
    SubProcessor<T>& proc;

    CheckVector<CheckVector<T>> to_shuffle;
    CheckVector<typename T::clear> to_share;

public:
    map<long, long> stats;

    Rep3Shuffler(SubProcessor<T>& proc);

    void generate(int n_shuffle, shuffle_type& shuffle);

    void apply_multiple(StackedVector<T>& a, vector<ShuffleTuple<T>> &shuffles,
            bool multithread = true);

    void shuffle_job(StackedVector<T>& a, const vector<ShuffleTuple<T>>& shuffles,
            long begin, long end, Player& P, ThreadQueues* queues);
};

#endif /* PROTOCOLS_REP3SHUFFLER_H_ */
