/*
 * Rep3Shuffler.cpp
 *
 */

#ifndef PROTOCOLS_REP3SHUFFLER_HPP_
#define PROTOCOLS_REP3SHUFFLER_HPP_

#include "Rep3Shuffler.h"

template<class T>
Rep3Shuffler<T>::Rep3Shuffler(SubProcessor<T> &proc) : proc(proc) {
}

template<class T>
void Rep3Shuffler<T>::generate(int n_shuffle, shuffle_type& shuffle)
{
    for (int i = 0; i < 2; i++) {
        auto &perm = shuffle[i];
        perm.reserve(n_shuffle);
        for (int j = 0; j < n_shuffle; j++)
            perm.push_back(j);
        auto& G = proc.protocol.shared_prngs[i];
        for (int j = 0; j < n_shuffle; j++)
        {
            int k = G.get_uint_lemire(n_shuffle - j);
            swap(perm[j], perm[k + j]);
        }
    }
}

template<class T>
void Rep3Shuffler<T>::apply_multiple(StackedVector<T> &a,
        vector<ShuffleTuple<T>> &shuffles, bool multithread)
{
    CODE_LOCATION

    const auto n_shuffles = shuffles.size();

    assert(proc.P.num_players() == 3);
    assert(not T::malicious);
    assert(not T::dishonest_majority);

    // for (size_t i = 0; i < n_shuffles; i++) {
    // this->apply(a, sizes[i], unit_sizes[i], destinations[i], sources[i], store.get(handles[i]), reverses[i]);
    // }

    to_shuffle.resize(n_shuffles);
    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        auto& shuffle = shuffles[current_shuffle];
        assert(shuffle.size % shuffle.unit_size == 0);
        to_shuffle[current_shuffle].assign(a.begin() + shuffle.source,
                a.begin() + shuffle.source + shuffle.size);

        if (shuffle.shuffle[0].empty())
            throw runtime_error("shuffle has been deleted");

        stats[shuffle.size / shuffle.unit_size] += shuffle.unit_size;
    }

    assert(not shuffles.empty());
    long global_shuffle_size = shuffles[0].size / shuffles[0].unit_size;
    for (auto& shuffle : shuffles)
        if (shuffle.size != shuffles[0].size
                or shuffle.unit_size != shuffles[0].unit_size)
        {
            global_shuffle_size = -1;
            break;
        }

    auto queues = BaseMachine::maybe_get_queues();
    if (queues and global_shuffle_size > 0 and multithread)
    {
        to_share.resize(shuffles[0].size);
        ShuffleJob job(this, a, shuffles);
        long start = queues->distribute_with_sync(job, global_shuffle_size);
        if (start != global_shuffle_size)
            shuffle_job(a, shuffles, start, global_shuffle_size, proc.P,
                    queues);
        queues->wrap_up(job);
    }
    else
        shuffle_job(a, shuffles, -1, -1, proc.P, 0);
}

template<class T>
void Rep3Shuffler<T>::shuffle_job(StackedVector<T>& a,
        const vector<ShuffleTuple<T> >& shuffles, long begin, long end,
        Player& P, ThreadQueues* queues)
{
    const auto n_shuffles = shuffles.size();

    typename T::Input input(P);

    for (int pass = 0; pass < 3; pass++) {
        input.reset_all(P);

        for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
            auto& shuffle_tuple = shuffles[current_shuffle];
            const size_t unit_size = shuffle_tuple.unit_size;
            const auto reverse = shuffle_tuple.reverse;
            auto& shuffle = shuffle_tuple.shuffle;
            const auto& current_to_shuffle = to_shuffle[current_shuffle];

            int i;
            if (reverse)
                i = 2 - pass;
            else
                i = pass;

            auto my_begin = shuffle_tuple.begin(begin);
            auto my_end = shuffle_tuple.end(end);

            if (begin < 0)
                to_share.resize(shuffle_tuple.size);

            if (P.get_player(i) == 0) {
                for (size_t j = my_begin; j < my_end; j++)
                    for (size_t k = 0; k < unit_size; k++)
                        if (reverse)
                            to_share.at(j * unit_size + k) = current_to_shuffle.at(
                                shuffle[0].at(j) * unit_size + k).sum();
                        else
                            to_share.at(shuffle[0].at(j) * unit_size + k) =
                                    current_to_shuffle.at(j * unit_size + k).sum();
            } else if (P.get_player(i) == 1) {
                for (size_t j = my_begin; j < my_end; j++)
                    for (size_t k = 0; k < unit_size; k++)
                        if (reverse)
                            to_share[j * unit_size + k] = current_to_shuffle[shuffle[1][j] * unit_size + k][0];
                        else
                            to_share[shuffle[1][j] * unit_size + k] = current_to_shuffle[j * unit_size + k][0];
            }

            if (queues)
                queues->sync();

            if (P.get_player(i) < 2)
            {
                auto& tmp = to_shuffle[current_shuffle];
                auto begin = my_begin * unit_size;
                auto end = my_end * unit_size;
                input.add_mine({tmp.begin() + begin, tmp.begin() + end},
                        {to_share.begin() + begin, to_share.begin() + end});
                }

            for (int k = 0; k < 2; k++)
                input.add_other((-i + 3 + k) % 3);

            if (queues)
                queues->sync();
        }

        input.exchange();

        for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
            auto& shuffle = shuffles[current_shuffle];
            const auto n = shuffle.size;
            const auto reverse = shuffle.reverse;

            int i;
            if (reverse)
                i = 2 - pass;
            else
                i = pass;

            auto& tmp = to_shuffle[current_shuffle];
            assert(tmp.size() == n);
            input.finalize_vector_sum(vector<int>(
                    { (-i + 3) % 3, (-i + 4) % 3 }), {tmp.begin() +
                    shuffle.begin(begin) * shuffle.unit_size,
                    tmp.begin() + shuffle.end(end) * shuffle.unit_size});
        }

        if (queues)
            queues->sync();
    }

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        assert(to_shuffle[current_shuffle].size() == shuffles[current_shuffle].size);
        auto& shuffle = shuffles[current_shuffle];
        auto unit_size = shuffle.unit_size;
        auto my_begin = shuffle.begin(begin) * unit_size;
        copy(to_shuffle[current_shuffle].begin() + my_begin,
                to_shuffle[current_shuffle].begin() + shuffle.end(end) * unit_size,
                a.begin() + shuffles[current_shuffle].dest + my_begin);
    }

    if (queues)
        queues->sync();
}

#endif
