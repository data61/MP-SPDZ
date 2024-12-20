/*
 * Rep3Shuffler.cpp
 *
 */

#ifndef PROTOCOLS_REP3SHUFFLER_HPP_
#define PROTOCOLS_REP3SHUFFLER_HPP_

#include "Rep3Shuffler.h"

template<class T>
Rep3Shuffler<T>::Rep3Shuffler(StackedVector<T> &a, size_t n, int unit_size,
                              size_t output_base, size_t input_base, SubProcessor<T> &proc) : proc(proc) {
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
Rep3Shuffler<T>::Rep3Shuffler(SubProcessor<T> &proc) : proc(proc) {
}

template<class T>
int Rep3Shuffler<T>::generate(int n_shuffle, store_type &store) {
    int res = store.add();
    auto &shuffle = store.get(res);
    for (int i = 0; i < 2; i++) {
        auto &perm = shuffle[i];
        for (int j = 0; j < n_shuffle; j++)
            perm.push_back(j);
        for (int j = 0; j < n_shuffle; j++) {
            int k = proc.protocol.shared_prngs[i].get_uint(n_shuffle - j);
            swap(perm[j], perm[k + j]);
        }
    }
    return res;
}

template<class T>
void Rep3Shuffler<T>::apply_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &destinations,
                                    vector<size_t> &sources,
                                    vector<size_t> &unit_sizes, vector<size_t> &handles, vector<bool> &reverses,
                                    store_type &store) {
    vector<shuffle_type> shuffles;
    for (size_t &handle: handles) {
        shuffle_type &shuffle = store.get(handle);
        shuffles.push_back(shuffle);
    }

    apply_multiple(a, sizes, destinations, sources, unit_sizes, shuffles, reverses);
}

template<class T>
void Rep3Shuffler<T>::apply_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &destinations,
                                    vector<size_t> &sources, vector<size_t> &unit_sizes, vector<shuffle_type> &shuffles,
                                    vector<bool> &reverses) {
    const auto n_shuffles = sizes.size();
    assert(sources.size() == n_shuffles);
    assert(destinations.size() == n_shuffles);
    assert(unit_sizes.size() == n_shuffles);
    assert(shuffles.size() == n_shuffles);
    assert(reverses.size() == n_shuffles);

    assert(proc.P.num_players() == 3);
    assert(not T::malicious);
    assert(not T::dishonest_majority);

    // for (size_t i = 0; i < n_shuffles; i++) {
    // this->apply(a, sizes[i], unit_sizes[i], destinations[i], sources[i], store.get(handles[i]), reverses[i]);
    // }

    vector<vector<T> > to_shuffle;
    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        assert(sizes[current_shuffle] % unit_sizes[current_shuffle] == 0);
        vector<T> x;
        for (size_t j = 0; j < sizes[current_shuffle]; j++)
            x.push_back(a[sources[current_shuffle] + j]);
        to_shuffle.push_back(x);

        const auto &shuffle = shuffles[current_shuffle];
        if (shuffle.empty())
            throw runtime_error("shuffle has been deleted");

        stats[sizes[current_shuffle] / unit_sizes[current_shuffle]] += unit_sizes[current_shuffle];
    }

    typename T::Input input(proc);

    for (int pass = 0; pass < 3; pass++) {
        input.reset_all(proc.P);

        for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
            const auto n = sizes[current_shuffle];
            const auto unit_size = unit_sizes[current_shuffle];
            const auto &shuffle = shuffles[current_shuffle];
            const auto reverse = reverses[current_shuffle];
            const auto current_to_shuffle = to_shuffle[current_shuffle];

            vector<typename T::clear> to_share(n);
            int i;
            if (reverse)
                i = 2 - pass;
            else
                i = pass;

            if (proc.P.get_player(i) == 0) {
                for (size_t j = 0; j < n / unit_size; j++)
                    for (size_t k = 0; k < unit_size; k++)
                        if (reverse)
                            to_share.at(j * unit_size + k) = current_to_shuffle.at(
                                shuffle[0].at(j) * unit_size + k).sum();
                        else
                            to_share.at(shuffle[0].at(j) * unit_size + k) =
                                    current_to_shuffle.at(j * unit_size + k).sum();
            } else if (proc.P.get_player(i) == 1) {
                for (size_t j = 0; j < n / unit_size; j++)
                    for (size_t k = 0; k < unit_size; k++)
                        if (reverse)
                            to_share[j * unit_size + k] = current_to_shuffle[shuffle[1][j] * unit_size + k][0];
                        else
                            to_share[shuffle[1][j] * unit_size + k] = current_to_shuffle[j * unit_size + k][0];
            }

            if (proc.P.get_player(i) < 2)
                for (auto &x: to_share)
                    input.add_mine(x);
            for (int k = 0; k < 2; k++)
                input.add_other((-i + 3 + k) % 3);
        }

        input.exchange();
        to_shuffle.clear();

        for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
            const auto n = sizes[current_shuffle];
            const auto reverse = reverses[current_shuffle];

            int i;
            if (reverse)
                i = 2 - pass;
            else
                i = pass;

            vector<T> tmp;
            for (size_t j = 0; j < n; j++) {
                T x = input.finalize((-i + 3) % 3) + input.finalize((-i + 4) % 3);
                tmp.push_back(x);
            }
            to_shuffle.push_back(tmp);
        }
    }

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        const auto n = sizes[current_shuffle];

        for (size_t i = 0; i < n; i++)
            a[destinations[current_shuffle] + i] = to_shuffle[current_shuffle][i];
    }
}

template<class T>
void Rep3Shuffler<T>::inverse_permutation(StackedVector<T> &, size_t, size_t, size_t) {
    throw runtime_error("inverse permutation not implemented");
}

#endif
