/*
 * SpdzWiseShuffler.cpp
 *
 */

#include "SpdzWiseRep3Shuffler.h"

template<class T>
SpdzWiseRep3Shuffler<T>::SpdzWiseRep3Shuffler(StackedVector<T>& a, size_t n,
        int unit_size, size_t output_base, size_t input_base,
        SubProcessor<T>& proc) :
        SpdzWiseRep3Shuffler(proc)
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
SpdzWiseRep3Shuffler<T>::SpdzWiseRep3Shuffler(SubProcessor<T>& proc) :
        proc(proc), internal_set(proc.P, {}), internal(internal_set.processor)
{
}

template<class T>
int SpdzWiseRep3Shuffler<T>::generate(int n_shuffle, store_type& store)
{
    return internal.generate(n_shuffle, store);
}

template<class T>
void SpdzWiseRep3Shuffler<T>::apply_multiple(StackedVector<T>& a, vector<size_t>& sizes, vector<size_t>& destinations, vector<size_t>& sources,
                                    vector<size_t>& unit_sizes, vector<size_t>& handles, vector<bool>& reverses, store_type& store) {
    vector<shuffle_type> shuffles;
    for (size_t &handle : handles) {
        shuffle_type& shuffle = store.get(handle);
        shuffles.push_back(shuffle);
    }

    apply_multiple(a, sizes, destinations, sources, unit_sizes, shuffles, reverses);
}


template<class T>
void SpdzWiseRep3Shuffler<T>::apply_multiple(StackedVector<T> &a, vector<size_t> &sizes, vector<size_t> &destinations,
    vector<size_t> &sources, vector<size_t> &unit_sizes, vector<shuffle_type> &shuffles, vector<bool> &reverse) {

    const size_t n_shuffles = sizes.size();
    assert(n_shuffles == destinations.size());
    assert(n_shuffles == sources.size());
    assert(n_shuffles == unit_sizes.size());
    assert(n_shuffles == shuffles.size());
    assert(n_shuffles == reverse.size());

    StackedVector<typename T::part_type::Honest> temporary_memory(0);
    vector<size_t> mapped_positions (n_shuffles, 0);
    vector<size_t> mapped_sizes(n_shuffles, 0);
    vector<size_t> mapped_unit_sizes (n_shuffles, 0);

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++) {
        mapped_positions[current_shuffle] = temporary_memory.size();

        mapped_sizes[current_shuffle] = 2 * sizes[current_shuffle];
        mapped_unit_sizes[current_shuffle] = 2 * unit_sizes[current_shuffle];
        stats[sizes[current_shuffle] / unit_sizes[current_shuffle]] += unit_sizes[current_shuffle];

        for (size_t i = 0; i < sizes[current_shuffle]; i++)
        {
            auto& x = a[sources[current_shuffle] + i];
            temporary_memory.push_back(x.get_share());
            temporary_memory.push_back(x.get_mac());
        }
    }

    internal.apply_multiple(temporary_memory, mapped_sizes, mapped_positions, mapped_positions, mapped_unit_sizes, shuffles, reverse);

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++)
    {
        const size_t n = sizes[current_shuffle];
        const size_t dest = destinations[current_shuffle];
        const size_t pos = mapped_positions[current_shuffle];
        for (size_t i = 0; i < n; i++)
        {
            auto& x = a[dest + i];
            x.set_share(temporary_memory[pos + 2 * i]);
            x.set_mac(temporary_memory[pos + 2 * i + 1]);
            proc.protocol.add_to_check(x);
        }
    }

    proc.protocol.maybe_check();
}

template<class T>
void SpdzWiseRep3Shuffler<T>::inverse_permutation(StackedVector<T>&, size_t, size_t,
        size_t)
{
    throw not_implemented();
}
