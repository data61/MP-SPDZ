/*
 * SpdzWiseShuffler.cpp
 *
 */

#include "SpdzWiseRep3Shuffler.h"

template<class T>
SpdzWiseRep3Shuffler<T>::SpdzWiseRep3Shuffler(SubProcessor<T>& proc) :
        proc(proc), internal_set(proc.P, {}), internal(internal_set.processor)
{
}

template<class T>
void SpdzWiseRep3Shuffler<T>::generate(int n_shuffle, shuffle_type& shuffle)
{
    internal.generate(n_shuffle, shuffle);
}

template<class T>
void SpdzWiseRep3Shuffler<T>::apply_multiple(StackedVector<T> &a,
        vector<ShuffleTuple<T>>& shuffles)
{
    CODE_LOCATION
    const size_t n_shuffles = shuffles.size();

    StackedVector<typename T::part_type::Honest> temporary_memory(0);
    vector<ShuffleTuple<typename T::part_type::Honest>> mapped_shuffles;

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles;
            current_shuffle++)
    {
        auto& shuffle = shuffles[current_shuffle];
        mapped_shuffles.push_back({2 * shuffle.size, temporary_memory.size(),
            temporary_memory.size(), 2 * shuffle.unit_size, shuffle.shuffle, shuffle.reverse});

        stats[shuffle.size / shuffle.unit_size] += shuffle.unit_size;

        for (size_t i = 0; i < shuffle.size; i++)
        {
            auto& x = a[shuffle.source + i];
            temporary_memory.push_back(x.get_share());
            temporary_memory.push_back(x.get_mac());
        }
    }

    internal.apply_multiple(temporary_memory, mapped_shuffles);

    for (size_t current_shuffle = 0; current_shuffle < n_shuffles; current_shuffle++)
    {
        auto& shuffle = shuffles[current_shuffle];
        const size_t n = shuffle.size;
        const size_t dest = shuffle.dest;
        const size_t pos = mapped_shuffles[current_shuffle].dest;
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
