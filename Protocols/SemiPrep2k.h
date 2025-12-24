/*
 * SemiPrep2k.h
 *
 */

#ifndef PROTOCOLS_SEMIPREP2K_H_
#define PROTOCOLS_SEMIPREP2K_H_

#include "SemiPrep.h"
#include "RepRingOnlyEdabitPrep.h"

/**
 * Preprocessing for additive secret sharing modulo a power of two
 */
template<class T>
class SemiPrep2k : public SemiPrep<T>, public RepRingOnlyEdabitPrep<T>
{
    void buffer_edabits(int n_bits, ThreadQueues* queues)
    {
        RepRingOnlyEdabitPrep<T>::buffer_edabits(n_bits, queues);
    }

    void buffer_edabits(bool strict, int n_bits, ThreadQueues* queues)
    {
        BufferPrep<T>::buffer_edabits(strict, n_bits, queues);
    }

    void buffer_sedabits(int n_bits, ThreadQueues*)
    {
        this->buffer_sedabits_from_edabits(n_bits);
    }

public:
    static void edabit_sacrifice_buckets(vector<edabit<T>>&, size_t, bool, int,
            SubProcessor<T>&, int, int, const void* = 0)
    {
        throw runtime_error("no need for sacrifice");
    }

    static bool dabits_from_bits()
    {
        return not SemiPrep<T>::bits_from_dabits();
    }

    SemiPrep2k(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            OTPrep<T>(proc, usage),
            RingPrep<T>(proc, usage),
            SemiHonestRingPrep<T>(proc, usage),
            SemiPrep<T>(proc, usage),
            RepRingOnlyEdabitPrep<T>(proc, usage)
    {
    }

    void get_dabit_no_count(T& a, typename T::bit_type& b)
    {
        if (this->bits_from_dabits())
        {
            SemiPrep<T>::get_dabit_no_count(a, b);
            return;
        }

        this->get_one_no_count(DATA_BIT, a);
        b = a & 1;
    }
};

#endif /* PROTOCOLS_SEMIPREP2K_H_ */
