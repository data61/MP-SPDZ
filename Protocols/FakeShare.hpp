/*
 * FakeShare.cpp
 *
 */

#include "FakeShare.h"
#include "Math/Z2k.h"
#include "GC/square64.h"

template<class T>
false_type FakeShare<T>::is_clear;

template<class T>
void FakeShare<T>::split(StackedVector<bit_type>& dest,
        const ArgVector& regs, int n_bits, const This* source, int n_inputs,
        GC::FakeSecret::Protocol&)
{
    assert(n_bits <= 64);
    int unit = GC::Clear::N_BITS;
    for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
    {
        int start = k * unit;
        int m = min(unit, n_inputs - start);

        int n_split = regs.size() / n_bits;
        for (int i = 0; i < n_bits; i++)
            for (int j = 1; j < n_split; j++)
                dest.at(regs.at(n_split * i + j) + k) = {};

        square64 square;

        for (int j = 0; j < m; j++)
        {
            square.rows[j] = (source[j + start]).get_limb(0);
        }

        square.transpose(m, n_bits);

        for (int j = 0; j < n_bits; j++)
        {
            auto& dest_reg = dest.at(regs.at(n_split * j) + k);
            dest_reg = square.rows[j];
        }
    }
}
