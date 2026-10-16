/*
 * F3.cpp
 *
 */

#include "F3.h"
#include "SemiSecureShuffle.h"

thread_local vector<array<F3, 5>> F3Vector::randomness_table;
thread_local vector<array<word, 2>> F3VectorBitWise::randomness_table;

void F3Vector::build_randomness_table()
{
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            for (int k = 0; k < 3; k++)
                for (int l = 0; l < 3; l++)
                    for (int m = 0; m < 3; m++)
                        randomness_table.push_back(
                                {F3(i), F3(j), F3(k), F3(l), F3(m)});
}

GC::RowMatrix<F3VectorBitWise> F3VectorBitWise::transpose(
        const GC::RowMatrix<F3VectorBitWise>& matrix)
{
    GC::RowMatrix<F3VectorBitWise> res(matrix.n_cols(), matrix.col(0).size());
    assert(res.n_cols() == matrix.col(0).size());
    assert(matrix.n_cols() == res.col(0).size());
    auto& tmp = matrix;
    size_t n = matrix.n_cols();
    size_t m = res.n_cols();
    for (size_t i = 0; i < n; i += 128)
        for (size_t j = 0; j < m; j += 128)
            for (int k = 0; k < 2; k++)
            {
                square128 square;
                square.set_zero();
                for (int ii = 0; ii < min(128, int(n - i)); ii++)
                    square.rows[ii] = tmp.col(i + ii).bits[k].get_int128(j / 128).a;
                square.transpose();
                for (int ii = 0; ii < min(128, int(m - j)); ii++)
                    res.col(j + ii).bits[k].set_int128(i / 128, square.rows[ii]);
            }
#ifdef AVOID_UNSET_MEMORY
    for (size_t j = 0; j < res.n_cols(); j++)
        for (int k = 0; k < 2; k++)
        {
            auto col = res.col(j);
            auto rounded_size = multiple_minimum(col.size(), 8);
            res.col(j).bits[k].part(rounded_size,
                    col.storage_size() - rounded_size).assign_zero();
        }
#endif
    return res;
}

void F3VectorBitWise::build_randomness_table()
{
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            for (int k = 0; k < 3; k++)
                for (int l = 0; l < 3; l++)
                    for (int m = 0; m < 3; m++)
                    {
                        F3VectorBitWise tmp(F3Vector({i, j, k, l, m}));
                        randomness_table.push_back({});
                        for (int k = 0; k < 2; k++)
                            randomness_table.back()[k] =
                                    tmp.bits[k].get_word(0) & 0x1f;
                    }
}

void F3VectorBitWise::randomize(PRNG& G)
{
    assert(storage_size() % 64 == 0);
    auto& table = randomness_table;
    if (randomness_table.empty())
        build_randomness_table();

    for (long i = 0; i < DIV_CEIL(size(), 64); i++)
    {
        array<word, 2> blocks({0, 0});

        for (int j = 0; j < 64; j += 5)
        {
            octet r = 243;
            while (r >= 243)
                r = G.get_uchar();
            auto part = table[r];

            for (int k = 0; k < 2; k++)
                blocks[k] ^= part[k] << j;
        }

        for (int k = 0; k < 2; k++)
            bits[k].set_word(i, blocks[k]);
    }
}
