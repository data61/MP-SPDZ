/*
 * F3Code.h
 *
 */

#ifndef GC_F3CODE_H_
#define GC_F3CODE_H_

#include "F3.h"

namespace GC
{
template<class T> class RowMatrix;
}

class F3Code
{
    vector<vector<int>> permutations;
    size_t out_size;

    static size_t n_permutations(size_t out_size);

public:
    F3Code() : out_size(0)
    {
    }

    F3Code(size_t key_size, size_t out_size, PRNG& G);

    bool empty()
    {
        return not out_size;
    }

    GC::RowMatrix<F3VectorBitWise> apply(
            const GC::RowMatrix<F3VectorBitWise>& x);

    F3VectorBitWise apply(const F3VectorBitWise& x);
};

#endif /* GC_F3CODE_H_ */
