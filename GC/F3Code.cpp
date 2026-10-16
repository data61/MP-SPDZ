/*
 * F3Code.cpp
 *
 */

#include "F3Code.h"
#include "SemiSecureShuffle.h"

#include <math.h>

size_t F3Code::n_permutations(size_t out_size)
{
    return max<int>(7, ceil(log2(out_size)));
}

F3Code::F3Code(size_t key_size, size_t out_size, PRNG& G) :
        out_size(out_size)
{
    assert(key_size >= out_size);
    permutations.resize(n_permutations(out_size));
    for (auto& perm : permutations)
        G.random_permutation(key_size, perm);
}

GC::RowMatrix<F3VectorBitWise> F3Code::apply(
        const GC::RowMatrix<F3VectorBitWise>& x)
{
    auto tmp = x;
    assert(x.n_cols() == permutations.at(0).size());

    for (size_t i = 1; i < tmp.n_cols(); i++)
        tmp.col(i) += tmp.col(i - 1);

    for (size_t i = 0; i < permutations.size() - 1; i++)
    {
        for (size_t j = 1; j < tmp.n_cols(); j++)
            tmp.col(permutations.at(i).at(j)) += tmp.col(
                    permutations.at(i).at(j - 1));
    }

    GC::RowMatrix<F3VectorBitWise> res(x.n_rows(), out_size);
    for (size_t i = 0; i < out_size; i++)
    {
        res.col(i).assign(tmp.col(permutations.back().at(i)));
    }

    return res;
}

F3VectorBitWise F3Code::apply(const F3VectorBitWise& x)
{
    assert(x.size() == permutations.at(0).size());
    GC::RowMatrix<F3VectorBitWise> code_input(x.size(), 1);
    code_input.set_col(0, x);
    auto code_output = apply(code_input.transpose());
    F3VectorBitWise res = code_output.transpose().col(0);
    assert(res.size());
    if (OnlineOptions::singleton.has_option("code_outputs"))
        cout << "code output " << res << endl;
    return res;
}
