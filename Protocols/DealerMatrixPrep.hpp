/*
 * DealerMatrixPrep.hpp
 *
 */

#include "DealerMatrixPrep.h"

template<class T>
DealerMatrixPrep<T>::DealerMatrixPrep(int n_rows, int n_inner, int n_cols,
        typename T::LivePrep& prep, DataPositions& usage) :
        super(usage), n_rows(n_rows), n_inner(n_inner), n_cols(n_cols),
        prep(&prep)
{
    assert(prep.proc);
    this->P = &prep.proc->P;
}

template<class T>
void append(vector<T>& values, ValueMatrix<T>& M)
{
    values.insert(values.end(), M.entries.begin(), M.entries.end());
}

template<class T>
ShareMatrix<T> receive(DealerInput<T>& input, int n, int m, bool random)
{
    ShareMatrix<T> res(n, m);
    if (random)
        for (size_t i = 0; i < res.entries.size(); i++)
            res.entries.v.push_back(input.finalize_random());
    else
        for (size_t i = 0; i < res.entries.size(); i++)
            res.entries.v.push_back(input.finalize_from_dealer());
    return res;
}

template<class T>
void DealerMatrixPrep<T>::buffer_triples()
{
    CODE_LOCATION
    assert(this->prep);
    assert(this->prep->proc);
    auto& input = this->prep->proc->input;
    input.reset(input.dealer_player());
    int batch_size = BaseMachine::matrix_batch_size(n_rows, n_inner, n_cols);
    assert(batch_size > 0);
    ValueMatrix<typename T::clear> A(n_rows, n_inner), B(n_inner, n_cols),
            C(n_rows, n_cols);
    size_t n_values = batch_size * C.entries.size();
    if (input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::clear> values;
        values.reserve(n_values);
        for (int i = 0; i < batch_size; i++)
        {
            A.entries.v.clear();
            B.entries.v.clear();
            for (size_t j = 0; j < A.entries.size(); j++)
                A.entries.v.push_back(input.random_for_dealer());
            for (size_t j = 0; j < B.entries.size(); j++)
                B.entries.v.push_back(input.random_for_dealer());
            C = A * B;
            append(values, C);
            this->triples.push_back({{{n_rows, n_inner}, {n_inner, n_cols},
                {n_rows, n_cols}}});
        }
        input.add_from_dealer(values);
    }
    else
    {
        input.add_n_from_dealer(n_values);
        input.add_n_from_dealer(
                batch_size * (A.entries.size() + B.entries.size()), true);
    }

    input.exchange();

    if (not input.is_dealer())
    {
        for (int i = 0; i < batch_size; i++)
        {
            this->triples.push_back({{receive(input, n_rows, n_inner, true),
                receive(input, n_inner, n_cols, true),
                receive(input, n_rows, n_cols, false)}});
        }
    }
}
