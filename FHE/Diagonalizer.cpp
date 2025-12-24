/*
 * Diagonalizer.cpp
 *
 */

#include "Diagonalizer.h"

Diagonalizer::Diagonalizer(const MatrixVector& matrices,
        const FFT_Data& FTD, const FHE_PK& pk) :
        FTD(FTD)
{
    CODE_LOCATION_NO_SCOPE

    assert(not matrices.empty());
    for (auto& matrix : matrices)
    {
        assert(matrix.n_cols == matrices[0].n_cols);
        assert(matrix.n_rows == matrices[0].n_rows);
    }

    n_rows = matrices[0].n_rows;
    n_cols = matrices[0].n_cols;
    assert(n_rows * matrices.size() <= size_t(FTD.num_slots()));
    for (size_t i = 0; i < n_cols; i++)
    {
        Plaintext_<FFT_Data> plaintext(FTD, Evaluation);
        for (size_t k = 0; k < matrices.size(); k++)
        {
            for (size_t j = 0; j < n_rows; j++)
            {
                auto entry = matrices.at(k)[{j, (j + i) % n_cols}];
                plaintext.set_element(k * n_rows + j, entry);
            }
        }
        ciphertexts.push_back(pk.encrypt(plaintext));
    }
}

Plaintext_<FFT_Data> Diagonalizer::get_plaintext(
        const MatrixVector& matrices, int left_col,
        int right_col)
{
    Plaintext_<FFT_Data> plaintext(FTD, Evaluation);
    for (size_t k = 0; k < matrices.size(); k++)
        for (size_t j = 0; j < n_rows; j++)
            plaintext.set_element(k * n_rows + j,
                    matrices.at(k)[{(left_col + j) % n_cols, right_col}]);
    return plaintext;
}

Diagonalizer::MatrixVector Diagonalizer::decrypt(
        const vector<Ciphertext>& products, int n_matrices, FHE_SK& sk)
{
    vector<Plaintext_<FFT_Data>> plaintexts;
    for (auto& x : products)
        plaintexts.push_back(sk.decrypt(x, FTD));
    return dediag(plaintexts, n_matrices);
}

Diagonalizer::MatrixVector Diagonalizer::dediag(
        const vector<Plaintext_<FFT_Data>>& products, int n_matrices)
{
    int n_cols_out = products.size();
    MatrixVector res(n_matrices, {int(n_rows), n_cols_out});
    for (int i = 0; i < n_cols_out; i++)
    {
        auto& c = products.at(i);
        for (int j = 0; j < n_matrices; j++)
        {
            res.at(j).entries.init();
            for (size_t k = 0; k < n_rows; k++)
                res.at(j)[{k, i}] = c.element(j * n_rows + k);
        }
    }
    return res;
}
