/*
 * Hemi.hpp
 *
 */

#ifndef PROTOCOLS_HEMI_HPP_
#define PROTOCOLS_HEMI_HPP_

#include "Hemi.h"
#include "ShareMatrix.h"
#include "HemiOptions.h"
#include "MatrixFile.h"
#include "DummyMatrixPrep.h"
#include "Processor/Conv2dTuple.h"

#include "HemiMatrixPrep.hpp"
#include "HemiPrep.hpp"

template<class T>
Hemi<T>::~Hemi()
{
    for (auto& x : matrix_preps)
        delete x.second;
    if (mc)
        delete mc;
}

template<class T>
Preprocessing<ShareMatrix<T>>& Hemi<T>::get_matrix_prep(const array<int, 3>& dims,
        SubProcessor<T>& processor)
{
    if (matrix_preps.find(dims) == matrix_preps.end())
    {
        Preprocessing<ShareMatrix<T>>* prep;
        if (OnlineOptions::singleton.live_prep)
            prep = new typename T::MatrixPrep(dims[0], dims[1], dims[2],
                    dynamic_cast<typename T::LivePrep&>(processor.DataF),
                    matrix_usage);
        else
            prep = new MatrixFile<T>(dims, matrix_usage, this->P);
        matrix_preps.insert({dims, prep});
    }
    return *matrix_preps.at(dims);
}

template<class T>
bool Hemi<T>::use_plain_matmul(const array<int, 3> dim, SubProcessor<T>& processor)
{
    if (OnlineOptions::singleton.has_option("force_matrix_triples"))
        return false;

    if (OnlineOptions::singleton.live_prep)
    {
        try
        {
            get_matrix_prep(dim, processor);
        }
        catch (no_matrix_prep&)
        {
            return true;
        }
    }
    else
    {
        int found = false;

        try
        {
            get_matrix_prep(dim, processor);
            found = true;
        }
        catch (signature_mismatch&)
        {
            if (not warned)
            {
                cerr << "Cannot find matrix triples on disk, "
                        << "reverting to plain triples" << endl;
                cerr << "Use './Fake-Offline.x -p <program-with-args> ...'"
                        << " to generate matrix triples" << endl;
                warned = true;
            }
        }

        Bundle<octetStream> os(processor.P);
        os.mine.store(found);
        processor.P.Broadcast_Receive(os);
        os.mine.reset_read_head();

        for (auto& o : os)
            if (not o.get_int(4))
                return true;
    }

    auto& prep = get_matrix_prep(dim, processor);
    int savings = (dim[0] * dim[2]) / (dim[0] + dim[2]) + 1;
    int requirement = BaseMachine::matrix_requirement(dim[0], dim[1], dim[2]);

    if (OnlineOptions::singleton.has_option("verbose_matrix"))
        fprintf(stderr, "savings=%d minimum_batch=%d requirement=%d\n", savings,
                prep.minimum_batch(), requirement);

    return HemiOptions::singleton.plain_matmul
            or prep.minimum_batch() / savings > requirement;
}

template<class T>
void Hemi<T>::matmulsm(SubProcessor<T>& processor, MemoryPart<T>& source,
        const Instruction& instruction)
{
    CODE_LOCATION
    auto& dim = instruction.get_start();

    vector<int> plain_args, complex_args;

    for (auto it = dim.begin(); it < dim.end(); it += 12)
    {
        array<int, 3> real_dims({it[3], it[4], it[5]});

        if (use_plain_matmul(real_dims, processor))
            plain_args.insert(plain_args.end(), it, it + 12);
        else
            complex_args.insert(complex_args.end(), it, it + 12);
    }

    if (not plain_args.empty())
        processor.matmulsm(source, plain_args);

    auto& S = processor.get_S();

    // Perform the matrix multiplications in sequence.
    // They are not merged into one communication round since that would require multiple matrix_preps to
    // merge rounds.
    // An improvement might be to merge the communication of multiple matrices with the same dimension into one round,
    // which is not implemented yet.
    auto Proc = processor.Proc;
    assert(Proc);

    for (auto matmulArgs = complex_args.begin();
            matmulArgs < complex_args.end(); matmulArgs += 12)
    {
        auto C = S.begin() + matmulArgs[0];
        size_t firstFactorBase  = Proc->get_Ci().at(matmulArgs[1]).get();
        size_t secondFactorBase = Proc->get_Ci().at(matmulArgs[2]).get();
        auto resultNumberOfRows = matmulArgs[3];
        auto usedNumberOfFirstFactorColumns = matmulArgs[4];
        auto resultNumberOfColumns = matmulArgs[5];
        auto firstFactorTotalNumberOfColumns = matmulArgs[10];
        auto secondFactorTotalNumberOfColumns = matmulArgs[11];

        assert(C + resultNumberOfRows * resultNumberOfColumns <= S.end());

        ShareMatrix<T> A(resultNumberOfRows, usedNumberOfFirstFactorColumns), B(usedNumberOfFirstFactorColumns, resultNumberOfColumns);
        if (not T::real_shares(processor.P))
        {
            matrix_multiply(A, B, processor);
            continue;
        }

        for (int i = 0; i < resultNumberOfRows; i++) {
            auto actualFirstFactorRow = Proc->get_Ci().at(matmulArgs[6] + i).get();

            for (int k = 0; k < usedNumberOfFirstFactorColumns; k++)
            {
                auto actualFirstFactorColumn = Proc->get_Ci().at(matmulArgs[7] + k).get();
                A.entries.v.push_back(source.at(firstFactorBase + actualFirstFactorRow * firstFactorTotalNumberOfColumns + actualFirstFactorColumn));
            }
        }


        for (int k = 0; k < usedNumberOfFirstFactorColumns; k++) {
            auto actualSecondFactorRow = Proc->get_Ci().at(matmulArgs[8] + k).get();
            for (int j = 0; j < resultNumberOfColumns; j++)
            {
                auto actualSecondFactorColumn = Proc->get_Ci().at(matmulArgs[9] + j).get();
                B.entries.v.push_back(source.at(secondFactorBase + actualSecondFactorRow * secondFactorTotalNumberOfColumns + actualSecondFactorColumn));
            }
        }

        auto res = matrix_multiply(A, B, processor);

        for (int i = 0; i < resultNumberOfRows; i++)
            for (int j = 0; j < resultNumberOfColumns; j++)
                *(C + i * resultNumberOfColumns + j) = res[{i, j}];
    }
}

template<class T>
ShareMatrix<T> Hemi<T>::matrix_multiply(const ShareMatrix<T>& A,
        const ShareMatrix<T>& B, SubProcessor<T>& processor)
{
    CODE_LOCATION
    if (mc == 0)
    {
        mc = new MatrixMC<T>(processor.MC);
    }

    Beaver<ShareMatrix<T>> beaver(this->P);
    array<int, 3> dims = {{A.n_rows, A.n_cols, B.n_cols}};
    ShareMatrix<T> C(A.n_rows, B.n_cols);

    bool verbose = OnlineOptions::singleton.has_option("verbose_matmul");

    int max_inner = OnlineOptions::singleton.batch_size;
    int max_cols = OnlineOptions::singleton.batch_size;

    if (not OnlineOptions::singleton.live_prep)
    {
        max_inner = A.n_cols;
        max_cols = B.n_cols;
    }

    for (int i = 0; i < A.n_cols; i += max_inner)
    {
        for (int j = 0; j < B.n_cols; j += max_cols)
        {
            auto subdim = dims;
            subdim[1] = min(max_inner, A.n_cols - i);
            subdim[2] = min(max_cols, B.n_cols - j);
            auto& prep = get_matrix_prep(subdim, processor);
            beaver.init(prep, *mc);
            beaver.init_mul();
            bool for_real = T::real_shares(processor.P);
            if (verbose)
                fprintf(stderr, "matmul prepare\n");
            auto AA = A.from(0, i, subdim.data(), for_real);
            auto BB = B.from(i, j, subdim.data() + 1, for_real);
            beaver.prepare_mul(AA, BB);
            if (for_real)
            {
                if (verbose)
                    fprintf(stderr, "matmul exchange\n");
                for (size_t k = 0; k < AA.entries.size() + BB.entries.size();
                        k++)
                    mc->inner.set_random_element({});
                beaver.exchange();
                C.add_from_col(j, beaver.finalize_mul());
            }
        }
    }

    if (OnlineOptions::singleton.has_option("debug_matmul"))
    {
        mc->inner.Check(processor.P);
        auto opened = mc->open(C, processor.P);
        for (auto& x: opened.entries)
            cout << x << " ";
        cout << endl;
        mc->inner.Check(processor.P);
    }

    return C;
}

/**
 * Reduce convolution to matrix multiplication
 */
template<class T>
void Hemi<T>::conv2ds(SubProcessor<T>& processor,
        const Instruction& instruction)
{
    auto& args = instruction.get_start();
    vector<Conv2dTuple> tuples;
    for (size_t i = 0; i < args.size(); i += 15)
    {
        tuples.push_back(Conv2dTuple(args, i));
        if (use_plain_matmul(tuples.back().matrix_dimensions(), processor))
        {
            processor.conv2ds(instruction);
            return;
        }
    }
    for (auto& tuple : tuples)
        tuple.run_matrix(processor);
}

inline
array<int, 3> Conv2dTuple::matrix_dimensions()
{
    return {1, weights_h * weights_w * n_channels_in, batch_size * output_h * output_w};
}

template<class T>
void Conv2dTuple::run_matrix(SubProcessor<T>& processor)
{
    CODE_LOCATION
    auto& S = processor.get_S();
    array<int, 3> dim = matrix_dimensions();
    ShareMatrix<T> A(dim[0], dim[1]), B(dim[1], dim[2]);

    if (not T::real_shares(processor.P))
    {
        processor.protocol.matrix_multiply(A, B, processor);
        return;
    }

    A.entries.init();
    B.entries.init();

    for (int i_batch = 0; i_batch < batch_size; i_batch ++)
    {
        size_t base = r1 + i_batch * inputs_w * inputs_h * n_channels_in;
        assert(base + inputs_w * inputs_h * n_channels_in <= S.size());
        T* input_base = &S[base];
        for (int out_y = 0; out_y < output_h; out_y++)
            for (int out_x = 0; out_x < output_w; out_x++)
            {
                int in_x_origin = (out_x * stride_w) - padding_w;
                int in_y_origin = (out_y * stride_h) - padding_h;

                for (int filter_y = 0; filter_y < weights_h; filter_y++)
                {
                    int in_y = in_y_origin + filter_y * filter_stride_h;
                    if ((0 <= in_y) and (in_y < inputs_h))
                        for (int filter_x = 0; filter_x < weights_w; filter_x++)
                        {
                            int in_x = in_x_origin + filter_x * filter_stride_w;
                            if ((0 <= in_x) and (in_x < inputs_w))
                            {
                                T* pixel_base = &input_base[(in_y * inputs_w
                                        + in_x) * n_channels_in];
                                T* weight_base = &S[r2
                                        + (filter_y * weights_w + filter_x)
                                                * n_channels_in];
                                for (int in_c = 0; in_c < n_channels_in; in_c++)
//                                    protocol.prepare_dotprod(pixel_base[in_c],
//                                            weight_base[in_c])
                                {
                                    int i_inner = n_channels_in * (filter_x * weights_h + filter_y) + in_c;
                                    B[{i_inner, output_h * (output_w * i_batch + out_x) + out_y}] = pixel_base[in_c];
                                    A[{0, i_inner}] = weight_base[in_c];
                                }
                            }
                        }
                }
//
//                protocol.next_dotprod();
            }
    }

    auto C = processor.protocol.matrix_multiply(A, B, processor);

    for (int i_batch = 0; i_batch < batch_size; i_batch ++)
    {
        size_t base = r0 + i_batch * output_h * output_w;
        assert(base + output_h * output_w <= S.size());
        T* output_base = &S[base];
        for (int out_y = 0; out_y < output_h; out_y++)
            for (int out_x = 0; out_x < output_w; out_x++)
            {
                output_base[out_y * output_w + out_x] = C[{0, output_h * (output_w * i_batch + out_x) + out_y}];
//                        protocol.finalize_dotprod(
//                                lengths[i_batch][out_y][out_x]);
            }
    }

}

template<class T>
TimerWithComm Hemi<T>::prep_time()
{
    TimerWithComm res;
    for (auto& prep : matrix_preps)
        res += prep.second->prep_timer;
    return res;
}

#endif /* PROTOCOLS_HEMI_HPP_ */
