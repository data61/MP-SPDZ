/*
 * OTCorrelator.hpp
 *
 */

#ifndef OT_OTCORRELATOR_HPP_
#define OT_OTCORRELATOR_HPP_

#include "OTExtensionWithMatrix.h"

#include "Math/Square.hpp"
#include "Tools/MMO.hpp"
#include "BitMatrix.hpp"

template <class U>
void OTCorrelator<U>::resize(int nOTs)
{
    t1.resize_vertical(nOTs);
    u.resize_vertical(nOTs);
    senderOutputMatrices.resize(2);
    for (int i = 0; i < 2; i++)
        senderOutputMatrices[i].resize_vertical(nOTs);
    receiverOutputMatrix.resize_vertical(nOTs);
}

template <class U>
void OTCorrelator<U>::expand(int start, int slice)
{
    (void)start, (void)slice;
    Slice<U> receiverOutputSlice(receiverOutputMatrix, start, slice);
    Slice<U> senderOutputSlices[2] = {
            Slice<U>(senderOutputMatrices[0], start, slice),
            Slice<U>(senderOutputMatrices[1], start, slice)
    };
    Slice<U> t1Slice(t1, start, slice);

    // expand with PRG
    if (ot_role & RECEIVER)
    {
        for (int i = 0; i < nbaseOTs; i++)
        {
            receiverOutputSlice.randomize(i, G_sender[i][0]);
            t1Slice.randomize(i, G_sender[i][1]);
        }
    }

    if (ot_role & SENDER)
    {
        for (int i = 0; i < nbaseOTs; i++)
            // randomize base receiver output
            senderOutputSlices[0].randomize(i, G_receiver[i]);
    }
}

template <class U>
void OTCorrelator<U>::setup_for_correlation(BitVector& baseReceiverInput,
        vector<U>& baseSenderOutputs,
        U& baseReceiverOutput)
{
    this->baseReceiverInput = baseReceiverInput;
    receiverOutputMatrix = baseSenderOutputs[0];
    t1 = baseSenderOutputs[1];
    u.squares.resize(t1.squares.size());
    senderOutputMatrices.resize(2);
    senderOutputMatrices[0] = baseReceiverOutput;
}

template <class U>
void OTCorrelator<U>::correlate(int start, int slice,
        BitVector& newReceiverInput, bool useConstantBase, int repeat)
{
    CODE_LOCATION
    vector<octetStream> os(2);

    Slice<U> receiverOutputSlice(receiverOutputMatrix, start, slice);
    Slice<U> senderOutputSlices[] = {
            Slice<U>(senderOutputMatrices[0], start, slice),
    };
    Slice<U> t1Slice(t1, start, slice);
    Slice<U> uSlice(u, start, slice);

    if (OnlineOptions::singleton.has_option("verbose_correlate"))
        fprintf(stderr, "correlate %d matrices of size %d*%d, %zu bits\n", slice,
                int(U::PartType::n_rows()), int(U::PartType::n_columns()),
                newReceiverInput.size());

    // create correlation
    if (ot_role & RECEIVER)
    {
        t1Slice.rsub(receiverOutputSlice);
        t1Slice.sub(newReceiverInput, repeat);
        t1Slice.pack(os[0]);

//        t1 = receiverOutputMatrix;
//        t1 ^= newReceiverInput;
//        receiverOutputMatrix.print_side_by_side(t1);
    }
#ifdef OTEXT_TIMER
    timeval commst1, commst2;
    gettimeofday(&commst1, NULL);
#endif
    // send t0 + t1 + x
    send_if_ot_receiver(player, os, ot_role);

    // sender adjusts using base receiver bits
    if (ot_role & SENDER)
    {
        // u = t0 + t1 + x
        uSlice.unpack(os[1]);
        senderOutputSlices[0].conditional_add(baseReceiverInput, u, !useConstantBase);
    }
#ifdef OTEXT_TIMER
    gettimeofday(&commst2, NULL);
    double commstime = timeval_diff(&commst1, &commst2);
    cout << "\t\tCommunication took time " << commstime/1000000 << endl << flush;
    times["Communication"] += timeval_diff(&commst1, &commst2);
#endif
}

template<class U>
void OTCorrelator<U>::expand_correlate_unchecked(const BitVector& delta, int n_bits)
{
    if (n_bits < 0)
        n_bits = delta.size();
    resize(n_bits);
    int slice = receiverOutputMatrix.squares.size();
    expand(0, slice);
    BitVector tmp = delta;
    tmp.resize_zero(receiverOutputMatrix.vertical_size());
    correlate(0, slice, tmp, true);
}

template <class V>
void OTExtensionWithMatrix::hash_outputs(int nOTs, vector<V>& senderOutput,
        V& receiverOutput, bool correlated)
{
    //cout << "Hashing... " << flush;
    MMO mmo;
#ifdef OTEXT_TIMER
    timeval startv, endv;
    gettimeofday(&startv, NULL);
#endif

    int n_rows = V::PartType::n_rows_allocated();
    int n = (nOTs + n_rows - 1) / n_rows * V::PartType::n_rows();
    for (int i = 0; i < 2; i++)
        senderOutput[i].resize_vertical(n);
    receiverOutput.resize_vertical(n);

    if (nOTs % 8 != 0)
        throw runtime_error("number of OTs must be divisible by 8");

    for (int i = 0; i < nOTs; i += 8)
    {
        int i_outer_input = i / 128;
        int i_inner_input = i % 128;
        int i_outer_output = i / n_rows;
        int i_inner_output = i % n_rows;
        if (ot_role & SENDER)
        {
            int128 tmp[2][8];
            for (int j = 0; j < 8; j++)
            {
                tmp[0][j] = senderOutputMatrices[0].squares[i_outer_input].rows[i_inner_input + j];
                if (correlated)
                    tmp[1][j] = tmp[0][j] ^ baseReceiverInput.get_int128(0);
                else
                    tmp[1][j] =
                            senderOutputMatrices[1].squares[i_outer_input].rows[i_inner_input + j];
            }
            for (int j = 0; j < 2; j++)
                mmo.hashEightBlocks(
                        &senderOutput[j].squares[i_outer_output].rows[i_inner_output],
                        &tmp[j]);
        }
        if (ot_role & RECEIVER)
        {
            mmo.hashEightBlocks(
                    &receiverOutput.squares[i_outer_output].rows[i_inner_output],
                    &receiverOutputMatrix.squares[i_outer_input].rows[i_inner_input]);
        }
    }
    //cout << "done.\n";
#ifdef OTEXT_TIMER
    gettimeofday(&endv, NULL);
    double elapsed = timeval_diff(&startv, &endv);
    cout << "\t\tOT ext hashing took time " << elapsed/1000000 << endl << flush;
    times["Hashing"] += timeval_diff(&startv, &endv);
#endif
}

template <class U>
template <class T>
void OTCorrelator<U>::reduce_squares(unsigned int nTriples, vector<T>& output, int start)
{
    if (receiverOutputMatrix.squares.size() < nTriples + start)
        throw invalid_length("reduce_squares");
    output.resize(nTriples);
    for (unsigned int j = 0; j < nTriples; j++)
    {
#ifdef DEBUG_MASCOT
        T a, b;
        receiverOutputMatrix.squares[j + start].to(a);
        senderOutputMatrices[0].squares[j + start].to(b);
#endif

        receiverOutputMatrix.squares[j + start].sub(
                senderOutputMatrices[0].squares[j + start]).to(output[j]);

#ifdef DEBUG_MASCOT
        cout << output[j] << " ?= " << a <<  " - " << b << endl;
        cout << "first row " << receiverOutputMatrix.squares[j + start].rows[0] << endl;
        assert(output[j] == a - b);
#endif
    }
}

template <class U>
void OTCorrelator<U>::common_seed(PRNG& G)
{
    Slice<U> t1Slice(t1, 0, t1.squares.size());
    Slice<U> uSlice(u, 0, u.squares.size());

    octetStream os;
    if (player->my_num())
    {
        t1Slice.pack(os);
        uSlice.pack(os);
    }
    else
    {
        uSlice.pack(os);
        t1Slice.pack(os);
    }
    auto hash = os.hash();
    G = PRNG(hash);
}

#endif /* OT_OTCORRELATOR_HPP_ */
