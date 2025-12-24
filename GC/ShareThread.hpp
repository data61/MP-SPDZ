/*
 * MalicousRepParty.cpp
 *
 */

#ifndef GC_SHARETHREAD_HPP_
#define GC_SHARETHREAD_HPP_

#include <GC/ShareThread.h>
#include "GC/ShareParty.h"
#include "BitPrepFiles.h"
#include "Math/Setup.h"
#include "Tools/DoubleRange.h"

#include "Processor/Data_Files.hpp"

namespace GC
{

template<class T>
StandaloneShareThread<T>::StandaloneShareThread(int i, ThreadMaster<T>& master) :
        ShareThread<T>(*Preprocessing<T>::get_new(master.opts.live_prep,
                master.N, usage)),
        Thread<T>(i, master)
{
}

template<class T>
StandaloneShareThread<T>::~StandaloneShareThread()
{
    delete &this->DataF;
}

template<class T>
ShareThread<T>::ShareThread(Preprocessing<T>& prep) :
    P(0), MC(0), protocol(0), DataF(prep)
{
}

template<class T>
ShareThread<T>::ShareThread(Preprocessing<T>& prep, Player& P,
        typename T::mac_key_type mac_key) :
        ShareThread(prep)
{
    pre_run(P, mac_key);
}

template<class T>
ShareThread<T>::~ShareThread()
{
    if (MC)
        delete MC;
    if (protocol)
        delete protocol;
}

template<class T>
void ShareThread<T>::pre_run(Player& P, typename T::mac_key_type mac_key)
{
    this->P = &P;
    if (singleton)
        throw runtime_error("there can only be one");
    singleton = this;
    protocol = new typename T::Protocol(*this->P);
    MC = this->new_mc(mac_key);
    DataF.set_protocol(*this->protocol);
    this->protocol->init(DataF, *MC);
}

template<class T>
void StandaloneShareThread<T>::pre_run()
{
    ShareThread<T>::pre_run(*Thread<T>::P, ShareParty<T>::s().mac_key);
    usage.set_num_players(Thread<T>::P->num_players());
}

template<class T>
void ShareThread<T>::post_run()
{
    check();
}

template<class T>
void ShareThread<T>::check()
{
    protocol->check();
    MC->Check(*this->P);
}

template<class T>
class BitOpTuple
{
    size_t n_bits, dest, left, right;

public:
    static const int n = 4;

    BitOpTuple(vector<int>::const_iterator it) :
            n_bits(*it++), dest(*it++), left(*it++), right(*it++)
    {
    }

    size_t n_blocks()
    {
        return DIV_CEIL(n_bits, T::default_length);
    }

    size_t n_full_blocks()
    {
        return n_bits / T::default_length;
    }

    DoubleRange<T> input_range(StackedVector<T>& S)
    {
        return {S, left, right, n_blocks()};
    }

    DoubleRange<T> full_block_input_range(StackedVector<T>& S)
    {
        return {S, left, right, n_full_blocks()};
    }

    Range<StackedVector<T>> full_block_left_range(StackedVector<T>& S)
    {
        return {S, left, n_full_blocks()};
    }

    DoubleIterator<T> partial_block(StackedVector<T>& S)
    {
        assert(n_blocks() != n_full_blocks());
        return {S.iterator_for_size(left + n_full_blocks(), 1),
            S.iterator_for_size(right + n_full_blocks(), 1)};
    }

    typename CheckVector<T>::iterator partial_left_block(StackedVector<T>& S)
    {
        assert(n_blocks() != n_full_blocks());
        return S.iterator_for_size(left + n_full_blocks(), 1);
    }

    T& get_right_base(StackedVector<T>& S)
    {
        return S[right];
    }

    Range<StackedVector<T>> full_block_output_range(StackedVector<T>& S)
    {
        return {S, dest, n_full_blocks()};
    }

    T& partial_output(StackedVector<T>& S)
    {
        assert(n_blocks() != n_full_blocks());
        return S[dest + n_full_blocks()];
    }

    int last_length()
    {
        if (n_blocks() == n_full_blocks())
            return 0;
        else
            return n_bits % T::default_length;
    }
};

template<class T>
void ShareThread<T>::and_(Processor<T>& processor,
        const vector<int>& args, bool repeat)
{
    auto& protocol = this->protocol;
    auto& S = processor.S;
    processor.check_args(args, 4);
    protocol->init_mul();
    T x_ext, y_ext;

    size_t total_bits = 0;
    for (auto it = args.begin(); it < args.end(); it += 4)
        total_bits += *it;

    // accept 10 % waste
    bool fast_mode = 0.1 * total_bits > args.size() / 4 * T::default_length;
    if (fast_mode)
    {
        protocol->set_fast_mode(true);
    }

    ArgList<BitOpTuple<T>> infos(args);

    if (repeat)
        for (auto info : infos)
        {
            int n = T::default_length;
            auto& y = info.get_right_base(S);
            for (auto x : info.full_block_left_range(S))
            {
                y.extend_bit(y_ext, n);
                protocol->prepare_mult(x, y_ext, n, true);
            }
            n = info.last_length();
            if (n)
            {
                info.partial_left_block(S)->mask(x_ext, n);
                y.extend_bit(y_ext, n);
                protocol->prepare_mult(x_ext, y_ext, n, true);
            }
        }
    else
        for (auto info : infos)
        {
            if (fast_mode)
                for (auto x : info.full_block_input_range(S))
                    protocol->prepare_mul_fast(x.first, x.second);
            else if (info.n_full_blocks())
                for (auto x : info.full_block_input_range(S))
                    protocol->prepare_mul(x.first, x.second);
            int n = info.last_length();
            if (n)
            {
                info.partial_block(S).left->mask(x_ext, n);
                info.partial_block(S).right->mask(y_ext, n);
                protocol->prepare_mult(x_ext, y_ext, n, false);
            }
        }

    if (OnlineOptions::singleton.has_option("verbose_and"))
        fprintf(stderr, "%zu%s ANDs\n", total_bits, repeat ? " repeat" : "");

    protocol->exchange();

    if (repeat)
        for (auto info : infos)
        {
            int n = T::default_length;
            for (auto& res : info.full_block_output_range(S))
                protocol->finalize_mult(res, n);
            n = info.last_length();
            if (n)
            {
                protocol->finalize_mult(info.partial_output(S), n);
            }
        }
    else
        for (auto info : infos)
        {
            if (fast_mode)
                for (auto& res : info.full_block_output_range(S))
                    res = protocol->finalize_mul_fast();
            else if (info.n_full_blocks())
                for (auto& res : info.full_block_output_range(S))
                    res = protocol->finalize_mul();

            int n = info.last_length();
            if (n)
            {
                protocol->finalize_mult(info.partial_output(S), n);
            }
        }

    if (OnlineOptions::singleton.has_option("always_check"))
        protocol->check();

    protocol->set_fast_mode(false);
}

template<class T>
void ShareThread<T>::andrsvec(Processor<T>& processor, const vector<int>& args)
{
    int N_BITS = T::default_length;
    auto& protocol = this->protocol;
    assert(protocol);
    protocol->init_mul();
    auto it = args.begin();
    T x_ext, y_ext;
    int total_bits = 0;
    while (it < args.end())
    {
        int n_args = (*it++ - 3) / 2;
        int size = *it++;
        total_bits += size * n_args;
        it += n_args;
        int base = *it++;
        for (int i = 0; i < size; i += N_BITS)
        {
            int n_ops = min(N_BITS, size - i);
            for (int j = 0; j < n_args; j++)
            {
                processor.S.at(*(it + j) + i / N_BITS).mask(x_ext, n_ops);
                processor.S.at(base + i / N_BITS).mask(y_ext, n_ops);
                protocol->prepare_mul(x_ext, y_ext, n_ops);
            }
        }
        it += n_args;
    }

    if (OnlineOptions::singleton.has_option("verbose_and"))
        fprintf(stderr, "%d repeat ANDs\n", total_bits);

    protocol->exchange();

    it = args.begin();
    while (it < args.end())
    {
        int n_args = (*it++ - 3) / 2;
        int size = *it++;
        for (int i = 0; i < size; i += N_BITS)
        {
            int n_ops = min(N_BITS, size - i);
            for (int j = 0; j < n_args; j++)
                protocol->finalize_mul(n_ops).mask(
                        processor.S.at(*(it + j) + i / N_BITS), n_ops);
        }
        it += 2 * n_args + 1;
    }

    if (OnlineOptions::singleton.has_option("always_check"))
        protocol->check();
}

template<class T>
void ShareThread<T>::xors(Processor<T>& processor, const vector<int>& args)
{
    processor.check_args(args, 4);
    auto it = args.begin();
    while (it < args.end())
    {
        int n_bits = *it++;
        if (n_bits == 1)
            processor.S[*it++].xor_(1, processor.S[*it++], processor.S[*it++]);
        else
        {
            int size = DIV_CEIL(n_bits, T::default_length);
            auto out = processor.S.iterator_for_size(*it++, size);
            auto left = processor.S.iterator_for_size(*it++, size);
            auto right = processor.S.iterator_for_size(*it++, size);
            for (int j = 0; j < size - 1; j++)
                (*out++).xor_(T::default_length, *left++, *right++);
            int n_bits_left = n_bits - (size - 1) * T::default_length;
            (*out++).xor_(n_bits_left, *left++, *right++);
        }
    }
}

} /* namespace GC */

#endif
