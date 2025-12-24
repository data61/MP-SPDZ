/*
 * SemiSecret.cpp
 *
 */

#ifndef GC_SEMISECRET_HPP_
#define GC_SEMISECRET_HPP_

#include "GC/ShareParty.h"
#include "GC/ShareSecret.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/DealerMC.h"
#include "SemiSecret.h"
#include "Semi.h"

namespace GC
{

inline
SemiSecret::MC* SemiSecret::new_mc(
        typename super::mac_key_type)
{
    if (OnlineOptions::singleton.direct)
        return new Direct_MC;
    else
        return new MC;
}

inline
DealerSecret::MC* DealerSecret::new_mc(
        typename super::mac_key_type)
{
    if (OnlineOptions::singleton.direct)
        return new Direct_MC;
    else
        return new MC;
}

template<class T, class V>
void SemiSecretBase<T, V>::trans(Processor<T>& processor, int n_outputs,
        const vector<int>& args)
{
    int N_BITS = default_length;
    for (int j = 0; j < DIV_CEIL(n_outputs, N_BITS); j++)
        for (int l = 0; l < DIV_CEIL(args.size() - n_outputs, N_BITS); l++)
        {
            square64 square;
            size_t input_base = n_outputs + l * N_BITS;
            for (size_t i = input_base;
                    i < min(input_base + N_BITS, args.size()); i++)
                square.rows[i - input_base] = processor.S[args[i] + j].get();
            square.transpose(
                    min(size_t(N_BITS), args.size() - n_outputs - l * N_BITS),
                    min(N_BITS, n_outputs - j * N_BITS));
            int output_base = j * N_BITS;
            for (int i = output_base; i < min(n_outputs, output_base + N_BITS);
                    i++)
            {
                processor.S[args[i] + l] = square.rows[i - output_base];
            }
        }
}

inline
void SemiSecret::andrsvec(Processor<SemiSecret>& processor,
        const vector<int>& args)
{
    int N_BITS = default_length;
    auto protocol = ShareThread<SemiSecret>::s().protocol;
    assert(protocol);
    protocol->init_mul();
    auto it = args.begin();
    int total_bits = 0, total_ops = 0;
    while (it < args.end())
    {
        int n_args = (*it++ - 3) / 2;
        int size = *it++;
        total_bits += n_args * size;
        it += n_args;
        int base = *it++;
        for (int i = 0; i < size; i += N_BITS)
        {
            for (int k = 0; k < n_args; k += N_BITS)
            {
                int left = min(N_BITS, n_args - k);
                square64 square;
                for (int j = 0; j < left; j++)
                    square.rows[j] = processor.S.at(
                            *(it + k + j) + i / N_BITS).get();
                int n_ops = min(N_BITS, size - i);
                total_ops += n_ops;
                square.transpose(left, n_ops);
                for (int j = 0; j < n_ops; j++)
                {
                    long bit = processor.S.at(base + i / N_BITS).get_bit(j);
                    auto y_ext = SemiSecret(bit).extend_bit();
                    protocol->prepare_mult(square.rows[j], y_ext, left, true);
                }
            }
        }
        it += n_args;
    }

    if (OnlineOptions::singleton.has_option("verbose_and"))
        fprintf(stderr, "%d/%d repeat ANDs\n", total_bits, total_ops);

    protocol->exchange();

    it = args.begin();
    while (it < args.end())
    {
        int n_args = (*it++ - 3) / 2;
        int size = *it++;
        for (int i = 0; i < size; i += N_BITS)
        {
            for (int base = 0; base < n_args; base += N_BITS)
            {
                int left = min(N_BITS, n_args - base);
                int n_ops = min(N_BITS, size - i);
                square64 square;
                for (int j = 0; j < n_ops; j++)
                    square.rows[j] = protocol->finalize_mul(left).get();
                square.transpose(n_ops, left);
                for (int j = 0; j < left; j++)
                    processor.S.at(*(it + base + j) + i / N_BITS) =
                            square.rows[j];
            }
        }
        it += 2 * n_args + 1;
    }
}

template<class T, class V>
void SemiSecretBase<T, V>::load_clear(int n, const Integer& x)
{
    this->check_length(n, x);
    *this = this->constant(x, ShareThread<T>::s().P->my_num());
}

template<class T, class V>
void SemiSecretBase<T, V>::bitcom(StackedVector<T>& S, const vector<int>& regs)
{
    *this = 0;
    for (unsigned int i = 0; i < regs.size(); i++)
        *this ^= (S[regs[i]] << i);
}

template<class T, class V>
void SemiSecretBase<T, V>::bitdec(StackedVector<T>& S,
        const vector<int>& regs) const
{
    for (unsigned int i = 0; i < regs.size(); i++)
        S[regs[i]] = (*this >> i) & 1;
}

template<class T, class V>
void SemiSecretBase<T, V>::reveal(size_t n_bits, Clear& x)
{
    auto& thread = ShareThread<T>::s();
    x = thread.MC->POpen(*this, *thread.P).mask(n_bits);
}

} /* namespace GC */

#endif
