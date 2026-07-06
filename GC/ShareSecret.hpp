/*
 * ReplicatedSecret.cpp
 *
 */

#ifndef GC_SHARESECRET_HPP
#define GC_SHARESECRET_HPP

#include "ShareSecret.h"

#include "ShareThread.h"
#include "Thread.h"
#include "square64.h"

#include "Protocols/Share.h"

#include "ShareParty.h"
#include "ShareThread.hpp"
#include "Thread.hpp"
#include "VectorProtocol.hpp"

namespace GC
{

template<class U, int L>
const int RepSecretBase<U, L>::N_BITS;

template<class U, int L>
const int RepSecretBase<U, L>::default_length;

template<class U, int L>
const false_type RepSecretBase<U, L>::is_clear;

template<class U>
void ShareSecret<U>::check_length(int n, const Integer& x)
{
	if ((size_t) n < 8 * sizeof(x)
			and (unsigned long long) abs(x.get()) >= (1ULL << n))
		throw out_of_range(
				"public value too long for " + to_string(n) + " bits: "
						+ to_string(x.get()) + "/" + to_string(1ULL << n));
}

template<class U>
void ShareSecret<U>::invert(int n, const U& x)
{
    U ones;
    ones.load_clear(64, -1);
    reinterpret_cast<U&>(*this) = U(x + ones) & get_mask(n);
}

template<class U>
void ReplicatedSecret<U>::load_clear(int n, const Integer& x)
{
    this->check_length(n, x);
    *this = x;
}

template<class U, int L>
void RepSecretBase<U, L>::bitcom(StackedVector<U>& S, const ArgVector& regs)
{
    plain_bitcom(*this, S, regs);
}

template<class T, class U>
void plain_bitcom(T& res, StackedVector<U>& S, const ArgVector& regs)
{
    res = 0;
    for (unsigned int i = 0; i < regs.size(); i++)
        res ^= (S[regs[i]] << i);
}

template<class U, int L>
void RepSecretBase<U, L>::bitdec(StackedVector<U>& S, const ArgVector& regs) const
{
    plain_bitdec(*this, S, regs);
}

template<class T, class U>
void plain_bitdec(const T& source, StackedVector<U>& S, const ArgVector& regs)
{
    for (unsigned int i = 0; i < regs.size(); i++)
        S[regs[i]] = (source >> i) & 1;
}

template<class U>
void ShareSecret<U>::load(vector<ReadAccess<U> >& accesses,
        const Memory<U>& mem)
{
    for (auto access : accesses)
        access.dest = mem[access.address];
}

template<class U>
void ShareSecret<U>::store(Memory<U>& mem,
        vector<WriteAccess<U> >& accesses)
{
    for (auto access : accesses)
        mem[access.address] = access.source;
}

template<class U>
void ShareSecret<U>::store_clear_in_dynamic(Memory<U>& mem,
        const vector<ClearWriteAccess>& accesses)
{
    auto& thread = ShareThread<U>::s();
    assert(thread.P);
    assert(thread.MC);
    for (auto access : accesses)
        mem[access.address] = U::constant(access.value, thread.P->my_num(),
                thread.MC->get_alphai());
}

template<class U>
template<class T>
void GC::ShareSecret<U>::my_input(T& inputter, BitVec value, int n_bits)
{
    inputter.add_mine(value, n_bits);
}

template<class U>
template<class T>
void GC::ShareSecret<U>::other_input(T& inputter, int from, int)
{
    inputter.add_other(from);
}

template<class U>
template<class T>
void GC::ShareSecret<U>::finalize_input(T& inputter, int from,
        int n_bits)
{
    static_cast<U&>(*this) = inputter.finalize(from, n_bits).mask(n_bits);
}

template<class U>
void ShareSecret<U>::inputb(Processor<U>& processor,
        ProcessorBase& input_processor,
        const ArgVector& args)
{
    auto& party = ShareThread<U>::s();
    typename U::Input input(*party.MC, party.DataF, *party.P, party.protocol);
    input.reset_all(*party.P);
    processor.inputb(input, input_processor, args, party.P->my_num());
}

template<class U>
void ShareSecret<U>::inputbvec(Processor<U>& processor,
        ProcessorBase& input_processor,
        const ArgVector& args)
{
    auto& party = ShareThread<U>::s();
    typename U::Input input(*party.MC, party.DataF, *party.P, party.protocol);
    input.reset_all(*party.P);
    processor.inputbvec(input, input_processor, args, *party.P);
}

template <class T>
void Processor<T>::inputb(typename T::Input& input, ProcessorBase& input_processor,
        const ArgVector& args, int my_num)
{
    InputArgList a(args);
    complexity += a.n_input_bits();
    bool interactive = T::actual_inputs
            && a.n_interactive_inputs_from_me(my_num) > 0;
    size_t dl = T::default_length;

    for (auto x : a)
    {
        if (input.is_me(x.from, my_num))
        {
            bigint whole_input = get_long_input<bigint>(x.params,
                    input_processor, interactive);
            for (int i = 0; i < DIV_CEIL(x.n_bits, dl); i++)
            {
                auto& res = S[x.dest + i];
                res.my_input(input,
                        (whole_input > 0) ?
                                whole_input.get_ui() : whole_input.get_si(),
                        min(dl, x.n_bits - i * dl));
                whole_input >>= dl;
            }
        }
        else
            for (int i = 0; i < DIV_CEIL(x.n_bits, dl); i++)
                S[x.dest + i].other_input(input, x.from,
                        min(dl, x.n_bits - i * dl));
    }

    if (interactive)
        cout << "Thank you" << endl;

    input.exchange();

    for (auto x : a)
    {
        int from = x.from;
        int n_bits = x.n_bits;
        for (int i = 0; i < DIV_CEIL(x.n_bits, dl); i++)
        {
            auto& res = S[x.dest + i];
            int n = min(dl, n_bits - i * dl);
            res.finalize_input(input, from, n);
        }
    }
}

template <class T>
void Processor<T>::inputbvec(typename T::Input& input, ProcessorBase& input_processor,
        const ArgVector& args, PlayerBase& P)
{
    int my_num = P.my_num();
    InputVecArgList a(args);
    complexity += a.n_input_bits();
    bool interactive = T::actual_inputs
            && a.n_interactive_inputs_from_me(my_num) > 0;

    for (auto x : a)
    {
        if (unsigned(x.from) >= unsigned(P.num_players()))
            throw runtime_error("invalid player number");

        if (input.is_me(x.from, my_num))
        {
            bigint whole_input = get_long_input<bigint>(x.params,
                    input_processor, interactive);
            for (size_t i = 0; i < x.n_bits; i++)
            {
                auto& res = S[x.dest[i]];
                res.my_input(input, bigint(whole_input >> (i)).get_si() & 1, 1);
            }
        }
        else
            for (size_t i = 0; i < x.n_bits; i++)
                S[x.dest[i]].other_input(input, x.from, 1);
    }

    if (interactive)
        cout << "Thank you" << endl;

    input.exchange();

    for (auto x : a)
    {
        int from = x.from;
        int n_bits = x.n_bits;
        for (int i = 0; i < n_bits; i++)
        {
            auto& res = S[x.dest[i]];
            res.finalize_input(input, from, 1);
        }
    }
}

template<class U>
void ShareSecret<U>::reveal_inst(Processor<U>& processor,
        const ArgVector& args)
{
    auto& party = ShareThread<U>::s();
    party.check();
    assert(args.size() % 3 == 0);
    vector<U> shares;
    for (size_t i = 0; i < args.size(); i += 3)
    {
        int n = args[i];
        int r1 = args[i + 2];
        if (n > max(U::default_length, Clear::N_BITS))
            assert(U::default_length == Clear::N_BITS);
        for (int j = 0; j < DIV_CEIL(n, U::default_length); j++)
        {
            shares.push_back({});
            processor.S[r1 + j].mask(shares.back(),
                    min(U::default_length, n - j * U::default_length));
        }
    }
    assert(party.MC);
    PointerVector<typename U::open_type> opened;
    party.MC->POpen(opened, shares, *party.P);
    for (size_t i = 0; i < args.size(); i += 3)
    {
        int n = args[i];
        int r0 = args[i + 1];
        for (int j = 0; j < DIV_CEIL(n, U::default_length); j++)
        {
            processor.C[r0 + j] = opened.next().mask(
                    min(U::default_length, n - j * U::default_length));
        }
    }
}

template<class U>
BitVec ReplicatedSecret<U>::local_mul(const ReplicatedSecret& other) const
{
    return (*this)[0] * other.sum() + (*this)[1] * other[0];
}

template<class U>
void ShareSecret<U>::and_(
        Processor<U>& processor, const ArgVector& args,
        bool repeat)
{
    ShareThread<U>::s().and_(processor, args, repeat);
}

template<class U>
void ShareSecret<U>::andrsvec(Processor<U>& processor, const ArgVector& args)
{
    ShareThread<U>::s().andrsvec(processor, args);
}

template<class U>
void ShareSecret<U>::xors(Processor<U>& processor, const ArgVector& args)
{
    ShareThread<U>::s().xors(processor, args);
}

template<class U, int L>
void RepSecretBase<U, L>::trans(Processor<U>& processor,
        int n_outputs, const ArgVector& args)
{
    vec_trans(processor, n_outputs, args);
}

template<class U>
void vec_trans(Processor<U>& processor,
        int n_outputs, const ArgVector& args)
{
    int N_BITS = U::default_length;
    int L = U::vector_length;
    for (int k = 0; k < L; k++)
    {
        for (int j = 0; j < DIV_CEIL(n_outputs, N_BITS); j++)
            for (int l = 0; l < DIV_CEIL(args.size() - n_outputs, N_BITS); l++)
            {
                square64 square;
                size_t input_base = n_outputs + l * N_BITS;
                for (size_t i = input_base; i < min(input_base + N_BITS, args.size()); i++)
                    square.rows[i - input_base] = processor.S[args[i] + j][k].get();
                square.transpose(
                        min(size_t(N_BITS), args.size() - n_outputs - l * N_BITS),
                        min(N_BITS, n_outputs - j * N_BITS));
                int output_base = j * N_BITS;
                for (int i = output_base; i < min(n_outputs, output_base + N_BITS); i++)
                {
                    processor.S[args[i] + l][k] = square.rows[i - output_base];
                }
            }
    }
}

template<class U>
void ReplicatedSecret<U>::reveal(size_t n_bits, Clear& x)
{
    (void) n_bits;
    auto& share = *this;
    vector<BitVec> opened;
    auto& party = ShareThread<U>::s();
    party.MC->POpen(opened, {share}, *party.P);
    x = BitVec::super(opened[0]);
}

template<class U>
void ShareSecret<U>::random_bit()
{
    U res;
    ShareThread<U>::s().DataF.get_one(DATA_BIT, res);
    *this = res;
}

template<class U>
U& GC::ShareSecret<U>::operator=(const U& other)
{
    U& real_this = reinterpret_cast<U&>(*this);
    real_this = other;
    return real_this;
}

}

#endif
