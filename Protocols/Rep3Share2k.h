/*
 * Rep3Share2k.h
 *
 */

#ifndef PROTOCOLS_REP3SHARE2K_H_
#define PROTOCOLS_REP3SHARE2K_H_

#include "Rep3Share.h"
#include "ReplicatedInput.h"
#include "Math/Z2k.h"
#include "GC/square64.h"
#include "Tools/CodeLocations.h"

template<class T> class SemiRep3Prep;

template<int K>
class Rep3Share2 : public Rep3Share<Z2<K>>
{
    typedef Z2<K> T;
    typedef Rep3Share2 This;

    static int split_index(int arithmetic_index, int my_num)
    {
        return (my_num + 2 - arithmetic_index) % 3;
    }

public:
    typedef Replicated<Rep3Share2> Protocol;
    typedef ReplicatedMC<Rep3Share2> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Rep3Share2> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef SemiRep3Prep<Rep3Share2> LivePrep;
    typedef Rep3Share2 Honest;
    typedef SignedZ2<K> clear;

    typedef GC::SemiHonestRepSecret bit_type;

    static const bool has_split = true;

    Rep3Share2()
    {
    }
    template<class U>
    Rep3Share2(const FixedVec<U, 2>& other)
    {
        FixedVec<T, 2>::operator=(other);
    }

    static bool matters_for_split(int, int)
    {
        return true;
    }

    template<class U, class V>
    static void split(StackedVector<U>& dest, const ArgVector& regs, int n_bits,
            const V* source, int n_inputs,
            typename U::Protocol& protocol)
    {
        CODE_LOCATION
        auto& P = protocol.P;
        int my_num = P.my_num();
        int unit = GC::Clear::N_BITS;
        int n_blocks = DIV_CEIL(n_inputs, unit);
        switch (regs.size() / n_bits)
        {
        case 3:
            for (int l = 0; l < n_bits; l += unit)
            {
                int base = l;
                int n_left = min(n_bits - base, unit);

                for (int i = base; i < base + n_left; i++)
                    for (auto& x : Range<StackedVector<U>>(dest,
                            regs.at(3 * i + V::split_index(2, my_num)), n_blocks))
                        x = {};

                for (int k = 0; k < n_blocks; k++)
                {
                    int start = k * unit;
                    int m = min(unit, n_inputs - start);

                    for (int i = 0; i < 2; i++)
                    {
                        if (not V::matters_for_split(i, my_num))
                            continue;

                        square64 square;

                        for (int j = 0; j < m; j++)
                            square.rows[j] =
                                    source[j + start].for_split(i).get_limb(
                                            l / unit);

                        square.transpose(m, n_left);

                        auto reg_it = regs.begin() + 3 * base
                                + V::split_index(i, my_num);
                        assert(reg_it + 3 * (n_left - 1) < regs.end());
                        for (int j = 0; j < n_left; j++)
                        {
                            auto& dest_reg = dest.at(*reg_it + k);
                            reg_it += 3;
                            dest_reg[1 - i] = 0;
                            dest_reg[i] = square.rows[j];
                            dest_reg = U::from_rep3(dest_reg);
                        }
                    }
                }
            }
            break;
        case 2:
        {
            assert(n_bits <= 64);
            ReplicatedInput<U> input(0, protocol);
            input.reset_all(P);
            bool fast_mode = n_inputs >= unit;
            if (fast_mode)
                input.prepare(n_blocks * n_bits);

            vector<typename StackedVector<U>::iterator> iterators[2];

            for (auto reg_it = regs.begin(); reg_it < regs.end();)
            {
                for (int i = 0; i < 2; i++)
                    iterators[i].push_back(
                            dest.iterator_for_size(*reg_it++, n_blocks));
            }

            for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
            {
                int start = k * unit;
                int m = min(unit, n_inputs - start);
                int m_for_input = m == unit ? -1 : m;

                if (P.my_num() == 0)
                {
                    square64 square;
                    auto dest_it = &square.rows[0];
                    auto end = source + start + m;
                    for (auto x = source + start; x < end; x++)
                        *dest_it++ = Integer(x->sum()).get();
                    square.transpose(m, n_bits);
                    if (fast_mode)
                    {
                        if (m_for_input == -1)
                            for (int j = 0; j < n_bits; j++)
                                input.add_mine_prepared(*iterators[0][j]++, square.rows[j]);
                        else
                            for (int j = 0; j < n_bits; j++)
                            {
                                auto& res = *iterators[0][j]++;
                                input.add_mine_prepared(res, square.rows[j]);
                            }
                    }
                    else
                        for (int j = 0; j < n_bits; j++)
                            input.add_mine(square.rows[j], m_for_input);
                }
                else
                    for (int j = 0; j < n_bits; j++)
                        input.add_other(0);
            }

            input.exchange();

            if (P.my_num() == 0)
            {
                for (int j = 0; j < n_bits; j++)
                    for (auto& x : Range(dest, regs.at(2 * j + 1), n_blocks))
                        x = {};

                if (fast_mode)
                {
                    return;
                }
            }

            for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
            {
                int start = k * unit;
                int m = min(unit, n_inputs - start);
                int m_for_input = m == unit ? -1 : m;

                if (m_for_input == -1 or fast_mode)
                {
                    switch (P.my_num())
                    {
#define X(I) case I: for (auto& x : iterators[0]) \
    { *x++ = input.finalize_offset(-I); } break;
                    X(0) X(1) X(2)
                    }
#undef X
                }
                else
                    for (auto& x : iterators[0])
                        *x++ = input.finalize(0, m_for_input);

                if (P.my_num() != 0)
                {
                    int my_num = P.my_num();
                    square64 square;
                    for (int j = 0; j < m; j++)
                        square.rows[j] = Integer(source[j + start][my_num - 1]).get();
                    square.transpose(m, n_bits);
                    for (int j = 0; j < n_bits; j++)
                    {
                        auto& dest_reg = *iterators[1][j]++;
                        dest_reg[my_num - 1] = square.rows[j];
                        dest_reg[2 - my_num] = {};
                    }
                }
            }
            break;
        }
        default:
            throw runtime_error("number of split summands not implemented");
        }
    }
};

#endif /* PROTOCOLS_REP3SHARE2K_H_ */
