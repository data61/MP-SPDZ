/*
 * Semi2kShare.h
 *
 */

#ifndef PROTOCOLS_SEMI2KSHARE_H_
#define PROTOCOLS_SEMI2KSHARE_H_

#include "SemiShare.h"
#include "Semi.h"
#include "OT/Rectangle.h"
#include "GC/SemiSecret.h"
#include "GC/square64.h"
#include "Processor/Instruction.h"

template<class T> class SemiPrep2k;

template <int K>
class Semi2kShare : public SemiShare<SignedZ2<K>>
{
    typedef SignedZ2<K> T;
    typedef Semi2kShare This;

public:
    typedef SemiMC<Semi2kShare> MAC_Check;
    typedef DirectSemiMC<Semi2kShare> Direct_MC;
    typedef SemiInput<Semi2kShare> Input;
    typedef ::PrivateOutput<Semi2kShare> PrivateOutput;
    typedef Semi<Semi2kShare> BasicProtocol;
    typedef SemiPrep2k<Semi2kShare> LivePrep;
    typedef MaybeHemi<This> Protocol;
    typedef DummyMatrixPrep<This> MatrixPrep;

    typedef Semi2kShare prep_type;
    typedef SemiMultiplier<Semi2kShare> Multiplier;
    typedef OTTripleGenerator<prep_type> TripleGenerator;
    typedef Z2kSquare<K> Rectangle;

    static const bool has_split = true;

    Semi2kShare()
    {
    }
    template<class U>
    Semi2kShare(const U& other) : SemiShare<SignedZ2<K>>(other)
    {
    }

    template<class U>
    static void split(StackedVector<U>& dest, const vector<int>& regs, int n_bits,
            const Semi2kShare* source, int n_inputs,
            typename U::Protocol& protocol)
    {
        auto& P = protocol.P;
        int my_num = P.my_num();
        int unit = GC::Clear::N_BITS;
        for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
        {
            int start = k * unit;
            int m = min(unit, n_inputs - start);
            int n = regs.size() / n_bits;
            if (P.num_players() != n)
                throw runtime_error(
                        to_string(n) + "-way split not working with "
                                + to_string(P.num_players()) + " parties");

            for (int l = 0; l < n_bits; l += unit)
            {
                int base = l;
                int n_left = min(n_bits - base, unit);
                for (int i = base; i < base + n_left; i++)
                    for (int j = 0; j < n; j++)
                        dest.at(regs.at(n * i + j) + k) = {};

                square64 square;

                for (int j = 0; j < m; j++)
                    square.rows[j] = source[j + start].get_limb(l / unit);

                square.transpose(m, n_left);

                for (int j = 0; j < n_left; j++)
                {
                    auto& dest_reg = dest.at(
                            regs.at(n * (base + j) + my_num) + k);
                    dest_reg = square.rows[j];
                }
            }
        }
    }
};

#endif /* PROTOCOLS_SEMI2KSHARE_H_ */
