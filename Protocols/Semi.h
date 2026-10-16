/*
 * Semi2k.h
 *
 */

#ifndef PROTOCOLS_SEMI_H_
#define PROTOCOLS_SEMI_H_

#include "Beaver.h"
#include "Processor/TruncPrTuple.h"
#include "OT/OTExtensionWithMatrix.h"

/**
 * Dishonest-majority protocol for computation modulo a power of two
 */
template<class T>
class Semi : public Beaver<T>
{
    typedef Beaver<T> super;

    SeededPRNG G;

    OTExtensionWithMatrix* ot_ext;

public:
    Semi(Player& P) :
            Beaver<T>(P), ot_ext(0)
    {
    }

    ~Semi()
    {
        if (ot_ext)
            delete ot_ext;
    }

    OTExtensionWithMatrix& get_ot_extension()
    {
        if (not ot_ext)
            ot_ext = new OTExtensionWithMatrix(this->P, true);

        return *ot_ext;
    }

    void randoms(T& res, int n_bits)
    {
        res.randomize_part(G, n_bits);
    }

    template<int = 0>
    void trunc_pr(const vector<int>&, int, SubProcessor<T>&, true_type)
    {
        throw not_implemented();
    }

    template<int = 0>
    void trunc_pr(const ArgVector& regs, int size,
            SubProcessor<T>& proc, false_type)
    {
        if (this->P.num_players() > 2)
            throw runtime_error("probabilistic truncation "
                    "only implemented for two players");

        assert(regs.size() % 4 == 0);
        this->trunc_pr_big_counter += size * regs.size() / 4;
        typedef typename T::open_type open_type;

        vector<TruncPrTupleWithGap<open_type>> infos;
        for (size_t i = 0; i < regs.size(); i += 4)
            infos.push_back({regs, i});

        for (auto& info : infos)
        {
            if (not info.big_gap())
            {
                if (not T::clear::invertible)
                {
                    int min_size = 64 * DIV_CEIL(
                            info.k + OnlineOptions::singleton.trunc_error, 64);
                    throw runtime_error(
                            "Bit length too large for trunc_pr. "
                                    "Disable it or increase the ring size "
                                    "during compilation using '-R "
                                    + to_string(min_size) + "'.");
                }
                else
                    throw runtime_error("bit length too large");
            }
            if (this->P.my_num())
                for (int i = 0; i < size; i++)
                    proc.get_S_ref(info.dest_base + i) =
                            proc.get_S()[info.source_base + i].signed_rshift(
                                    info.m);
            else
                for (int i = 0; i < size; i++)
                    proc.get_S_ref(info.dest_base + i) =
                            proc.get_S()[info.source_base + i].signed_rshift(info.m);
        }
    }

    void buffer_random()
    {
        for (int i = 0; i < this->buffer_size; i++)
            this->random.push_back(G.get<T>());
    }

    void mulbits(const ArgVector& reg, SubProcessor<T>& proc)
    {
        proc.mulbits(reg);
    }

    bool corrected_lsb(const T& share)
    {
        if (T::prime_field)
        {
            bigint::tmp.from_signed(typename T::clear(share));
            return bigint::tmp.get_ui() & 1;
        }
        else
            return share.get_bit(0);
    }

    template<int = 0>
    void multiply_mixed(vector<T>& products,
            vector<pair<T, T>>& multiplicands, SubProcessor<T>& proc)
    {
        CODE_LOCATION
        auto& P = this->P;
        if (P.num_players() == 2)
        {
            assert(T::N_BITS <= 128);
            if (not ot_ext)
                ot_ext = new OTExtensionWithMatrix(P, false);
            auto& ext = get_ot_extension();
            BitVector bits;
            octetStream os, os2;
            SeededPRNG G;
            size_t budget = OnlineOptions::singleton.batch_size * T::length();

            for (size_t base = 0; base < multiplicands.size(); base += budget)
            {
                os.reset_write_head();
                os2.reset_write_head();
                size_t chunk = min(budget, multiplicands.size() - base);
                bits.resize(chunk);
                bits.randomize(G);
                ext.extend(bits.size(), bits);

                for (size_t i = 0; i < bits.size(); i++)
                {
                    auto& x = multiplicands[base + i];
                    os.store_bit(corrected_lsb(x.second) ^ bits.get_bit(i));
                    products[base + i].from_random(ext.receiverOutputMatrix[i]);
                }

                os.append(0);
                P.pass_around(os, 1);

                for (size_t i = 0; i < bits.size(); i++)
                {
                    auto& x = multiplicands[base + i];
                    auto sk = x.first;
                    auto fk = corrected_lsb(x.second);
                    auto d = os.get_bit();
                    T m[2];
                    for (int j = 0; j < 2; j++)
                        m[j].from_random(ext.senderOutputMatrices[j ^ d][i]);
                    auto r = m[0] - (sk * fk);
                    auto v1 = sk * (1 ^ fk) + r;
                    (v1 - m[1]).pack(os2);
                    products[base + i] -= r;
                }

                P.pass_around(os2, 1);
                for (size_t i = 0; i < bits.size(); i++)
                    products[base + i] += os2.get<T>()
                            * corrected_lsb(multiplicands[base + i].second);
            }
        }
        else
            this->multiply(products, multiplicands, 0, products.size(), proc);
    }
};

#endif /* PROTOCOLS_SEMI_H_ */
