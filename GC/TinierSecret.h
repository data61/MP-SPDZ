/*
 * TinierSecret.h
 *
 */

#ifndef GC_TINIERSECRET_H_
#define GC_TINIERSECRET_H_

#include "TinySecret.h"
#include "TinierShare.h"

template<class T> class TinierMultiplier;

namespace GC
{

template<class T> class TinierPrep;
template<class T> class VectorProtocol;
template<class T> class CcdPrep;
template<class T> class VectorInput;

template<class T>
class TinierSecret : public VectorSecret<TinierShare<T>>
{
    typedef VectorSecret<TinierShare<T>> super;
    typedef TinierSecret This;

public:
    typedef TinyMC<This> MC;
    typedef MC MAC_Check;
    typedef VectorProtocol<This> Protocol;
    typedef VectorInput<This> Input;
    typedef CcdPrep<This> LivePrep;
    typedef Memory<This> DynamicMemory;

    typedef NPartyTripleGenerator<This> TripleGenerator;
    typedef NPartyTripleGenerator<This> InputGenerator;
    typedef TinierMultiplier<This> Multiplier;

    typedef typename super::part_type check_type;
    typedef Share<T> input_check_type;
    typedef check_type input_type;
    typedef This bit_prep_type;

    static string type_short()
    {
        return "TT";
    }

    static MC* new_mc(typename super::mac_key_type mac_key)
    {
        return new MC(mac_key);
    }

    template<class U>
    static void generate_mac_key(typename super::mac_key_type& dest, const U&)
    {
        SeededPRNG G;
        dest.randomize(G);
    }

    static void store_clear_in_dynamic(Memory<This>& mem,
            const vector<ClearWriteAccess>& accesses)
    {
        auto& party = ShareThread<This>::s();
        for (auto access : accesses)
            mem[access.address] = super::constant(access.value,
                    party.P->my_num(), {});
    }


    TinierSecret()
    {
    }
    TinierSecret(const super& other) :
            super(other)
    {
    }
    TinierSecret(const typename super::super& other) :
            super(other)
    {
    }
    TinierSecret(const typename super::part_type& other)
    {
        this->get_regs().push_back(other);
    }

    void reveal(size_t n_bits, Clear& x)
    {
        auto& to_open = *this;
        to_open.resize_regs(n_bits);
        auto& party = ShareThread<This>::s();
        x = party.MC->POpen(to_open, *party.P);
    }
};

template<class T>
TinierShare<T>::TinierShare(const TinierSecret<T>& other)
{
    assert(other.get_regs().size() > 0);
    *this = other.get_reg(0);
}

} /* namespace GC */

#endif /* GC_TINIERSECRET_H_ */
