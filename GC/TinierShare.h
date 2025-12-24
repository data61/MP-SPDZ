/*
 * TinierShare.h
 *
 */

#ifndef GC_TINIERSHARE_H_
#define GC_TINIERSHARE_H_

#include "Processor/DummyProtocol.h"
#include "Protocols/Share.h"
#include "Math/Bit.h"

#ifdef LONG_BIT_MAC_KEY
class gf2n_mac_key : public gf2n_long
{
    typedef gf2n_long super;
#else
class gf2n_mac_key : public gf2n_short
{
    typedef gf2n_short super;
#endif

public:
    gf2n_mac_key()
    {
    }

    template<class T>
    gf2n_mac_key(const T& other) :
            super(other)
    {
    }
};

namespace GC
{

template<class T> class TinierSecret;
template<class T> class TinierSharePrep;

template<class T>
class TinierShare: public Share_<SemiShare<Bit>, SemiShare<T>>,
        public ShareSecret<TinierSecret<T>>
{
    typedef TinierShare This;

public:
    typedef Share_<SemiShare<Bit>, SemiShare<T>> super;

    typedef T mac_key_type;
    typedef T mac_type;
    typedef T sacri_type;
    typedef Share<T> input_check_type;
    typedef This prep_type;
    typedef This prep_check_type;
    typedef This bit_prep_type;

    typedef MAC_Check_<This> MAC_Check;
    typedef Direct_MAC_Check<This> Direct_MC;
    typedef TinierSharePrep<This> LivePrep;
    typedef ::Input<This> Input;
    typedef Beaver<This> Protocol;
    typedef NPartyTripleGenerator<TinierSecret<T>> TripleGenerator;

    typedef void DynamicMemory;
    typedef SwitchableOutput out_type;

    typedef This small_type;

    typedef TinierSecret<T> whole_type;

    static const int default_length = 1;
    static const bool expensive_triples = true;

    static string name()
    {
        return "tinier share";
    }

    static string type_string()
    {
        return "Tinier";
    }

    static string type_short()
    {
        return "TT";
    }

    static ShareThread<TinierSecret<T>>& get_party()
    {
        return ShareThread<TinierSecret<T>>::s();
    }

    static MAC_Check* new_mc(mac_key_type mac_key)
    {
        return new MAC_Check(mac_key);
    }

    TinierShare()
    {
    }
    TinierShare(const super& other) :
            super(other)
    {
    }
    TinierShare(const typename super::share_type& share, const typename super::mac_type& mac) :
            super(share, mac)
    {
    }
    TinierShare(const TinierSecret<T>& other);

    void XOR(const This& a, const This& b)
    {
        *this = a + b;
    }

    This operator^(const This& other) const
    {
        return *this + other;
    }

    This& operator^=(const This& other)
    {
        *this += other;
        return *this;
    }

    void public_input(bool input)
    {
        auto& party = get_party();
        *this = super::constant(input, party.P->my_num(),
                party.MC->get_alphai());
    }

    This lsb() const
    {
        return *this;
    }

    This get_bit(int i)
    {
        assert(i == 0);
        return lsb();
    }
};

template<class T>
const int TinierShare<T>::default_length;

} /* namespace GC */

#endif /* GC_TINIERSHARE_H_ */
