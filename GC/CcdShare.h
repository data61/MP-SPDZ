/*
 * CcdShare.h
 *
 */

#ifndef GC_CCDSHARE_H_
#define GC_CCDSHARE_H_

#include "Protocols/ShamirShare.h"

namespace GC
{

template<class T> class CcdSecret;

template<class T>
class CcdShare : public ShamirShare<T>, public ShareSecret<CcdSecret<T>>
{
    typedef CcdShare This;

public:
    typedef ShamirShare<T> super;

    typedef Bit clear;

    typedef ReplicatedPrep<This> LivePrep;
    typedef ShamirInput<This> Input;

    typedef IndirectShamirMC<This> MAC_Check;
    typedef ShamirMC<This> Direct_MC;
    typedef Shamir<This> Protocol;

    typedef This small_type;

    typedef NoShare bit_type;

    static const int default_length = 1;

    static string name()
    {
        return "CCD";
    }

    static MAC_Check* new_mc(typename super::mac_key_type)
    {
        return new MAC_Check;
    }

    CcdShare()
    {
    }

    CcdShare(const CcdSecret<T>& other) :
            super(other.get_bit(0))
    {
    }

    template<class U>
    CcdShare(const U& other) :
            super(other)
    {
    }

    void XOR(const This& a, const This& b)
    {
        *this = a + b;
    }

    void public_input(bool input)
    {
        *this = input;
    }

    This& operator^=(const This& other)
    {
        *this += other;
        return *this;
    }
};

template<class T>
const int CcdShare<T>::default_length;

}

#endif /* GC_CCDSHARE_H_ */
