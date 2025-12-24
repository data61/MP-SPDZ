/*
 * MalicousCcdShare.h
 *
 */

#ifndef GC_MALICIOUSCCDSHARE_H_
#define GC_MALICIOUSCCDSHARE_H_

#include "CcdShare.h"
#include "Protocols/MaliciousShamirShare.h"

template<class T> class MaliciousBitOnlyRepPrep;

namespace GC
{

template<class T> class MaliciousCcdSecret;

template<class T>
class MaliciousCcdShare: public MaliciousShamirShare<T>, public ShareSecret<
        MaliciousCcdSecret<T>>
{
    typedef MaliciousCcdShare This;

public:
    typedef MaliciousShamirShare<T> super;

    typedef Bit clear;

    typedef MaliciousRepPrep<This> LivePrep;
    typedef ShamirInput<This> Input;
    typedef Beaver<This> Protocol;

    typedef MaliciousShamirMC<This> MAC_Check;
    typedef MAC_Check Direct_MC;

    typedef This small_type;

    typedef NoShare bit_type;

    static const int default_length = 1;

    static string name()
    {
        return "Malicious CCD";
    }

    static MAC_Check* new_mc(typename super::mac_key_type)
    {
        return new MAC_Check;
    }

    MaliciousCcdShare()
    {
    }

    MaliciousCcdShare(const MaliciousCcdSecret<T>& other) :
            super(other.get_bit(0))
    {
    }

    template<class U>
    MaliciousCcdShare(const U& other) :
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

    This get_bit(int i)
    {
        assert(i == 0);
        return *this;
    }
};

template<class T>
const int MaliciousCcdShare<T>::default_length;

} /* namespace GC */

#endif /* GC_MALICIOUSCCDSHARE_H_ */
