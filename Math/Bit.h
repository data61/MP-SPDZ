/*
 * Bit.h
 *
 */

#ifndef MATH_BIT_H_
#define MATH_BIT_H_

#include "BitVec.h"

template<class T> class gf2n_;

class Bit : public BitVec_<bool>
{
    typedef BitVec_<bool> super;

public:
    static int size_in_bits()
    {
        return 1;
    }

    static int p()
    {
        return 2;
    }

    Bit()
    {
    }
    Bit(int other) :
            super(other)
    {
        assert(other == 0 or other == 1);
    }
    Bit(const super::super& other) :
            super(other)
    {
    }
    Bit(char*)
    {
        throw runtime_error("never call this");
    }

    template<class T>
    Bit(const gf2n_<T>& other);

    Bit operator*(const Bit& other) const
    {
        return super::operator*(other);
    }

    template<class T>
    T operator*(const T& other) const
    {
        return this->a ? other : T();
    }

    void randomize(PRNG& G)
    {
        *this = G.get_bit();
    }

    void pack(octetStream& os, int = -1) const
    {
        super::pack(os, 1);
    }
    void unpack(octetStream& os, int = -1)
    {
        super::unpack(os, 1);
    }

    void operator>>=(int)
    {
        throw runtime_error("never call this");
    }
    void operator<<=(int)
    {
        throw runtime_error("never call this");
    }
};

inline Bit operator+(bool a, const Bit& b)
{
    return b + a;
}

inline Bit operator*(bool a, const Bit& b)
{
    return b * a;
}

#endif /* MATH_BIT_H_ */
