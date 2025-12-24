/*
 * fixint.h
 *
 */

#ifndef MATH_FIXINT_H_
#define MATH_FIXINT_H_

#include "Z2k.h"

template<int L>
class fixint : public SignedZ2<64 * (L + 1)>
{
    static const int N_OVERFLOW = 60;

public:
    typedef SignedZ2<64 * (L + 1)> super;
    typedef typename conditional<L == 0, super, SignedZ2<64 * L>>::type pack_type;

    fixint()
    {
    }

    template<class T>
    fixint(const T& other) :
            super(other)
    {
        auto check = mp_limb_signed_t(this->a[this->N_WORDS - 1]) >> N_OVERFLOW;
        assert(check == 0 or check == -1);
    }

    fixint operator-(const fixint& other) const
    {
        return super::operator-(other);
    }

    fixint operator-() const
    {
        return super::operator-();
    }

    fixint operator^(const fixint& other) const
    {
        assert(L == 0);
        return fixint(this->a[0] ^ other.a[0]);
    }

    void generateUniform(PRNG& G, int n_bits, bool positive = true)
    {
        G.get(bigint::tmp, n_bits, positive);
        *this = bigint::tmp;
    }

    void randomBnd(PRNG& G, const bigint& bound, bool positive)
    {
        G.randomBnd(bigint::tmp, bound, positive);
        *this = bigint::tmp;
    }

    void pack(octetStream& os) const
    {
        pack_type tmp = *this;
        tmp.pack(os);
    }

    void unpack(octetStream& os)
    {
        pack_type tmp;
        tmp.unpack(os);
        *this = tmp;
    }

    int get_min_alloc() const
    {
        return this->N_BYTES;
    }

    size_t report_size(int) const
    {
        return this->N_BYTES;
    }

    template<class T>
    void allocate_slots(const T& limit)
    {
        int n_bits = this->size_in_bits();
        if (numBits(limit) - N_OVERFLOW > n_bits)
        {
            throw runtime_error("Fixed-length integer too small. "
                    "Maybe change N_LIMBS_RAND to at least " +
                    to_string((numBits(limit) - N_OVERFLOW) / 64));
        }
    }
};

template<int L>
bigint operator-(const bigint& x, const fixint<L>& y)
{
    return x - (bigint::tmp = y);
}

template<int L>
bigint& operator+=(bigint& x, const fixint<L>& y)
{
    x += (bigint::tmp = y);
    return x;
}

template<int L>
bigint operator%(const fixint<L>& x, const bigint& y)
{
    return (bigint::tmp = x) % y;
}

template<int L>
fixint<L>& operator%=(fixint<L>& x, const bigint& y)
{
    return x = (bigint::tmp = x) % y;
}

#endif /* MATH_FIXINT_H_ */
