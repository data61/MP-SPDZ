/*
 * BitVec.h
 *
 */

#ifndef MATH_BITVEC_H_
#define MATH_BITVEC_H_

#include "Integer.h"
#include "field_types.h"

class BitDiagonal;

template<class T>
class BitVec_ : public IntBase<T>
{
public:
    typedef IntBase<T> super;

    typedef BitVec_ Scalar;

    typedef BitVec_ next;
    typedef BitDiagonal Square;

    static const int n_bits = sizeof(T) * 8;

    static const false_type invertible;
    static const true_type characteristic_two;
    static const true_type binary;

    static char type_char() { return 'B'; }
    static string type_short() { return "B"; }
    static DataFieldType field_type() { return DATA_GF2; }

    static bool allows(Dtype dtype) { return dtype == DATA_TRIPLE or dtype == DATA_BIT; }

    BitVec_() {}
    BitVec_(long a) : super(a) {}
    template<class U>
    BitVec_(const IntBase<U>& a) : super(a.get()) {}
    template<int K>
    BitVec_(const Z2<K>& a) : super(a.get_limb(0)) {}

    BitVec_(PRNG& G);

    BitVec_ operator+(const BitVec_& other) const { return *this ^ other; }
    BitVec_ operator-(const BitVec_& other) const { return *this ^ other; }
    BitVec_ operator*(const BitVec_& other) const { return *this & other; }

    BitVec_ operator~() const { return ~this->a; }

    BitVec_ operator/(const BitVec_& other) const { (void) other; throw not_implemented(); }

    BitVec_& operator+=(const BitVec_& other) { *this ^= other; return *this; }
    BitVec_& operator-=(const BitVec_& other) { *this ^= other; return *this; }
    BitVec_& operator*=(const BitVec_& other) { *this &= other; return *this; }

    BitVec_ operator-() const { return *this; }

    BitVec_ extend_bit() const { return -(this->a & 1); }

    void extend_bit(BitVec_& res, int) const { res = extend_bit(); }

    void mul(const BitVec_& a, const BitVec_& b) { *this = a * b; }

    void randomize(PRNG& G, int n = -1)
    {
        if (n == -1 or is_same<T, bool>())
            super::randomize(G);
        else
        {
            assert(n <= n_bits);
            G.get_octets((octet*) &this->a, DIV_CEIL(n, 8));
            *this = this->mask(n);
        }
    }

    template<int LL = sizeof(T)>
    void pack(octetStream& os) const { os.store_int<LL>(this->a); }
    template<int LL = sizeof(T)>
    void unpack(octetStream& os) { this->a = os.get_int<LL>(); }

    void pack(octetStream& os, int n) const
    {
        if (n == -1)
            pack(os);
        else if (n < 8)
            os.store_bits(this->a, n);
        else
            os.store_int(super::mask(n).get(), DIV_CEIL(n, 8));
    }

    void unpack(octetStream& os, int n)
    {
        if (n == -1)
            unpack(os);
        else if (n < 8)
            this->a = os.get_bits(n);
        else
            this->a = os.get_int(DIV_CEIL(n, 8));
    }

    static BitVec_ unpack_new(octetStream& os, int n = n_bits)
    {
        BitVec_ res;
        res.unpack(os, n);
        return res;
    }
};

typedef BitVec_<long> BitVec;

template<class T>
const false_type BitVec_<T>::invertible;
template<class T>
const true_type BitVec_<T>::characteristic_two;
template<class T>
const true_type BitVec_<T>::binary;

template<class T>
BitVec_<T>::BitVec_(PRNG& G)
{
    randomize(G);
}

#endif /* MATH_BITVEC_H_ */
