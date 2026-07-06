/*
 * Z2k.h
 *
 */

#ifndef MATH_Z2K_H_
#define MATH_Z2K_H_

#include <gmpxx.h>
#include <string>
using namespace std;

#include "Tools/avx_memcpy.h"
#include "bigint.h"
#include "field_types.h"
#include "mpn_fixed.h"
#include "ValueInterface.h"

template<class T> class IntBase;
template<int L> class fixint;

/**
 * Type for values in the ring defined by the integers modulo ``2^K``
 * representing `[0, 2^K-1]`.
 * It supports arithmetic, bit-wise, and output streaming operations.
 * It does not need initialization because ``K`` completely defines the domain.
 */
template <int K>
class Z2 : public ValueInterface
{

protected:
	template <int L>
	friend class Z2;
	friend class bigint;

	typedef typename conditional<K <= 32, uint32_t, mp_limb_t>::type limb_type;

	static const int N_WORDS = ((K + 7) / 8 + sizeof(mp_limb_t) - 1)
			/ sizeof(mp_limb_t);
	static const int N_LIMB_BITS = 8 * sizeof(limb_type);

	limb_type a[N_WORDS];


public:
	typedef void Square;

	static const int N_BITS = K;
	static const int MAX_EDABITS = K;
	static const int MAX_N_BITS = K;
	static const int N_BYTES = (K + 7) / 8;
	static const mp_limb_t UPPER_MASK = mp_limb_t(-1LL) >> (N_LIMB_BITS - 1 - (K - 1) % N_LIMB_BITS);

	static int size() { return N_BYTES; }
	static int size_in_limbs() { return N_WORDS; }
	static int size_in_bits() { return size() * 8; }
	static int length() { return n_bits(); }
	static int n_bits() { return N_BITS; }
	static int t() { return 0; }

	static char type_char() { return 'R'; }
	static string type_short() { return "R"; }
	static string type_string() { return "Z2^" + to_string(int(N_BITS)); }

	static DataFieldType field_type() { return DATA_INT; }

	static const false_type invertible;

	template <int L, int M, bool LAZY = false>
	static Z2<K> Mul(const Z2<L>& x, const Z2<M>& y);

	static void reqbl(int n);
	static bool allows(Dtype dtype);

	static void specification(octetStream& os);

	static Z2 power_of_two(bool bit, int exp) { return Z2(bit) << exp; }

	static string fake_opts() { return " -lgp " + to_string(K); }

	typedef Z2 next;
	typedef Z2 Scalar;

	/**
	 * Initialize to zero.
	 */
	Z2() { assign_zero(); }
	Z2(mp_limb_t x) : Z2() { a[0] = x; }
	Z2(__m128i x) : Z2() { avx_memcpy(a, &x, min(N_BYTES, 16)); }
	Z2(int x) : Z2(long(x)) { a[N_WORDS - 1] &= UPPER_MASK; }
	Z2(unsigned x) : Z2(mp_limb_t(x)) {}
	Z2(long x) : Z2(mp_limb_t(x)) { if (K > 64 and x < 0) memset(&a[1], -1, N_BYTES - 8); }
	Z2(long long x) : Z2(long(x)) {}
	template<class T>
	Z2(const IntBase<T>& x);
	/**
	 * Convert from unrestricted integer.
	 */
	Z2(const bigint& x);
	Z2(const void* buffer) : Z2() { assign(buffer); }
	/**
	 * Convert from different domain via the canonical integer representation.
	 */
	template <int L>
	Z2(const Z2<L>& x) : Z2()
	{ avx_memcpy(a, x.a, min(N_BYTES, x.N_BYTES)); normalize(); }

	Z2(PRNG& G);

	void normalize() { a[N_WORDS - 1] &= UPPER_MASK; }
	void normalize_byte() { if (N_BITS % 8) normalize(); }

	void assign_zero() { avx_memzero(a, sizeof(a)); }
	void assign_one()  { assign_zero(); a[0] = 1; }
	void assign(const void* buffer) { avx_memcpy(a, buffer, N_BYTES); normalize_byte(); }
	void assign(int x) { *this = x; }

	/**
	 * Get 64-bit part.
	 *
	 * @param i return word containing 64*i- to 64*i+63-least significant bits
	 */
	mp_limb_t get_limb(int i) const { return a[i]; }
	bool get_bit(int i) const;

	const void* get_ptr() const { return a; }
	const limb_type* get() const { return a; }

	void convert_destroy(bigint& a) { *this = a; }
	
	int bit_length() const;

	Z2 mask(int) const { return *this; }

	Z2<K> operator+(const Z2<K>& other) const;
	Z2<K> operator-(const Z2<K>& other) const;

	template <int L>
	Z2<(K > L) ? K : L> operator*(const Z2<L>& other) const;

	Z2<K> operator*(bool other) const { return other ? *this : Z2<K>(); }
	Z2<K> operator*(int other) const { return *this * Z2<K>(other); }

	Z2<K> operator/(const Z2& other) const { (void) other; throw division_by_zero(); }

	Z2<K> operator&(const Z2& other) const;
	Z2<K> operator^(const Z2& other) const;
	Z2<K> operator|(const Z2& other) const;

	Z2<K>& operator+=(const Z2<K>& other);
	Z2<K>& operator-=(const Z2<K>& other);
        Z2<K>& operator*=(const Z2<K>& other);
	Z2<K>& operator&=(const Z2<K>& other);
	Z2<K>& operator<<=(int other);
	Z2<K>& operator>>=(int other);

	Z2<K> operator<<(unsigned long i) const;
	Z2<K> operator>>(unsigned long i) const;
	Z2<K> operator<<(const Z2<K>& i) const { return *this << i.a[0]; }
	Z2<K> operator>>(const Z2<K>& i) const { return *this >> i.a[0]; }

	SignedZ2<K> signed_rshift(int i) const;
	Z2<K> cheap_lshift(unsigned i) const;

	bool operator==(const Z2<K>& other) const;
	bool operator!=(const Z2<K>& other) const { return not (*this == other); }

	Z2 lazy_add(const Z2& x) const;
	Z2 lazy_mul(const Z2& x) const;

	Z2 invert() const;

	/**
	 * Deterministic square root for values with least significate bit 1.
	 * Raises an exception otherwise.
	 */
	Z2 sqrRoot();

	bool is_zero() const { return *this == Z2<K>(); }
	bool is_one() const { return *this == 1; }
	bool is_bit() const { return is_zero() or is_one(); }

	bool msb() const
	{
        return this->a[this->N_WORDS - 1]
                & 1ll << ((K - 1) % (8 * sizeof(limb_type)));
	}

	/**
	 * Sample with uniform distribution.
	 * @param G randomness generator
	 * @param n (unused)
	 */
	void randomize(PRNG& G, int n = -1);
	void randomize_part(PRNG& G, int n);
	void almost_randomize(PRNG& G) { randomize(G); }

	void force_to_bit() { throw runtime_error("impossible"); }

	/**
	 * Append to buffer in native format.
	 * @param o buffer
	 * @param n (unused)
	 */
	void pack(octetStream& o, int = -1) const;
	/**
	 * Read from buffer in native format
	 * @param o buffer
	 * @param n (unused)
	 */
	void unpack(octetStream& o, int n = -1);

	void input(istream& s, bool human=true);
	void output(ostream& s, bool human=true) const;

	template <int J>
	friend ostream& operator<<(ostream& o, const Z2<J>& x);
};

/**
 * Type for values in the ring defined by the integers modulo ``2^K``
 * representing `[-2^(K-1), 2^(K-1)-1]`.
 * It supports arithmetic, bit-wise, comparison, and output streaming operations.
 * It does not need initialization because ``K`` completely defines the domain.
 */
template<int K>
class SignedZ2 : public Z2<K>
{
public:
    /**
     * Initialization to zero
     */
    SignedZ2()
    {
    }

    /**
     * Conversion from another domain via the signed representation
     */
    template <int L>
    SignedZ2(const SignedZ2<L>& other) : Z2<K>(other)
    {
        extend(other);
    }

    template<int L>
    void extend(const SignedZ2<L>& other)
    {
        if (L < K and other.negative())
        {
            this->a[other.size_in_limbs() - 1] |= ~other.UPPER_MASK;
            for (int i = Z2<L>::size_in_limbs(); i < this->N_WORDS; i++)
              this->a[i] = -1;
        }
        this->normalize();
    }

    SignedZ2(const Integer& other);

    template<class T>
    SignedZ2(const T& other) :
            Z2<K>(other)
    {
    }

    template<int L>
    SignedZ2(const fixint<L>& other) :
            Z2<K>(other)
    {
        extend(other);
    }

    void to(bigint& res) const
    {
        res = *this;
    }

    bool negative() const
    {
        return this->msb();
    }

    bool operator<(const SignedZ2& other) const
    {
        return (*this - other).negative();
    }

    bool operator>(const SignedZ2& other) const
    {
        return (other - this).negative();
    }

    SignedZ2 operator-() const
    {
        return SignedZ2() - *this;
    }

    void negate()
    {
        *this = -*this;
    }

    SignedZ2 operator-(const SignedZ2& other) const
    {
        return Z2<K>::operator-(other);
    }

    SignedZ2<K> operator*(const SignedZ2<K>& other) const
    {
        return Z2<K>::operator*(other);
    }

    template<int L>
    Z2<K + L> operator*(const Z2<L>& other) const
    {
        return Z2<K>::operator*(other);
    }

    SignedZ2<K> operator*(int other) const
    {
        return operator*(SignedZ2<64>(other));
    }

    void output(ostream& s, bool human = true, bool signed_ = true) const;
};

template<int K>
inline Z2<K> Z2<K>::operator+(const Z2<K>& other) const
{
	auto res = lazy_add(other);
	res.normalize();
	return res;
}

template<int K>
Z2<K> Z2<K>::lazy_add(const Z2<K>& other) const
{
    Z2<K> res;
    mpn_add_fixed_n<N_WORDS>(res.a, a, other.a);
    return res;
}

template<int K>
Z2<K> Z2<K>::operator-(const Z2<K>& other) const
{
	Z2<K> res;
	mpn_sub_fixed_n<N_WORDS>(res.a, a, other.a);
	res.a[N_WORDS - 1] &= UPPER_MASK;
	return res;
}

template <int K>
inline Z2<K>& Z2<K>::operator+=(const Z2<K>& other)
{
	mpn_add_fixed_n<N_WORDS>(a, other.a, a);
	a[N_WORDS - 1] &= UPPER_MASK;
	return *this;
}

template <int K>
Z2<K>& Z2<K>::operator-=(const Z2<K>& other)
{
	*this = *this - other;
	return *this;
}

template <int K>
Z2<K>& Z2<K>::operator*=(const Z2<K>& other)
{
        *this = *this * other;
        return *this;
}

template <int K>
Z2<K>& Z2<K>::operator&=(const Z2<K>& other)
{
	*this = *this & other;
	return *this;
}

template <int K>
Z2<K>& Z2<K>::operator<<=(int other)
{
	*this = *this << other;
	return *this;
}

template <int K>
Z2<K>& Z2<K>::operator>>=(int other)
{
	*this = *this >> other;
	return *this;
}

template <int K>
template <int L, int M, bool LAZY>
inline Z2<K> Z2<K>::Mul(const Z2<L>& x, const Z2<M>& y)
{
	Z2<K> res;
	mpn_mul_fixed_<N_WORDS, Z2<L>::N_WORDS, Z2<M>::N_WORDS>(res.a, x.a, y.a);
	if (not LAZY)
		res.normalize();
	return res;
}

template <int K>
template <int L>
inline Z2<(K > L) ? K : L> Z2<K>::operator*(const Z2<L>& other) const
{
	return Z2<(K > L) ? K : L>::Mul(*this, other);
}

template <int K>
inline Z2<K> Z2<K>::lazy_mul(const Z2<K>& other) const
{
	return Z2<K>::Mul<K, K, true>(*this, other);
}

template <int K>
Z2<K> Z2<K>::operator<<(unsigned long i) const
{
	Z2<K> res;
	auto n_limb_shift = i / N_LIMB_BITS;
	for (int j = n_limb_shift; j < N_WORDS; j++)
		res.a[j] = a[j - n_limb_shift];
	int n_inside_shift = i % N_LIMB_BITS;
	if (N_WORDS == 1)
	    res.a[0] <<= n_inside_shift;
	else
	    if (n_inside_shift > 0)
	        mpn_lshift_fixed<limb_type, N_WORDS>(res.a, res.a, n_inside_shift);
	res.a[N_WORDS - 1] &= UPPER_MASK;
	return res;
}

template<int K>
Z2<K> Z2<K>::cheap_lshift(unsigned i) const
{
    if (N_WORDS == 1)
        return a[0] << i;
    else
        return *this << i;
}

template <int K>
Z2<K> Z2<K>::operator>>(unsigned long i) const
{
	Z2<K> res;
	auto n_limb_shift = i / N_LIMB_BITS;
	for (int j = n_limb_shift; j < N_WORDS; j++)
		res.a[j - n_limb_shift] = a[j];
	int n_inside_shift = i % N_LIMB_BITS;
	if (N_WORDS == 1)
		res.a[0] >>= n_inside_shift;
	else if (n_inside_shift > 0)
		mpn_rshift_fixed<limb_type, N_WORDS>(res.a, res.a, n_inside_shift);
	return res;
}

template<int K>
SignedZ2<K> Z2<K>::signed_rshift(int i) const
{
    if (SignedZ2<K>(*this).negative())
        return -SignedZ2<K>(-SignedZ2<K>(*this + 1) >> i);
    else
        return *this >> i;
}

template<int K>
Z2<K>::Z2(PRNG& G)
{
	randomize(G);
}

template<int K>
void Z2<K>::randomize(PRNG& G, int n)
{
	(void) n;
	G.get_octets<N_BYTES>((octet*)a);
	normalize_byte();
}

template<int K>
void Z2<K>::randomize_part(PRNG& G, int n)
{
	if (n >= N_BITS)
	{
		randomize(G);
		return;
	}

	*this = {};
	G.get_octets((octet*)a, DIV_CEIL(n, 8));
	a[DIV_CEIL(n, 64) - 1] &= mp_limb_t(-1LL) >> (N_LIMB_BITS - 1 - (n - 1) % N_LIMB_BITS);
}

template<int K>
void Z2<K>::pack(octetStream& o, int n) const
{
	(void) n;
	o.append((octet*)a, N_BYTES);
}

template<int K>
void Z2<K>::unpack(octetStream& o, int n)
{
	(void) n;
	o.consume((octet*)a, N_BYTES);
}

template<int K>
SignedZ2<K> abs(const SignedZ2<K>& x)
{
    if (x.negative())
        return -x;
    else
        return x;
}

template<int K>
void SignedZ2<K>::output(ostream& s, bool human, bool signed_) const
{
    if (human)
    {
        if (signed_)
        {
            bigint::tmp = *this;
            s << bigint::tmp;
        }
        else
            Z2<K>::output(s, human);
    }
    else
        Z2<K>::output(s, false);
}

template<int K>
ostream& operator<<(ostream& o, const SignedZ2<K>& x)
{
    x.output(o, true, false);
    return o;
}

#endif /* MATH_Z2K_H_ */
