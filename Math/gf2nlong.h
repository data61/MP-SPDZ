/*
 * gf2nlong.h
 *
 */

#ifndef MATH_GF2NLONG_H_
#define MATH_GF2NLONG_H_

#include <stdlib.h>
#include <string.h>

#include <iostream>
using namespace std;

#include "Tools/random.h"
#include "Tools/intrinsics.h"
#include "Math/field_types.h"
#include "Math/bigint.h"
#include "Math/gf2n.h"


bool is_ge(__m128i a, __m128i b);

class int128
{
public:
    __m128i a;

    int128() : a(_mm_setzero_si128()) { }
    int128(const __m128i& a) : a(a) { }
    int128(const word& a) : a(_mm_cvtsi64_si128(a)) { }
    int128(const word& upper, const word& lower) : a(_mm_set_epi64x(upper, lower)) { }

    word get_lower() const                      { return (word)_mm_cvtsi128_si64(a); }
    word get_upper() const     { return _mm_cvtsi128_si64(_mm_unpackhi_epi64(a, a)); }
    word get_half(bool upper) const { return upper ? get_upper() : get_lower(); }

#ifdef __SSE4_1__
    bool operator==(const int128& other) const  { return _mm_test_all_zeros(a ^ other.a, a ^ other.a); }
#else
    bool operator==(const int128& other) const  { return get_lower() == other.get_lower() and get_upper() == other.get_upper(); }
#endif
    bool operator!=(const int128& other) const  { return !(*this == other); }

    bool operator>=(const int128& other) const  { return is_ge(a, other.a); }

    int128 operator<<(const int& other) const;
    int128 operator>>(const int& other) const;

    int128 operator^(const int128& other) const { return a ^ other.a; }
    int128 operator|(const int128& other) const { return a | other.a; }
    int128 operator&(const int128& other) const { return a & other.a; }

    int128 operator~() const                    { return ~a; }

    int128& operator<<=(const int& other)       { return *this = *this << other; }
    int128& operator>>=(const int& other)       { return *this = *this >> other; }

    int128& operator^=(const int128& other)     { a ^= other.a; return *this; }
    int128& operator|=(const int128& other)     { a |= other.a; return *this; }
    int128& operator&=(const int128& other)     { a &= other.a; return *this; }

    friend ostream& operator<<(ostream& s, const int128& a);
    friend istream& operator>>(istream& s, int128& a);

    bool get_bit(int i) const;

    void randomize(PRNG& G)                     { *this = G.get_doubleword(); }

    void to(int128& other)                      { other = *this; }
    void to(word& other)                        { other = get_lower(); }

    void pack(octetStream& os) const;
    void unpack(octetStream& os);
};

template<class T>
class bit_plus
{
    static const int N_BITS = 8 * sizeof(T);

    T lower;
    bool msb;

public:
    bit_plus() : msb(false) { }
    bit_plus(T lower, bool msb) : lower(lower), msb(msb) { }
    template<class U>
    bit_plus(U a) : lower(a), msb(false) { }
    T get_lower() { return lower; }
    bool operator==(const bit_plus& other)
        { return (lower == other.lower) && (msb == other.msb); }
    bool operator!=(const bit_plus& other)
        { return !(*this == other); }
    bool operator>=(const bit_plus& other)
        { return msb == other.msb ? lower >= other.lower : msb > other.msb; }
    bit_plus operator<<(int other)
        { return bit_plus(lower << other, ((lower >> (N_BITS-other)) & 1) != 0); }
    bit_plus& operator>>=(int other)
        { lower >>= other; lower |= (T(msb) << (N_BITS-other)); msb = !other; return *this; }
    bit_plus operator^(const bit_plus& other)
        { return bit_plus(lower ^ other.lower, msb ^ other.msb); }
    bit_plus& operator^=(const bit_plus& other)
        { lower ^= other.lower; msb ^= other.msb; return *this; }
    bit_plus operator&(const word& other)
        { return bit_plus(lower & other, false); }
    friend ostream& operator<<(ostream& s, const bit_plus& a)
        { s << a.msb << a.lower; return s; }
};

typedef bit_plus<int128> int129;


template<class T> class Input;
template<class T> class PrivateOutput;
template<class T> class SPDZ;
template<class T> class Share;
template<class T> class Square;

namespace GC
{
class NoValue;
}

/* This interface compatible with the gfp interface
 * which then allows us to template the Share
 * data type.
 */


/*
  Arithmetic in Gf_{2^n} with n<=128
*/

class gf2n_long : public gf2n_<int128>
{
  typedef gf2n_<int128> super;

  public:

  typedef gf2n_long value_type;
  typedef gf2n_long next;
  typedef ::Square<gf2n_long> Square;

  typedef gf2n_long Scalar;

  static int default_degree() { return 128; }

  static string type_string() { return "gf2n_long"; }
  word get_word() const { return this->a.get_lower(); }

  static gf2n_long cut(int128 x) { return x; }

  gf2n_long()              { assign_zero(); }
  gf2n_long(const super& g) : super(g) {}
  gf2n_long(const int128& g) : super(g) {}
  gf2n_long(int g) : gf2n_long(int128(unsigned(g))) {}
  gf2n_long(long g) : gf2n_long(int128(g)) {}
  gf2n_long(word g) : gf2n_long(int128(g)) {}
  template<class T>
  gf2n_long(IntBase<T> g) : super(g.get()) {}
  template<class T>
  gf2n_long(const gf2n_<T>& a) : super(int128(a.get())) {}
};

#if defined(__aarch64__) && defined(__clang__)
inline __m128i my_slli(int128 x, int i)
{
  if (i < 64)
    return int128(x.get_upper() << i, x.get_lower() << i).a;
  else
    return int128().a;
}

inline __m128i my_srli(int128 x, int i)
{
  if (i < 64)
    return int128(x.get_upper() >> i, x.get_lower() >> i).a;
  else
    return int128().a;
}

#undef _mm_slli_epi64
#undef _mm_srli_epi64
#define _mm_slli_epi64 my_slli
#define _mm_srli_epi64 my_srli
#endif

inline int128 int128::operator<<(const int& other) const
{
  int128 res(_mm_slli_epi64(a, other));
  __m128i mask;
  if (other < 64)
    mask = _mm_srli_epi64(a, 64 - other);
  else
    mask = _mm_slli_epi64(a, other - 64);
  res.a ^= _mm_slli_si128(mask, 8);
  return res;
}

inline int128 int128::operator>>(const int& other) const
{
  int128 res(_mm_srli_epi64(a, other));
  __m128i mask;
  if (other < 64)
    mask = _mm_slli_epi64(a, 64 - other);
  else
    mask = _mm_srli_epi64(a, other - 64);
  res.a ^= _mm_srli_si128(mask, 8);
  return res;
}

void mul(word x, word y, word& lo, word& hi);

inline __m128i software_clmul(__m128i a, __m128i b, int choice)
{
    word lo, hi;
    mul(int128(a).get_half(choice & 1),
            int128(b).get_half((choice & 0x10) >> 4), lo, hi);
    return int128(hi, lo).a;
}

template<int choice>
inline __m128i clmul(__m128i a, __m128i b)
{
#if defined(__PCLMUL__) || !defined(__x86_64__)
    if (cpu_has_pclmul())
    {
        return _mm_clmulepi64_si128(a, b, choice);
    }
    else
#endif
        return software_clmul(a, b, choice);
}

inline void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2)
{
    __m128i tmp3, tmp4, tmp5, tmp6;

    tmp3 = clmul<0x00>(a, b);
    tmp4 = clmul<0x10>(a, b);
    tmp5 = clmul<0x01>(a, b);
    tmp6 = clmul<0x11>(a, b);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // initial mul now in tmp3, tmp6
    *res1 = tmp3;
    *res2 = tmp6;
}

inline void mul(int128 a, int128 b, int128& lo, int128& hi)
{
    mul128(a.a, b.a, &lo.a, &hi.a);
}

inline bool int128::get_bit(int i) const
{
    if (i < 64)
        return (get_lower() >> i) & 1;
    else
        return (get_upper() >> (i - 64)) & 1;
}

#endif /* MATH_GF2NLONG_H_ */
