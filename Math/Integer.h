/*
 * Integer.h
 *
 */

#ifndef INTEGER_H_
#define INTEGER_H_

#include <iostream>
using namespace std;

#include "Tools/octetStream.h"
#include "Tools/random.h"
#include "bigint.h"
#include "field_types.h"
#include "Z2k.h"
#include "ValueInterface.h"
#include "gf2nlong.h"

// Fix false warning
#if __GNUC__ == 10
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif

// Functionality shared between integers and bit vectors
template<class T>
class IntBase : public ValueInterface
{
protected:
  T a;

public:
  static const int N_BYTES = sizeof(a);
  static const int N_BITS = 8 * sizeof(a);
  static const int MAX_N_BITS = N_BITS;

  static int size() { return sizeof(a); }
  static int size_in_bits() { return N_BITS; }
  static int length() { return N_BITS; }
  static string type_string() { return "integer"; }

  static void specification(octetStream& os);

  static bool allows(Dtype type) { return type <= DATA_BIT; }

  static void check_setup(const string&) {}

  IntBase()                 { a = 0; }
  IntBase(T a) : a(a)    {}

  T get() const          { return a; }
  bool get_bit(int i) const { return (a >> i) & 1; }

  char* get_ptr() const     { return (char*)&a; }

  unsigned long debug() const { return a; }

  void assign(long x)       { *this = x; }
  void assign(const void* buffer) { avx_memcpy(&a, buffer, sizeof(a)); }
  void assign_zero()        { a = 0; }
  void assign_one()         { a = 1; }

  bool is_zero() const      { return a == 0; }
  bool is_one() const       { return a == 1; }
  bool is_bit() const       { return is_zero() or is_one(); }

  long operator>>(const IntBase<long>& other) const
  {
    if (other.get() < N_BITS)
      return (unsigned long) a >> other.get();
    else
      return 0;
  }
  long operator<<(const IntBase<long>& other) const
  {
    if (other.get() < N_BITS)
      return a << other.get();
    else
      return 0;
  }

  long operator^(const IntBase& other) const { return a ^ other.a; }
  long operator&(const IntBase& other) const { return a & other.a; }
  long operator|(const IntBase& other) const { return a | other.a; }

  bool operator==(const IntBase& other) const { return a == other.a; }
  bool operator!=(const IntBase& other) const { return a != other.a; }

  bool equal(const IntBase& other) const { return *this == other; }

  T& operator^=(const IntBase& other) { return a ^= other.a; }
  T& operator&=(const IntBase& other) { return a &= other.a; }

  IntBase mask(int n) const
  {
    return n < N_BITS and n > 0 ? *this & ((1L << n) - 1) : *this;
  }
  void mask(IntBase& res, int n) const { res = mask(n); }

  friend ostream& operator<<(ostream& s, const IntBase& x) { x.output(s, true); return s; }
  friend istream& operator>>(istream& s, IntBase& x) { x.input(s, true); return s; }

  void randomize(PRNG& G);
  void almost_randomize(PRNG& G) { randomize(G); }

  void output(ostream& s, bool human, bool signed_ = true) const;
  void input(istream& s,bool human);

  void pack(octetStream& os) const { os.store_int(a, sizeof(a)); }
  void unpack(octetStream& os) { a = os.get_int(sizeof(a)); }
};

// Wrapper class for integer
class Integer : public IntBase<long>
{
  public:

  typedef Integer value_type;
  typedef Integer clear;

  static char type_char() { return 'R'; }
  static DataFieldType field_type() { return DATA_INT; }

  static void reqbl(int n);

  static const bool invertible = false;

  template<int X, int L>
  static Integer convert_unsigned(const gfp_<X, L>& other);
  template<int K>
  static Integer convert_unsigned(const Z2<K>& other);

  Integer()                 { a = 0; }
  Integer(long a) : IntBase(a) {}
  Integer(const bigint& x)  { *this = (x > 0) ? x.get_ui() : -x.get_ui(); }
  template<int K>
  Integer(const Z2<K>& x) : Integer(x.get_limb(0)) {}
  template<int K>
  Integer(const SignedZ2<K>& x);
  template<int X, int L>
  Integer(const gfp_<X, L>& x);
  Integer(int128 x) : Integer(x.get_lower()) {}
  template<class T>
  Integer(const IntBase<T>& x) : Integer(x.get()) {}
  template<class T>
  Integer(const gf2n_<T>& x) : Integer(x.get()) {}

  Integer(const Integer& x, int n_bits);

  void convert_destroy(bigint& other) { *this = other.get_si(); }

  long operator+(const Integer& other) const { return a + other.a; }
  long operator-(const Integer& other) const { return a - other.a; }
  long operator*(const Integer& other) const { return a * other.a; }
  long operator/(const Integer& other) const { return a / other.a; }

  bool operator<(const Integer& other) const { return a < other.a; }
  bool operator<=(const Integer& other) const { return a <= other.a; }
  bool operator>(const Integer& other) const { return a > other.a; }
  bool operator>=(const Integer& other) const { return a >= other.a; }

  long operator+=(const Integer& other) { return a += other.a; }

  friend unsigned int& operator+=(unsigned int& x, const Integer& other) { return x += other.a; }

  long operator-() const { return -a; }
};

inline string to_string(const Integer& x)
{
  return to_string(x.get());
}

template<>
inline void IntBase<long>::randomize(PRNG& G)
{
  a = G.get_word();
}

template<>
inline void IntBase<bool>::randomize(PRNG& G)
{
  a = G.get_bit();
}

template<>
inline void IntBase<unsigned char>::randomize(PRNG& G)
{
  a = G.get_uchar();
}

template<int X, int L>
Integer::Integer(const gfp_<X, L>& x)
{
  to_signed_bigint(bigint::tmp, x);
  *this = bigint::tmp;
}

template<int X, int L>
Integer Integer::convert_unsigned(const gfp_<X, L>& other)
{
  to_bigint(bigint::tmp, other);
  return bigint::tmp;
}

template<int K>
Integer Integer::convert_unsigned(const Z2<K>& other)
{
  return other;
}

// slight misnomer
inline void to_gfp(Integer& res, const bigint& x)
{
  res = x.get_si();
}

#include "Integer.hpp"

#endif /* INTEGER_H_ */
