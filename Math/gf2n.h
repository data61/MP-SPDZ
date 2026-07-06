#ifndef _gf2n
#define _gf2n

#include <stdlib.h>
#include <string.h>

#include <iostream>
using namespace std;

#include "Tools/random.h"

#include "Math/field_types.h"
#include "Math/bigint.h"
#include "Math/ValueInterface.h"

class gf2n_short;
class P2Data;
class Bit;
class int128;
template<class T> class IntBase;
template<class T> class Square;
typedef Square<gf2n_short> gf2n_short_square;

void expand_byte(gf2n_short& a,int b);
void collapse_byte(int& b,const gf2n_short& a);

/* This interface compatible with the gfp interface
 * which then allows us to template the Share
 * data type.
 */


/* 
  Arithmetic in Gf_{2^n} with n<64
*/

template<class U>
class gf2n_ : public ValueInterface
{
protected:
  friend class gf2n_long;

  U a;

  static int n, nterms;
  static int t[4], l[4];
  static U mask;
  static U uppermask, lowermask;
  static bool useC;

  static octet mult_table[256][256];

  static void init_tables();
  static void init_multiplication();

  template<class T>
  T invert(T a) const;

  public:

  typedef U internal_type;
  typedef gf2n_ Scalar;

  static const int N_BYTES = sizeof(a);
  static const int MAX_N_BITS = 8 * N_BYTES;

  static void init_field(int nn = 0);
  static void init_default(int, bool = false) { init_field(); }
  static void init_minimum(int lower);

  static void reset() { n = 0; }
  static int degree() { return n; }
  static int get_nterms() { return nterms; }
  static int get_t(int i) { return (i < 3) ? t[i + 1] : -1; }

  static DataFieldType field_type() { return DATA_GF2N; }
  static char type_char() { return '2'; }
  static string type_short() { return "2"; }
  static string type_string() { return "gf2n_"; }

  static void specification(octetStream& os);

  static int size() { return sizeof(a); }
  static int size_in_bits() { return sizeof(a) * 8; }

  static int length()         { return n == 0 ? MAX_N_BITS : n; }

  static bool allows(Dtype type) { return type <= DATA_INVERSE; }

  static string options();

  static string fake_opts() { return " -lg2 " + to_string(length()); }

  static void check_setup(string) {}

  static const true_type invertible;
  static const true_type characteristic_two;
  static const true_type optimized_packing;

  static gf2n_ Mul(gf2n_ a, gf2n_ b) { return a * b; }

  U get() const { return a; }

  const void* get_ptr() const { return &a; }

  void assign_zero()             { a=0; }
  void assign_one()              { a=1; } 
  void assign_x()                { a=2; }
  void assign(const void* aa)    { memcpy(&a, aa, sizeof(a)); }

  void normalize()               { a &= mask; }

  /* Assign x[0..2*nwords] to a and reduce it...  */
  void reduce(U xh, U xl);

  int get_bit(int i) const
    { return ((a>>i)&1) != 0; }
  void set_bit(int i,unsigned int b)
  { if (b==1)
      { a |= (1UL<<i); }
    else
      { a &= ~(1UL<<i); }
  }
  
  gf2n_() : a(0)       {}
  gf2n_(bool a) : a(a) {}
  gf2n_(U a) : a(a & mask) {}
  gf2n_(long a) : gf2n_(U(a)) {}
  gf2n_(int a) : gf2n_(U(unsigned(a))) {}
  gf2n_(long long a) : gf2n_(U(a)) {}
  template<class T>
  gf2n_(IntBase<T> a) : a(a.get()) {}

  gf2n_(PRNG& G);

  int is_zero() const            { return (a==0); }
  int is_one()  const            { return (a==1); }
  bool operator==(const gf2n_& y) const { return a==y.a; }
  bool operator!=(const gf2n_& y) const { return a!=y.a; }

  // x+y
  void add(const gf2n_& x,const gf2n_& y)
    { a=x.a^y.a; }  
  void sub(const gf2n_& x,const gf2n_& y)
    { a=x.a^y.a; }
  // = x * y
  gf2n_& mul(const gf2n_& x,const gf2n_& y);

  gf2n_ lazy_add(const gf2n_& x) const { return *this + x; }
  gf2n_ lazy_mul(const gf2n_& x) const { return *this * x; }

  gf2n_ operator+(const gf2n_& x) const { gf2n_ res; res.add(*this, x); return res; }
  gf2n_ operator*(const gf2n_& x) const { gf2n_ res; res.mul(*this, x); return res; }
  gf2n_& operator+=(const gf2n_& x) { add(*this, x); return *this; }
  gf2n_& operator*=(const gf2n_& x) { mul(*this, x); return *this; }
  gf2n_ operator-(const gf2n_& x) const { gf2n_ res; res.add(*this, x); return res; }
  gf2n_& operator-=(const gf2n_& x) { sub(*this, x); return *this; }
  gf2n_ operator/(const gf2n_& x) const { return *this * x.invert(); }

  gf2n_ operator*(const Bit& x) const;
  gf2n_ operator*(int x) const { return *this * gf2n_(x); }

  gf2n_ invert() const;

  gf2n_ operator-() const { return *this; }
  void negate() { return; }

  /* Bitwise Ops */
  gf2n_ operator&(const gf2n_& x) const { return a & x.a; }
  gf2n_ operator^(const gf2n_& x) const { return a ^ x.a; }
  gf2n_ operator|(const gf2n_& x) const { return a | x.a; }
  gf2n_ operator~() const { return ~a; }
  gf2n_ operator<<(int i) const;
  gf2n_ operator>>(int i) const;

  gf2n_& operator&=(const gf2n_& x) { *this = *this & x; return *this; }
  gf2n_& operator^=(const gf2n_& x) { *this = *this ^ x; return *this; }
  gf2n_& operator>>=(int i) { *this = *this >> i; return *this; }
  gf2n_& operator<<=(int i) { *this = *this << i; return *this; }

  /* Crap RNG */
  void randomize(PRNG& G, int n = -1);
  // compatibility with gfp
  void almost_randomize(PRNG& G)        { randomize(G); }

  void force_to_bit() { a &= 1; }

  void output(ostream& s,bool human) const;
  void input(istream& s,bool human);

  friend ostream& operator<<(ostream& s,const gf2n_& x)
    {
      x.output(s, true);
      return s;
    }
  friend istream& operator>>(istream& s,gf2n_& x)
    {
      x.input(s, true);
      return s;
    }


  // Pack and unpack in native format
  //   i.e. Dont care about conversion to human readable form
  template<int LL = sizeof(U)>
  void pack(octetStream& o, int n = -1) const
    { (void) n; o.append((octet*) &a, LL); }
  template<int LL = sizeof(U)>
  void unpack(octetStream& o, int n = -1)
    { (void) n; o.consume((octet*) &a, LL); }
};

class gf2n_short : public gf2n_<word>
{
  typedef gf2n_<word> super;

public:
  typedef gf2n_short value_type;
  typedef gf2n_short next;
  typedef ::Square<gf2n_short> Square;
  typedef P2Data FD;
  typedef gf2n_short Scalar;

  static const int DEFAULT_LENGTH = 40;

  static int length()         { return n == 0 ? DEFAULT_LENGTH : n; }
  static int default_degree() { return DEFAULT_LENGTH; }

  static void init_field(int nn = 0);

  static gf2n_short cut(int128 x);

  gf2n_short() {}
  template<class T>
  gf2n_short(const T& other) : super(other) {}
  gf2n_short(const int128& a);

  word get_word() const { return a; }
};

#include "gf2nlong.h"

class gf2n_long;

#ifdef USE_GF2N_LONG
typedef gf2n_long gf2n;
#else
typedef gf2n_short gf2n;
#endif

template<class U>
const true_type gf2n_<U>::characteristic_two;
template<class U>
const true_type gf2n_<U>::invertible;
template<class U>
const true_type gf2n_<U>::optimized_packing;

template<class U>
int gf2n_<U>::n = 0;
template<class U>
U gf2n_<U>::mask;
template<class U>
int gf2n_<U>::nterms;
template<class U>
int gf2n_<U>::t[4];

template<class U>
U gf2n_<U>::uppermask;
template<class U>
U gf2n_<U>::lowermask;

template<class U>
octet gf2n_<U>::mult_table[256][256];

template<>
inline gf2n_<octet>& gf2n_<octet>::mul(const gf2n_<octet>& x, const gf2n_<octet>& y)
{
  return *this = mult_table[octet(x.a)][octet(y.a)];
}

template<class U>
gf2n_<U>::gf2n_(PRNG& G)
{
  randomize(G);
}

#endif
