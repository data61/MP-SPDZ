#ifndef _bigint
#define _bigint

#include <iostream>
using namespace std;

#include <stddef.h>
#include <gmpxx.h>

#include "Tools/Exceptions.h"
#include "Tools/int.h"
#include "Tools/random.h"
#include "Tools/octetStream.h"
#include "Tools/avx_memcpy.h"
#include "Protocols/config.h"

enum ReportType
{
  CAPACITY,
  USED,
  MINIMAL,
  REPORT_TYPE_MAX
};

template<int X, int L>
class gfp_;
template<int X, int L>
class gfpvar_;
class gmp_random;
class Integer;
template<int K> class Z2;
template<int K> class SignedZ2;
template<int L> class fixint;

namespace GC
{
  class Clear;
}

/**
 * Type for arbitrarily large integers.
 * This is a sub-class of ``mpz_class`` from GMP. As such, it implements
 * all integers operations and input/output via C++ streams. In addition,
 * the ``get_ui()`` member function allows retrieving the least significant
 * 64 bits.
 */
class bigint : public mpz_class
{
public:
  static thread_local bigint tmp, tmp2;
  static thread_local gmp_random random;

  // workaround for GCC not always initializing thread_local variables
  static void init_thread() { tmp = 0; tmp2 = 0; }

  template<class T>
  static mpf_class get_float(T v, T p, T z, T s);
  template<class U, class T>
  static void output_float(U& o, const mpf_class& x, T nan);

  /// Initialize to zero.
  bigint() : mpz_class() {}
  template <class T>
  bigint(const T& x) : mpz_class(x) {}
  /// Convert to canonical representation as non-negative number.
  template<int X, int L>
  bigint(const gfp_<X, L>& x);
  /// Convert to canonical representation as non-negative number.
  template<int X, int L>
  bigint(const gfpvar_<X, L>& x);
  /// Convert to canonical representation as non-negative number.
  template <int K>
  bigint(const Z2<K>& x);
  /// Convert to canonical representation as non-negative number.
  template <int K>
  bigint(const SignedZ2<K>& x);
  template <int L>
  bigint(const fixint<L>& x);
  bigint(const Integer& x);
  bigint(const GC::Clear& x);
  bigint(const mp_limb_t* data, size_t n_limbs);

  template<class T>
  bigint& operator=(const T& x);
  template<int X, int L>
  bigint& operator=(const gfp_<X, L>& other);
  template<int X, int L>
  bigint& operator=(const gfpvar_<X, L>& other);
  template<int K>
  bigint& operator=(const Z2<K>& x);
  template<int K>
  bigint& operator=(const SignedZ2<K>& x);
  template <int L>
  bigint& operator=(const fixint<L>& x);
  bigint& operator=(const Integer& x);
  bigint& operator=(const GC::Clear& x);

  /// Convert to signed representation in :math:`[-p/2,p/2]`.
  template<int X, int L>
  bigint& from_signed(const gfp_<X, L>& other);
  template<class T>
  bigint& from_signed(const T& other);

  void allocate_slots(const bigint& x) { *this = x; }
  int get_min_alloc() { return get_mpz_t()->_mp_alloc; }

  void mul(const bigint& x, const bigint& y) { *this = x * y; }

#ifdef REALLOC_POLICE
  ~bigint() { lottery(); }
  void lottery();

  bigint& operator-=(const bigint& y)
  {
    if (rand() % 10000 == 0)
      if (get_mpz_t()->_mp_alloc < abs(y.get_mpz_t()->_mp_size) + 1)
        throw runtime_error("insufficient allocation");
    ((mpz_class&)*this) -= y;
    return *this;
  }
  bigint& operator+=(const bigint& y)
  {
    if (rand() % 10000 == 0)
      if (get_mpz_t()->_mp_alloc < abs(y.get_mpz_t()->_mp_size) + 1)
        throw runtime_error("insufficient allocation");
    ((mpz_class&)*this) += y;
    return *this;
  }
#endif

  int numBits() const
  { return mpz_sizeinbase(get_mpz_t(), 2); }

  void generateUniform(PRNG& G, int n_bits, bool positive = false)
  { G.get(*this, n_bits, positive); }

  void pack(octetStream& os, int = -1) const;
  void unpack(octetStream& os, int = -1);

  size_t report_size(ReportType type) const;
};


void inline_mpn_zero(mp_limb_t* x, mp_size_t size);
void inline_mpn_copyi(mp_limb_t* dest, const mp_limb_t* src, mp_size_t size);


template<class T>
inline bigint& bigint::operator=(const T& x)
{
  mpz_class::operator=(x);
  return *this;
}

template<int K>
bigint::bigint(const Z2<K>& x)
{
  *this = x;
}

template<int K>
bigint& bigint::operator=(const Z2<K>& x)
{
  mpz_import(get_mpz_t(), Z2<K>::N_WORDS, -1, sizeof(mp_limb_t), 0, 0, x.get_ptr());
  return *this;
}

template<int K>
bigint::bigint(const SignedZ2<K>& x)
{
  *this = x;
}

template<int K>
bigint& bigint::operator=(const SignedZ2<K>& x)
{
  mpz_import(get_mpz_t(), Z2<K>::N_WORDS, -1, sizeof(mp_limb_t), 0, 0, x.get_ptr());
  if (x.negative())
  {
    bigint::tmp2 = 1;
    bigint::tmp2 <<= K;
    *this -= bigint::tmp2;
  }
  return *this;
}

template<int X, int L>
bigint::bigint(const gfp_<X, L>& x)
{
  *this = x;
}

template<int X, int L>
bigint::bigint(const gfpvar_<X, L>& other)
{
  *this = other;
}

template<int X, int L>
bigint& bigint::operator=(const gfpvar_<X, L>& other)
{
  to_bigint(*this, other.get(), other.get_ZpD());
  return *this;
}

template<int X, int L>
bigint& bigint::operator=(const gfp_<X, L>& x)
{
  to_bigint(*this, x);
  return *this;
}

template<class T>
void to_bigint(bigint& res, const T& other)
{
  other.to(res);
}

template<class T>
void to_gfp(T& res, const bigint& a)
{
  res = a;
}

template<int L>
bigint::bigint(const fixint<L>& x)
{
  *this = x;
}

template<int L>
bigint& bigint::operator =(const fixint<L>& x)
{
  return *this = typename fixint<L>::super(x);
}

string to_string(const bigint& x);

/**********************************
 *       Utility Functions        *
 **********************************/

inline int gcd(const int x,const int y)
{
  bigint& xx = bigint::tmp = x;
  return mpz_gcd_ui(NULL,xx.get_mpz_t(),y);
}


inline bigint gcd(const bigint& x,const bigint& y)
{ 
  bigint g;
  mpz_gcd(g.get_mpz_t(),x.get_mpz_t(),y.get_mpz_t());
  return g;
}


inline void invMod(bigint& ans,const bigint& x,const bigint& p)
{
  mpz_invert(ans.get_mpz_t(),x.get_mpz_t(),p.get_mpz_t());
}

inline int numBits(const bigint& m)
{
  return m.numBits();
}



inline int numBits(long m)
{
  bigint& te = bigint::tmp = m;
  return mpz_sizeinbase(te.get_mpz_t(),2);
}



inline size_t numBytes(const bigint& m)
{
  return mpz_sizeinbase(m.get_mpz_t(),256);
}





inline int probPrime(const bigint& x)
{
  int ans = mpz_probab_prime_p(x.get_mpz_t(), max(40, DEFAULT_SECURITY) / 2);
  return ans;
}


inline void bigintFromBytes(bigint& x,octet* bytes,int len)
{
#ifdef REALLOC_POLICE
  if (rand() % 10000 == 0)
    if (x.get_mpz_t()->_mp_alloc < ((len + 7) / 8))
      throw runtime_error("insufficient allocation");
#endif
  mpz_import(x.get_mpz_t(),len,1,sizeof(octet),0,0,bytes);
}


inline void bytesFromBigint(octet* bytes,const bigint& x,unsigned int len)
{
  size_t ll = x == 0 ? 0 : numBytes(x);
  if (ll>len)
    { throw invalid_length(); }
  memset(bytes, 0, len - ll);
  size_t l;
  mpz_export(bytes + len - ll, &l, 1, sizeof(octet), 0, 0, x.get_mpz_t());
  assert(ll == l);
}


inline int isOdd(const bigint& x)
{
  return mpz_odd_p(x.get_mpz_t());
}


template<class T>
bigint sqrRootMod(const T& x);

bigint powerMod(const bigint& x,const bigint& e,const bigint& p);

// Assume e>=0
int powerMod(int x,int e,int p);

inline int Hwt(int N)
{
  int result=0;
  while(N)
    { result++;
      N&=(N-1);
    }
  return result;
}

template <class T>
int limb_size();

#endif

