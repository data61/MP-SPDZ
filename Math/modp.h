#ifndef _Modp
#define _Modp

/* 
 * Currently we only support an GMP based implementation.
 *
 * What ever is type-def'd to bigint is assumed to have
 * operator overloading for all standard operators, has
 * comparison operations and istream/ostream operators >>/<<.
 *
 * All "integer" operations will be done using operator notation
 * all "modp" operations should be done using the function calls
 * below (interchange with Montgomery arithmetic).
 *
 */

#include "Tools/octetStream.h"
#include "Tools/random.h"

#include "Math/bigint.h"
#include "Math/Zp_Data.h"

template<int L>
class modp_
{ 
  mp_limb_t x[L];

  public: 

  static const int MAX_N_BITS = 64 * L;
  static const int N_LIMBS = L;

  // NEXT FUNCTION IS FOR DEBUG PURPOSES ONLY
  mp_limb_t get_limb(int i) const { return x[i]; }

  // use mem* functions instead of mpn_*, so the compiler can optimize
  modp_()
    { avx_memzero(x, sizeof(x)); }
  
  template<int M>
  modp_(const modp_<M>& other)
    {
      inline_mpn_copyi(x, other.get(), min(L, M));
      if (L > M)
        inline_mpn_zero(x + M, L - M);
    }

  template<int X, int M>
  modp_(const gfp_<X, M>& other, const Zp_Data& ZpD) :
      modp_()
    {
      assert(other.get_ZpD() == ZpD);
      assert(M <= L);
      inline_mpn_copyi(x, other.get().get(), M);
    }

  template<int X, int M>
  modp_(const gfpvar_<X, M>& other, const Zp_Data& ZpD) :
      modp_()
    {
      if (other.get_ZpD() == ZpD)
        *this = other.get();
      else
        to_modp(*this, bigint(other), ZpD);
    }

  const mp_limb_t* get() const { return x; }

  void assign(const void* buffer, int t) { memcpy(x, buffer, t * sizeof(mp_limb_t)); }

  void convert(const mp_limb_t* source, mp_size_t size, const Zp_Data& ZpD,
      bool negative = false);
  void convert_destroy(bigint& source, const Zp_Data& ZpD);
  void convert_destroy(int source, const Zp_Data& ZpD) { to_modp(*this, source, ZpD); }
  template<int M>
  void convert_destroy(const fixint<M>& source, const Zp_Data& ZpD);

  void zero_overhang(const Zp_Data& ZpD);

  void randomize(PRNG& G, const Zp_Data& ZpD);

  // Pack and unpack in native format
  //   i.e. Dont care about conversion to human readable form
  //   i.e. When we do montgomery we dont care about decoding
  void pack(octetStream& o,const Zp_Data& ZpD) const;
  void unpack(octetStream& o,const Zp_Data& ZpD);

  template<int LL = L * sizeof(mp_limb_t)>
  void pack(octetStream& o) const;
  template<int LL = L * sizeof(mp_limb_t)>
  void unpack(octetStream& o);

  bool operator==(const modp_& other) const { return 0 == mpn_cmp(x, other.x, L); }
  bool operator!=(const modp_& other) const { return not (*this == other); }


   /**********************************
    *         Modp Operations        *
    **********************************/

  // Convert representation to and from a modp number
  void to_bigint(bigint& ans,const Zp_Data& ZpD,bool reduce=true) const;
  template<int M>
  void to_bigint(bigint& ans,const Zp_Data& ZpD,bool reduce=true) const;

  template<int T>
  void mul(const modp_& x, const modp_& y, const Zp_Data& ZpD);

  template<int M> friend void to_modp(modp_<M>& ans,int x,const Zp_Data& ZpD);
  template<int M> friend void to_modp(modp_<M>& ans,const mpz_class& x,const Zp_Data& ZpD);

  modp_ add(const modp_& other, const Zp_Data& ZpD) const;
  modp_ sub(const modp_& other, const Zp_Data& ZpD) const;
  modp_ mul(const modp_& other, const Zp_Data& ZpD) const;

  friend void Add(modp_& ans,const modp_& x,const modp_& y,const Zp_Data& ZpD)
    { ZpD.Add(ans.x, x.x, y.x); }
  template<int M> friend void Sub(modp_<M>& ans,const modp_<M>& x,const modp_<M>& y,const Zp_Data& ZpD);
  template<int M> friend void Mul(modp_<M>& ans,const modp_<M>& x,const modp_<M>& y,const Zp_Data& ZpD);
  template<int M> friend void Sqr(modp_<M>& ans,const modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend void Negate(modp_<M>& ans,const modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend void Inv(modp_<M>& ans,const modp_<M>& x,const Zp_Data& ZpD);
   
  template<int M> friend void Power(modp_<M>& ans,const modp_<M>& x,int exp,const Zp_Data& ZpD);
  template<int M> friend void Power(modp_<M>& ans,const modp_<M>& x,const bigint& exp,const Zp_Data& ZpD);
   
  template<int M> friend void assignOne(modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend void assignZero(modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend bool isZero(const modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend bool isOne(const modp_<M>& x,const Zp_Data& ZpD);
  template<int M> friend bool areEqual(const modp_<M>& x,const modp_<M>& y,const Zp_Data& ZpD);

  // Input and output from a stream
  //  - Can do in human or machine only format (later should be faster)
  //  - If human output appends a space to help with reading
  //    and also convert back/forth from Montgomery if needed
  void output(ostream& s, const Zp_Data& ZpD, bool human, bool signed_ = false) const;
  void input(istream& s,const Zp_Data& ZpD,bool human);

  template<int X, int K>
  friend class gfp_;
};

typedef modp_<MAX_MOD_SZ> modp;

template<int L>
inline void modp_<L>::pack(octetStream& o,const Zp_Data& ZpD) const
{
  o.append((octet*) x,ZpD.t*sizeof(mp_limb_t));
}

template<int L>
void assignZero(modp_<L>& x,const Zp_Data& ZpD)
{
  if (sizeof(x.x) <= 3 * 16 or ZpD.pr_byte_length == 0)
    // use memset to allow the compiler to optimize
    // if x.x is at most 3*128 bits
    avx_memzero(x.x, sizeof(x.x));
  else
    inline_mpn_zero(x.x, ZpD.get_t());
}

template<int L>
inline void Sub(modp_<L>& ans,const modp_<L>& x,const modp_<L>& y,const Zp_Data& ZpD)
{
  ZpD.Sub(ans.x, x.x, y.x);
}

template<int L>
inline void Mul(modp_<L>& ans,const modp_<L>& x,const modp_<L>& y,const Zp_Data& ZpD)
{
  if (ZpD.montgomery)
    { ZpD.Mont_Mult_max(ans.x,x.x,y.x,L); }
  else
    { //ans.x=(x.x*y.x)%ZpD.pr;
      mp_limb_t aa[2*L],q[2*L];
      mpn_mul_n(aa,x.x,y.x,ZpD.t);
      mpn_tdiv_qr(q,ans.x,0,aa,2*ZpD.t,ZpD.prA,ZpD.t);
    }
}

template<int L>
template<int T>
inline void modp_<L>::mul(const modp_<L>& x, const modp_<L>& y, const Zp_Data& ZpD)
{
  if (ZpD.montgomery)
    ZpD.Mont_Mult_<T>(this->x, x.x, y.x);
  else
    Mul<L>(*this, x, y, ZpD);
}

template<int L>
void to_bigint(bigint& ans,const modp_<L>& x,const Zp_Data& ZpD,bool reduce=true)
{
  x.to_bigint(ans, ZpD, reduce);
}

#endif

