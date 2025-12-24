#ifndef MATH_MODP_HPP_
#define MATH_MODP_HPP_

#include "Zp_Data.h"
#include "modp.h"
#include "Z2k.hpp"
#include "gfpvar.h"

#include "Tools/Exceptions.h"

/***********************************************************************
 *  The following functions remain the same in Real and Montgomery rep *
 ***********************************************************************/

template<int L>
modp_<L> modp_<L>::add(const modp_& other, const Zp_Data& ZpD) const
{
  modp_ res;
  Add(res, *this, other, ZpD);
  return res;
}

template<int L>
modp_<L> modp_<L>::sub(const modp_& other, const Zp_Data& ZpD) const
{
  modp_ res;
  Sub(res, *this, other, ZpD);
  return res;
}

template<int L>
modp_<L> modp_<L>::mul(const modp_& other, const Zp_Data& ZpD) const
{
  modp_ res;
  Mul(res, *this, other, ZpD);
  return res;
}

template<int L>
void modp_<L>::randomize(PRNG& G, const Zp_Data& ZpD)
{
  const int M = sizeof(mp_limb_t) * L;
  switch (ZpD.pr_byte_length)
  {
#define X(LL) case LL: G.randomBnd<LL>(x, ZpD.get_prA(), ZpD.overhang_mask()); break;
  X(M) X(M-1) X(M-2) X(M-3) X(M-4) X(M-5) X(M-6) X(M-7)
#undef X
  default:
    G.randomBnd(x, ZpD.get_prA(), ZpD.pr_byte_length, ZpD.overhang_mask());
  }
}

template<int L>
void modp_<L>::unpack(octetStream& o,const Zp_Data& ZpD)
{
  o.consume((octet*) x,ZpD.t*sizeof(mp_limb_t));
}

template<int L>
void modp_<L>::unpack(octetStream& o)
{
  o.consume((octet*) x,L*sizeof(mp_limb_t));
}

template<int L>
void modp_<L>::pack(octetStream& o) const
{
  o.append((octet*) x,L*sizeof(mp_limb_t));
}

template<int L>
void Negate(modp_<L>& ans,const modp_<L>& x,const Zp_Data& ZpD)
{ 
  if (isZero(x,ZpD)) { ans=x; return; }
  mpn_sub_n(ans.x,ZpD.prA,x.x,ZpD.t); 
}


template<int L>
bool areEqual(const modp_<L>& x,const modp_<L>& y,const Zp_Data& ZpD)
{ if (mpn_cmp(x.x,y.x,ZpD.t)!=0)
    { return false; }
  return true;
}

template<int L>
bool isZero(const modp_<L>& ans,const Zp_Data& ZpD)
{
  for (int i=0; i<ZpD.t; i++)
    { if (ans.x[i]!=0) { return false; } }
  return true;
}



/***********************************************************************
 *  All the remaining functions have Montgomery variants which we need *
 *  to deal with                                                       *
 ***********************************************************************/


template<int L>
void assignOne(modp_<L>& x,const Zp_Data& ZpD)
{ if (ZpD.montgomery)
    { mpn_copyi(x.x,ZpD.R,ZpD.get_t()); }
  else
    { assignZero(x,ZpD); 
      x.x[0]=1; 
    }
}


template<int L>
bool isOne(const modp_<L>& x,const Zp_Data& ZpD)
{ if (ZpD.montgomery)
    { if (mpn_cmp(x.x,ZpD.R,ZpD.t)!=0)
        { return false; }
    }
  else
    { if (x.x[0]!=1) { return false; }
      for (int i=1; i<min(ZpD.t, L); i++)
	{ if (x.x[i]!=0) { return false; } }
    }
  return true;
}



template<int L>
void modp_<L>::to_bigint(bigint& ans,const Zp_Data& ZpD,bool reduce) const
{ 
  auto& x = *this;
  mpz_ptr a = ans.get_mpz_t();
  if (a->_mp_alloc < ZpD.t)
      mpz_realloc(a, ZpD.t);
  if (ZpD.montgomery)
    {
      mp_limb_t one[MAX_MOD_SZ];
      inline_mpn_zero(one,L);
      one[0]=1;
      ZpD.Mont_Mult(a->_mp_d,x.x,one);
    }
  else
    { inline_mpn_copyi(a->_mp_d,x.x,ZpD.t); }
  a->_mp_size=ZpD.t;
  if (reduce)
    while (a->_mp_size>=1 && (a->_mp_d)[a->_mp_size-1]==0)
      { a->_mp_size--; }
}


template<int L>
template<int M>
void modp_<L>::to_bigint(bigint& ans,const Zp_Data& ZpD,bool reduce) const
{
  assert(M == ZpD.t);
  auto& x = *this;
  mpz_ptr a = ans.get_mpz_t();
  if (a->_mp_alloc < M)
      mpz_realloc(a, M);
  if (ZpD.montgomery)
    {
      mp_limb_t one[M];
      inline_mpn_zero(one,M);
      one[0]=1;
      ZpD.Mont_Mult_<M>(a->_mp_d,x.x,one);
    }
  else
    { inline_mpn_copyi(a->_mp_d,x.x,M); }
  a->_mp_size=M;
  if (reduce)
    while (a->_mp_size>=1 && (a->_mp_d)[a->_mp_size-1]==0)
      { a->_mp_size--; }
}


template<int L>
void to_modp(modp_<L>& ans,int x,const Zp_Data& ZpD)
{
  inline_mpn_zero(ans.x,ZpD.get_t());
  if (x>=0)
    { ans.x[0]=x;
      if (ZpD.t==1) { ans.x[0]=ans.x[0]%ZpD.prA[0]; }
    }
  else
    { if (ZpD.t==1)
	{ ans.x[0]=(ZpD.prA[0]+x)%ZpD.prA[0]; }
      else
        { bigint& xx = bigint::tmp = ZpD.pr+x;
          to_modp(ans,xx,ZpD);
          return;
        }
    }
  if (ZpD.montgomery)
    { ZpD.Mont_Mult(ans.x,ans.x,ZpD.R2); }
}


template<int L>
void to_modp(modp_<L>& ans,const mpz_class& x,const Zp_Data& ZpD)
{
  if (x == 0)
  {
    assignZero(ans, ZpD);
    return;
  }
  else if (x == 1)
  {
    assignOne(ans, ZpD);
    return;
  }
  bigint::tmp = x;
  ans.convert_destroy(bigint::tmp, ZpD);
}


template<int L>
void modp_<L>::convert_destroy(bigint& xx,
    const Zp_Data& ZpD)
{
  xx %= ZpD.pr;
  //mpz_mod(xx.get_mpz_t(),x.get_mpz_t(),ZpD.pr.get_mpz_t());
  convert(xx.get_mpz_t()->_mp_d, abs(xx.get_mpz_t()->_mp_size), ZpD, xx < 0);
}

template<int L>
template<int M>
void modp_<L>::convert_destroy(const fixint<M>& xx,
    const Zp_Data& ZpD)
{
  assert(xx.size_in_limbs() <= L);
  SignedZ2<64 * L> tmp = xx;
  if (xx.negative())
    tmp += ZpD.pr;
  convert(tmp.get(), ZpD.get_t(), ZpD, false);
}

template<int L>
void modp_<L>::convert(const mp_limb_t* source, mp_size_t size, const Zp_Data& ZpD, bool negative)
{
  assert(size <= ZpD.get_t());
  if (negative)
    mpn_sub(x, ZpD.prA, ZpD.t, source, size);
  else
    {
      inline_mpn_zero(x + size, ZpD.t - size);
      inline_mpn_copyi(x, source, size);
    }
  if (ZpD.montgomery)
    ZpD.Mont_Mult(x, x, ZpD.R2);
}

template<int L>
void modp_<L>::zero_overhang(const Zp_Data& ZpD)
{
  x[ZpD.get_t() - 1] &= ZpD.overhang_mask();
}



template<int L>
void Sqr(modp_<L>& ans,const modp_<L>& x,const Zp_Data& ZpD)
{ 
  if (ZpD.montgomery)
    { ZpD.Mont_Mult(ans.x,x.x,x.x); }
  else
    { //ans.x=(x.x*x.x)%ZpD.pr;
      mp_limb_t aa[2*L],q[2*L];
      mpn_sqr(aa,x.x,ZpD.t);
      mpn_tdiv_qr(q,ans.x,0,aa,2*ZpD.t,ZpD.prA,ZpD.t);     
    }
}


template<int L>
void Inv(modp_<L>& ans,const modp_<L>& x,const Zp_Data& ZpD)
{ 
  mp_limb_t g[L],xx[L],yy[L];
  mp_size_t sz;
  mpn_copyi(xx,x.x,ZpD.t);
  mpn_copyi(yy,ZpD.prA,ZpD.t);
  mpn_gcdext(g,ans.x,&sz,xx,ZpD.t,yy,ZpD.t);
  if (sz<0)
    {
      assert(-sz <= L);
      mpn_sub(ans.x,ZpD.prA,ZpD.t,ans.x,-sz);
      sz=-sz;
    }
  else
    { for (int i=sz; i<ZpD.t; i++) { ans.x[i]=0; } }
  if (ZpD.montgomery)
    { ZpD.Mont_Mult_max(ans.x,ans.x,ZpD.R3,L); }
}


template<int L>
void Power(modp_<L>& ans,const modp_<L>& x,int exp,const Zp_Data& ZpD)
{
  if (exp==1) { ans=x; return; }
  if (exp==0) { assignOne(ans,ZpD); return; }
  if (exp<0)  { throw not_implemented(); }
  modp_<L> t=x;
  assignOne(ans,ZpD);
  while (exp!=0)
    { if ((exp&1)==1) { Mul(ans,ans,t,ZpD); }
      exp>>=1;
      Sqr(t,t,ZpD);
    }
}


template<int L>
void Power(modp_<L>& ans,const modp_<L>& x,const bigint& exp,const Zp_Data& ZpD)
{
  if (exp==1) { ans=x; return; }
  if (exp==0) { assignOne(ans,ZpD); return; }
  if (exp<0)  { throw not_implemented();  }
  modp t=x;
  assignOne(ans,ZpD);
  bigint& e = bigint::tmp = exp;
  while (e!=0)
     { if ((e&1)==1) { Mul(ans,ans,t,ZpD); }
       e>>=1;
       Sqr(t,t,ZpD);
     }
}


template<int L>
void modp_<L>::output(ostream& s, const Zp_Data& ZpD, bool human, bool signed_) const
{
  if (human)
    { bigint te;
      to_bigint(te, ZpD);
      if (te <= ZpD.pr_half or not signed_)
          s << te;
      else
          s << (te - ZpD.pr);
    }
  else
    { s.write((char*) x,ZpD.t*sizeof(mp_limb_t)); }
}

template<int L>
void modp_<L>::input(istream& s,const Zp_Data& ZpD,bool human)
{
  if (s.peek() == EOF)
    { if (s.tellg() == 0)
        { cout << "IO problem. Empty file?" << endl;
          throw file_error("modp input");
        }
      throw end_of_file("modp");
    }

  if (human)
    { bigint te;
      s >> te;
      to_modp(*this,te,ZpD);
    }
  else
    { s.read((char*) x,ZpD.t*sizeof(mp_limb_t)); }
}

#endif
