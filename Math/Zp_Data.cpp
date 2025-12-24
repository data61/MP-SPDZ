
#include "Zp_Data.h"
#include "mpn_fixed.h"
#include "gf2nlong.h"


void Zp_Data::init(const bigint& p,bool mont)
{
  lock.lock();

  if (pr != 0)
    {
#ifdef VERBOSE
      if (pr != p)
        cerr << "Changing prime from " << pr << " to " << p << endl;
      if (mont != montgomery)
        cerr << "Changing Montgomery" << endl;
#endif
      if (pr != p or mont != montgomery)
        throw runtime_error("Zp_Data instance already initialized");
    }

  if (not probPrime(p))
    throw runtime_error(p.get_str() + " is not a prime");

  pr=p;
  pr_half = p / 2;
  mask=static_cast<mp_limb_t>(1ULL<<((mpz_sizeinbase(pr.get_mpz_t(),2)-1)%(8*sizeof(mp_limb_t))))-1;
  pr_byte_length = numBytes(pr);
  pr_bit_length = numBits(pr);
  int k = pr_bit_length;
  overhang = (uint64_t(-1LL) >> (63 - (k - 1) % 64));

  montgomery=mont;
  t=mpz_size(pr.get_mpz_t());
  if (t>MAX_MOD_SZ)
    throw max_mod_sz_too_small(t);
  if (montgomery)
    { inline_mpn_zero(R,MAX_MOD_SZ);
      inline_mpn_zero(R2,MAX_MOD_SZ);
      inline_mpn_zero(R3,MAX_MOD_SZ);
      bigint r=2,pp=pr;
      mpz_pow_ui(r.get_mpz_t(),r.get_mpz_t(),t*8*sizeof(mp_limb_t));
      mpz_invert(pp.get_mpz_t(),pr.get_mpz_t(),r.get_mpz_t());
      pp=r-pp;   // pi=-1/p mod R
      pi=(pp.get_mpz_t()->_mp_d)[0];
      
      r=r%pr;
      mpn_copyi(R,r.get_mpz_t()->_mp_d,mpz_size(r.get_mpz_t()));

      bigint r2=(r*r)%pr;
      mpn_copyi(R2,r2.get_mpz_t()->_mp_d,mpz_size(r2.get_mpz_t()));

      bigint r3=(r2*r)%pr;
      mpn_copyi(R3,r3.get_mpz_t()->_mp_d,mpz_size(r3.get_mpz_t()));

      if (sizeof(unsigned long)!=sizeof(mp_limb_t))
	{ cout << "The underlying types of GMP mean we cannot use our Montgomery code" << endl;
          throw not_implemented();
        }
    }
  inline_mpn_zero(prA,MAX_MOD_SZ+1);
  mpn_copyi(prA,pr.get_mpz_t()->_mp_d,t);

  lock.unlock();
}


#include <stdlib.h>

void Zp_Data::Mont_Mult(mp_limb_t* z,const mp_limb_t* x,const mp_limb_t* y,int t) const
{
  mp_limb_t ans[2 * MAX_MOD_SZ + 1], u, yy[MAX_MOD_SZ + 1];
  inline_mpn_copyi(yy, y, t);
  yy[t] = 0;
  // First loop
  u=x[0]*y[0]*pi;
  ans[t]  = mpn_mul_1(ans,y,t,x[0]);
  ans[t+1] = mpn_addmul_1(ans,prA,t+1,u);
  for (int i=1; i<t; i++)
    { // u=(ans0+xi*y0)*pd
      u=(ans[i]+x[i]*y[0])*pi;
      // ans=ans+xi*y+u*pr
      ans[t+i+1]=mpn_addmul_1(ans+i,yy,t+1,x[i]);
      ans[t+i+1]+=mpn_addmul_1(ans+i,prA,t+1,u);
    }
  // if (ans>=pr) { ans=z-pr; }
  // else         { z=ans;    }
  if (mpn_cmp(ans+t,prA,t+1)>=0)
     { mpn_sub_n(z,ans+t,prA,t); }
  else
     { inline_mpn_copyi(z,ans+t,t); }
}

void Zp_Data::Mont_Mult_switch(mp_limb_t* z, const mp_limb_t* x,
        const mp_limb_t* y) const
{
  switch (t)
  {
#ifdef __BMI2__
#define CASE(N) \
  case N: \
    Mont_Mult_<N>(z, x, y); \
    break;
  CASE(1)
  CASE(2)
#if MAX_MOD_SZ >= 4
  CASE(3)
  CASE(4)
#endif
#if MAX_MOD_SZ >= 5
  CASE(5)
#endif
#if MAX_MOD_SZ >= 6
  CASE(6)
#endif
#if MAX_MOD_SZ >= 10
  CASE(7)
  CASE(8)
  CASE(9)
  CASE(10)
#endif
#undef CASE
#endif
  default:
    Mont_Mult_variable(z, x, y);
    break;
  }
}



ostream& operator<<(ostream& s,const Zp_Data& ZpD)
{
  s << ZpD.pr << " " << ZpD.montgomery << endl;
  if (ZpD.montgomery)
    { s << ZpD.t << " " << ZpD.pi << endl;
      for (int i=0; i<ZpD.t; i++) { s << ZpD.R[i] << " "; }
      s << endl;
      for (int i=0; i<ZpD.t; i++) { s << ZpD.R2[i] << " "; }
      s << endl;
      for (int i=0; i<ZpD.t; i++) { s << ZpD.R3[i] << " "; }
      s << endl;
      for (int i=0; i<ZpD.t; i++) { s << ZpD.prA[i] << " "; }
      s << endl;
    }
  return s;
}

istream& operator>>(istream& s,Zp_Data& ZpD)
{
  s >> ZpD.pr >> ZpD.montgomery;
  ZpD.init(ZpD.pr, ZpD.montgomery);
  if (ZpD.montgomery)
    { s >> ZpD.t >> ZpD.pi;
      if (ZpD.t>MAX_MOD_SZ)
        throw max_mod_sz_too_small(ZpD.t);
      inline_mpn_zero(ZpD.R,MAX_MOD_SZ);
      inline_mpn_zero(ZpD.R2,MAX_MOD_SZ);
      inline_mpn_zero(ZpD.R3,MAX_MOD_SZ);
      inline_mpn_zero(ZpD.prA,MAX_MOD_SZ+1);
      for (int i=0; i<ZpD.t; i++) { s >> ZpD.R[i]; }
      for (int i=0; i<ZpD.t; i++) { s >> ZpD.R2[i]; }
      for (int i=0; i<ZpD.t; i++) { s >> ZpD.R3[i]; }
      for (int i=0; i<ZpD.t; i++) { s >> ZpD.prA[i]; }
    }
  return s;
}

void Zp_Data::pack(octetStream& o) const
{
  pr.pack(o);
  o.store((int)montgomery);
}

void Zp_Data::unpack(octetStream& o)

{
  pr.unpack(o);
  int m;
  o.get(m);
  montgomery = m;
  if (pr != 0)
    init(pr, m);
}

bool Zp_Data::operator!=(const Zp_Data& other) const
{
  if (pr != other.pr or montgomery != other.montgomery)
    return true;
  else
    return false;
}

bool Zp_Data::operator==(const Zp_Data& other) const
{
  return not (*this != other);
}

void Zp_Data::get_shanks_parameters(bigint& y, bigint& q_half, int& r) const
{
  if (shanks_y == 0)
    {
      auto& p = pr;
      bigint n, q, yy, xx, temp;
      // Find n such that (n/p)=-1
      int leg = 1;
      gmp_randclass Gen(gmp_randinit_default);
      Gen.seed(0);
      while (leg != -1)
        {
          n = Gen.get_z_range(p);
          leg = mpz_legendre(n.get_mpz_t(), p.get_mpz_t());
        }
      // Split p-1 = 2^e q
      q = p - 1;
      int e = 0;
      while (mpz_even_p(q.get_mpz_t()))
        {
          e++;
          q = q / 2;
        }
      // y=n^q mod p, x=a^((q-1)/2) mod p, r=e
      shanks_r = e;
      mpz_powm(shanks_y.get_mpz_t(), n.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
      shanks_q_half = (q - 1) / 2;
    }

  y = shanks_y;
  q_half = shanks_q_half;
  r = shanks_r;
}

string Zp_Data::fake_opts() const
{
    return "-P " + to_string(pr) + (montgomery ? "" : " -n");
}
