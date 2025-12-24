
#include "bigint.h"
#include "gfp.h"
#include "gfpvar.h"
#include "Integer.h"
#include "Z2k.h"
#include "Z2k.hpp"
#include "GC/Clear.h"
#include "Tools/Exceptions.h"

#include "bigint.hpp"

thread_local bigint bigint::tmp = 0;
thread_local bigint bigint::tmp2 = 0;
thread_local gmp_random bigint::random;


bigint powerMod(const bigint& x,const bigint& e,const bigint& p)
{
  bigint ans;
  if (e>=0)
    { mpz_powm(ans.get_mpz_t(),x.get_mpz_t(),e.get_mpz_t(),p.get_mpz_t()); }
  else
    { bigint xi,ei=-e;
      invMod(xi,x,p);
      mpz_powm(ans.get_mpz_t(),xi.get_mpz_t(),ei.get_mpz_t(),p.get_mpz_t()); 
    }
      
  return ans;
}


int powerMod(int x,int e,int p)
{
  if (e==1) { return x; }
  if (e==0) { return 1; }
  if (e<0)
     { throw not_implemented(); }
   int t=x,ans=1;
   while (e!=0)
     { if ((e&1)==1) { ans=(ans*t)%p; }
       e>>=1;
       t=(t*t)%p;
     }
  return ans;
}

size_t bigint::report_size(ReportType type) const
{
  size_t res = 0;
  if (type != MINIMAL)
    res += sizeof(*this);
  if (type == CAPACITY)
    res += get_mpz_t()->_mp_alloc * sizeof(mp_limb_t);
  else if (type == USED)
    res += abs(get_mpz_t()->_mp_size) * sizeof(mp_limb_t);
  else if (type == MINIMAL)
    res += 5 + numBytes(*this);
  return res;
}

template <>
int limb_size<bigint>()
{
  return 64;
}

template <>
int limb_size<int>()
{
  // doesn't matter
  return 0;
}

bigint::bigint(const Integer& x)
{
  *this = x;
}

bigint::bigint(const GC::Clear& x)
{
  *this = x;
}

bigint& bigint::operator =(const Integer& x)
{
  return *this = SignedZ2<64>(x);
}

bigint& bigint::operator =(const GC::Clear& x)
{
  return *this = SignedZ2<64>(x);
}

bigint::bigint(const mp_limb_t* data, size_t n_limbs)
{
  mpz_import(get_mpz_t(), n_limbs, -1, 8, -1, 0, data);
}

void bigint::pack(octetStream& os, int length) const
{
  os.store(*this, length);
}

void bigint::unpack(octetStream& os, int length)
{
  os.get(*this, length);
}

string to_string(const bigint& x)
{
  stringstream ss;
  ss << x;
  return ss.str();
}

#ifdef REALLOC_POLICE
void bigint::lottery()
{
  if (rand() % 1000 == 0)
    if (rand() % 1000 == 0)
      throw runtime_error("much deallocation");
}
#endif
