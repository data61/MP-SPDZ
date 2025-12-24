#include "Ciphertext.h"
#include "P2Data.h"
#include "Tools/Exceptions.h"
#include "Tools/CodeLocations.h"

#include "Math/modp.hpp"

Ciphertext::Ciphertext(const FHE_PK& pk) : Ciphertext(pk.get_params())
{
}


void Ciphertext::set(const Rq_Element& a0, const Rq_Element& a1,
        const FHE_PK& pk)
{
  set(a0, a1, pk.a().get(0).get_element(0).get_limb(0));
}


word check_pk_id(word a, word b)
{
  if (a == 0)
    return b;
  else if (b == 0 or a == b)
    return a;
  else
  {
    cout << a << " vs " << b << endl;
    throw runtime_error("public keys of ciphertext operands don't match");
  }
}


void Ciphertext::Scale()
{
  Scale(params->get_plaintext_modulus());
}


void add(Ciphertext& ans,const Ciphertext& c0,const Ciphertext& c1)
{
  if (c0.params!=c1.params)  { throw params_mismatch(); }
  if (ans.params!=c1.params) { throw params_mismatch(); }
  ans.pk_id = check_pk_id(c0.pk_id, c1.pk_id);
  add(ans.cc0,c0.cc0,c1.cc0);
  add(ans.cc1,c0.cc1,c1.cc1);
}


void sub(Ciphertext& ans,const Ciphertext& c0,const Ciphertext& c1)
{
  if (c0.params!=c1.params)  { throw params_mismatch(); }
  if (ans.params!=c1.params) { throw params_mismatch(); }
  ans.pk_id = check_pk_id(c0.pk_id, c1.pk_id);
  sub(ans.cc0,c0.cc0,c1.cc0);
  sub(ans.cc1,c0.cc1,c1.cc1);
}


void mul(Ciphertext& ans,const Ciphertext& c0,const Ciphertext& c1,
         const FHE_PK& pk)
{
  CODE_LOCATION_NO_SCOPE

  if (c0.params!=c1.params)  { throw params_mismatch(); }
  if (ans.params!=c1.params) { throw params_mismatch(); }

  // Switch Modulus for c0 and c1 down to level 0
  Ciphertext cc0=c0,cc1=c1;
  cc0.Scale(pk.p()); cc1.Scale(pk.p());
  
  // Now do the multiply
  auto d0 = cc0.cc0 * cc1.cc0;
  auto d1 = cc0.cc0 * cc1.cc1 + cc0.cc1 * cc1.cc0;
  auto d2 = cc0.cc1 * cc1.cc1;
  d2.negate(); 

  // Now do the switch key
  d2.raise_level();
  d0.mul_by_p1();
  auto t =  pk.bs()* d2;
  add(d0,d0,t);

  d1.mul_by_p1();
  mul(t,pk.as(),d2);
  add(d1,d1,t);

  ans.set(d0, d1, check_pk_id(c0.pk_id, c1.pk_id));
  ans.Scale(pk.p());
}


template<class T,class FD,class S>
void mul(Ciphertext& ans,const Plaintext<T,FD,S>& a,const Ciphertext& c)
{
  a.to_poly();

  int lev=c.cc0.level();
  Rq_Element ra((*ans.params).FFTD(),evaluation,evaluation);
  if (lev==0) { ra.lower_level(); }
  ra.from(a.get_iterator());
  ans.mul(c, ra);
}

void Ciphertext::mul(const Ciphertext& c, const Rq_Element& ra)
{
  if (params!=c.params) { throw params_mismatch(); }
  pk_id = c.pk_id;

  ::mul(cc0,ra,c.cc0);
  ::mul(cc1,ra,c.cc1);
}

void Ciphertext::add(octetStream& os, int)
{
  Ciphertext tmp(*params);
  tmp.unpack(os);
  *this += tmp;
}

void Ciphertext::rerandomize(const FHE_PK& pk)
{
  Rq_Element tmp(*params);
  SeededPRNG G;
  vector<FFT_Data::S> r(params->FFTD()[0].phi_m());
  bigint p = pk.p();
  assert(p != 0);
  for (auto& x : r)
    {
      G.get(x, params->p0().numBits() - p.numBits() - 1);
      x *= p;
    }
  tmp.from(r, 0);
  Scale();
  cc0 += tmp;
  auto zero = pk.encrypt(*params);
  zero.Scale(pk.p());
  *this += zero;
}


template void mul(Ciphertext& ans,const Plaintext<gfp,FFT_Data,bigint>& a,const Ciphertext& c);
template void mul(Ciphertext& ans, const Plaintext<gf2n_short, P2Data, int>& a,
        const Ciphertext& c);
