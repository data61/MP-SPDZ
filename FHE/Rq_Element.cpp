#include "Rq_Element.h"
#include "FHE_Keys.h"
#include "Tools/Exceptions.h"
#include "Tools/CodeLocations.h"

#include "Math/modp.hpp"

Rq_Element::Rq_Element(const FHE_PK& pk) :
        Rq_Element(pk.get_params().FFTD(), evaluation, evaluation)
{
}

Rq_Element::Rq_Element(const vector<FFT_Data>& prd, RepType r0, RepType r1)
{
    if (prd.size() > 0)
        a.push_back({prd[0], r0});
    if (prd.size() > 1)
    {
        assert(prd[0].get_R() == prd[1].get_R());
        a.push_back({prd[1], r1});
    }
    lev = n_mults();
}

void Rq_Element::set_data(const vector<FFT_Data>& prd)
{
    a.resize(prd.size(), {});
    for(size_t i = 0; i < a.size(); i++)
        a[i].set_data(prd[i]);
    lev=n_mults();
}

void Rq_Element::assign_zero(const vector<FFT_Data>& prd)
{
    set_data(prd);
    assign_zero();
}

void Rq_Element::assign_zero()
{
	for (int i=0; i<=lev; ++i)
		a[i].assign_zero();
}

void Rq_Element::assign_one()
{
	for (int i=0; i<=lev; ++i)
		a[i].assign_one();
}

void Rq_Element::partial_assign(const Rq_Element& other)
{
	lev=other.lev;
	a.resize(other.a.size(), {});
}

void Rq_Element::negate()
{
	for (int i=0; i<=lev; ++i)
		a[i].negate();
}

Rq_Element Rq_Element::mul_by_X_i(int i) const
{
  Rq_Element res;
  res.lev = lev;
  res.a.clear();
  for (auto& x : a)
    {
      auto tmp = x.mul_by_X_i(i);
      res.a.push_back(tmp);
    }
  return res;
}

void add(Rq_Element& ans,const Rq_Element& ra,const Rq_Element& rb)
{
  ans.partial_assign(ra, rb);
  for (int i=0; i<=ans.lev; ++i)
	  add(ans.a[i],ra.a[i],rb.a[i]);
  if (ans.lev == 0 && ans.n_mults() == 1) {
	  ans.a[1].partial_assign(ra.a[1]);
  }
}
void sub(Rq_Element& ans,const Rq_Element& a,const Rq_Element& b)
{
  ans.partial_assign(a, b);
  for (int i=0; i<=ans.lev; ++i)
	  sub(ans.a[i],a.a[i],b.a[i]);
  if (ans.lev == 0 && ans.n_mults() == 1) {
	  ans.a[1].partial_assign(a.a[1]);
  }
}

void mul(Rq_Element& ans,const Rq_Element& a,const Rq_Element& b)
{
  ans.partial_assign(a, b);
  for (int i=0; i<=ans.lev; ++i)
	  mul(ans.a[i],a.a[i],b.a[i]);
  if (ans.lev == 0 && ans.n_mults() == 1) {
	  ans.a[1].partial_assign(a.a[1]);
  }
}

void mul(Rq_Element& ans,const Rq_Element& a,const bigint& b)
{
  ans.partial_assign(a);
  modp bp;
  for (int i=0; i<=ans.lev; ++i)
  {
	  to_modp(bp,b,a.a[i].get_prD());
	  mul(ans.a[i],a.a[i],bp);
  }
}

void Rq_Element::randomize(PRNG& G,int l)
{
  set_level(l);
  for (int i=0; i<=lev; ++i)
	  a[i].randomize(G);
}

bool Rq_Element::equals(const Rq_Element& other) const
{
  if (lev!=other.lev)                 { throw level_mismatch(); }
  for (int i=0; i<=lev; ++i)
	  if (!a[i].equals(other.a[i])) return false;
  return true;
}


vector<bigint> Rq_Element::to_vec_bigint() const
{
  vector<bigint> v;
  to_vec_bigint(v);
  return v;
}

// Doing sort of CRT;
// result mod p0 = a[0]; result mod p1 = a[1]
void Rq_Element::to_vec_bigint(vector<bigint>& v) const
{
  CODE_LOCATION_NO_SCOPE

  a[0].to_vec_bigint(v);
  if (n_mults() == 0) {
	  bigint p0 = a[0].get_prime();
	  for (size_t i = 0; i < v.size(); ++i) {
		  if (v[i] > p0 / 2) {
			  v[i] = (v[i] - p0);
		  }
	  }
  }
  if (lev==1)
    { vector<bigint> v1;
      a[1].to_vec_bigint(v1);
      assert(v.size() == v1.size());
      bigint p0=a[0].get_prime();
      bigint p1=a[1].get_prime();
      bigint p0i,lambda,Q=p0*p1;
      invMod(p0i,p0%p1,p1);
      for (unsigned int i=0; i<v.size(); i++)
	{ lambda=((v1[i]-v[i])*p0i)%Q;
          v[i]=(v[i]+p0*lambda)%Q;
	}
    }
}

ConversionIterator Rq_Element::get_iterator() const
{
  if (lev != 0)
    throw not_implemented();
  return a[0].get_iterator();
}

bigint Rq_Element::infinity_norm() const
{
  bigint Q = 1, ans = 0;
  for (int i = 0; i <= n_mults(); ++i)
  {
	  Q *= a[i].get_prime();
  }
  bigint t;
  vector<bigint> te=to_vec_bigint();
  for (unsigned int i=0; i<te.size(); i++)
    { // Take rounded value and then abs value
      if (te[i]<Q/2) { t=te[i]; }
      else           { t=Q-te[i]; }
      if (t>ans) { ans=t; }
    }
  return ans;
}

void Rq_Element::change_rep(RepType r)
{
  if (lev==1) { throw level_mismatch(); }
  a[0].change_rep(r);
}

void Rq_Element::change_rep(RepType r0,RepType r1)
{
  if (lev==0 or n_mults() != 1) { throw level_mismatch(); }
  a[0].change_rep(r0);
  a[1].change_rep(r1);
}

void Rq_Element::Scale(const bigint& p)
{
  if (lev==0) { return; }

  CODE_LOCATION_NO_SCOPE

  if (n_mults() == 0) {
	  //for some reason we scale but we have just one level
	  throw level_mismatch();
  }
  bigint p0=a[0].get_prime(),p1=a[1].get_prime(),p1i,lambda,n=p1*p;
  invMod(p1i,p1%p,p);

  // First multiply input by [p1]_p
  bigint te=p1%p;
  if (te>p/2) { te-=p; }
  modp tep;
  to_modp(tep,te,a[0].get_prD());
  mul(a[0],a[0],tep);
  to_modp(tep,te,a[1].get_prD());
  mul(a[1],a[1],tep);

  // Now compute delta
  Ring_Element b0(a[0].get_FFTD(),evaluation);
  Ring_Element b1(a[1].get_FFTD(),evaluation);
  // scope to ensure deconstruction of write iterators
  {
    auto poly_a1 = a[1];
    poly_a1.change_rep(polynomial);
    auto it = poly_a1.get_iterator();
    auto it0 = b0.get_write_iterator();
    auto it1 = b1.get_write_iterator();
    bigint half_n = n / 2;
    bigint delta;
    for (int i=0; i < a[1].get_FFTD().phi_m(); i++)
      {
        it.get(delta);
        lambda = delta;
        lambda *= p1i;
        lambda %= p;
        lambda *= p1;
        lambda -= delta;
        lambda %= n;
        if (lambda > half_n)
          lambda -= n;
        it0.get(lambda);
        it1.get(lambda);
      }
  }

  // Now add delta back onto a0
  Rq_Element bb(b0,b1);
  ::add(*this,*this,bb);

  // Now divide by p1 mod p0
  modp p1_inv,pp;
  to_modp(pp,p1,a[0].get_prD());
  Inv(p1_inv,pp,a[0].get_prD());
  lev=0;
  mul(a[0],a[0],p1_inv);
}

void Rq_Element::mul_by_p1()
{

  if (n_mults() == 0) {throw level_mismatch();}
  lev=1;
  bigint m=a[1].get_prime()%a[0].get_prime();
  modp mp;
  to_modp(mp,m,a[0].get_prD());
  mul(a[0],a[0],mp);
  a[1].assign_zero();
}

void Rq_Element::raise_level()
{
  if (lev==n_mults()) { return; }
  lev=1;
  a[1].from(a[0].get_copy_iterator());
}

void Rq_Element::check_level() const
{
  if ((unsigned)lev > (unsigned)n_mults())
    throw range_error(
        "level out of range: " + to_string(lev) + "/" + to_string(n_mults()));
}

void Rq_Element::partial_assign(const Rq_Element& x, const Rq_Element& y)
{
  x.check_level();
  y.check_level();
  if (x.lev != y.lev or x.n_mults() != y.n_mults())
    throw level_mismatch();
  partial_assign(x);
}

void Rq_Element::pack(octetStream& o, int) const
{
  check_level();
  o.store(lev);
  for (int i = 0; i <= lev; ++i)
	  a[i].pack(o);
}

void Rq_Element::unpack(octetStream& o, int)
{
  unsigned int ll;  o.get(ll); lev=ll;

  try
  {
      check_level();
  }
  catch (...)
  {
      lev = 0;
      throw;
  }

  for (int i = 0; i <= lev; ++i)
	  a[i].unpack(o);
}

void Rq_Element::output(ostream& s) const
{
  check_level();
  s.write((char*)&lev, sizeof(lev));
  for (int i = 0; i <= lev; i++)
    a[i].output(s);
}

void Rq_Element::input(istream& s)
{
  s.read((char*)&lev, sizeof(lev));
  check_level();
  for (int i = 0; i <= lev; i++)
    a[i].input(s);
}

void Rq_Element::check(const FHE_Params& params) const
{
  if (n_mults() != params.n_mults())
    throw level_mismatch();
  for (int i = 0; i <= lev; i++)
    a[i].check(params.FFTD()[i]);
}

size_t Rq_Element::report_size(ReportType type) const
{
  size_t sz = a[0].report_size(type);
  if (lev == 1 || type == CAPACITY)
	  if (n_mults() == 1)
		  sz += a[1].report_size(type);
  return sz;
}

void Rq_Element::unpack(octetStream& o, const FHE_Params& params)
{
  set_data(params.FFTD());
  unpack(o);
}

void Rq_Element::print_first_non_zero() const
{
  vector<bigint> v = to_vec_bigint();
  size_t i;
  for (i = 0; i < v.size(); i++)
  {
      if (v[i] != 0)
      {
          cout << i << ":" << v[i];
          break;
      }
  }
  if (i == v.size())
      cout << "ZERO" << endl;
  cout << endl;
}

template void Rq_Element::from<bigint>(const Generator<bigint>&, int);
template void Rq_Element::from<int>(const Generator<int>&, int);
