
#include "FHE/Ring_Element.h"
#include "Tools/Exceptions.h"
#include "Tools/CodeLocations.h"
#include "FHE/FFT.h"

#include "Math/modp.hpp"

void reduce_step(vector<modp>& aa,int i,const FFT_Data& FFTD)
{ modp temp=aa[i];
  for (int j=0; j<FFTD.phi_m(); j++)
    {
      if (FFTD.Phi()[j] > 0)
        for (int k = 0; k < FFTD.Phi()[j]; k++)
          Sub(aa[i-FFTD.phi_m()+j],aa[i-FFTD.phi_m()+j],temp,FFTD.get_prD());
      else
        for (int k = 0; k < abs(FFTD.Phi()[j]); k++)
          Add(aa[i-FFTD.phi_m()+j],aa[i-FFTD.phi_m()+j],temp,FFTD.get_prD());
    }
}

void reduce(vector<modp>& aa, int top, int bottom, const FFT_Data& FFTD)
{
  for (int i = top - 1; i >= bottom; i--)
    reduce_step(aa, i, FFTD);
}


Ring_Element::Ring_Element(const FFT_Data& fftd,RepType r)
{ 
  FFTD=&fftd;
  rep=r;          
  assign_zero();
}


void Ring_Element::prepare(const Ring_Element& other)
{
  assert(this != &other);
  FFTD = other.FFTD;
  rep = other.rep;
  prepare_push();
}

void Ring_Element::prepare_push()
{
  element.clear();
  assert(FFTD);
  element.reserve(FFTD->phi_m());
}


void Ring_Element::allocate()
{
  assert(FFTD);
  element.resize(FFTD->phi_m());
}


void Ring_Element::assign_zero()
{
  element.clear();
}


void Ring_Element::assign_one()
{
  assert(FFTD);
  allocate();
  modp fill;
  if (rep==polynomial) { assignZero(fill,(*FFTD).get_prD()); }
  else                 { assignOne(fill,(*FFTD).get_prD()); }
  for (int i=1; i<(*FFTD).phi_m(); i++)
    { element[i]=fill; }
  assignOne(element[0],(*FFTD).get_prD());
}



void Ring_Element::negate()
{
  if (element.empty())
    return;

  assert(FFTD);
  for (int i=0; i<(*FFTD).phi_m(); i++)
    { Negate(element[i],element[i],(*FFTD).get_prD()); }
}



void add(Ring_Element& ans,const Ring_Element& a,const Ring_Element& b)
{
  assert(a.FFTD);
  if (a.FFTD!=b.FFTD) { throw pr_mismatch();  }  
  if (a.element.empty())
    {
      ans = b;
      return;
    }
  else if (b.element.empty())
    {
      ans = a;
      return;
    }

  if (a.rep!=b.rep)   { throw rep_mismatch(); }

  if (&ans == &a)
    {
      ans += b;
      return;
    }
  else if (&ans == &b)
    {
      ans += a;
      return;
    }

  ans.prepare(a);
  for (int i=0; i<(*ans.FFTD).phi_m(); i++)
    ans.element.push_back(a.element[i].add(b.element[i], a.FFTD->get_prD()));
}

void sub(Ring_Element& ans,const Ring_Element& a,const Ring_Element& b)
{
  assert(a.FFTD);
  if (a.rep!=b.rep)   { throw rep_mismatch(); }
  if (a.FFTD!=b.FFTD) { throw pr_mismatch();  }
  if (a.element.empty())
    {
      ans = b;
      ans.negate();
      return;
    }
  else if (b.element.empty())
    {
      ans = a;
      return;
    }

  if (&ans == &a)
    {
      ans -= b;
      return;
    }

  ans.prepare(a);
  for (int i=0; i<(*ans.FFTD).phi_m(); i++)
    ans.element.push_back(a.element[i].sub(b.element[i], a.FFTD->get_prD()));
}



void mul(Ring_Element& ans,const Ring_Element& a,const Ring_Element& b)
{
  CODE_LOCATION_NO_SCOPE

  assert(a.FFTD);
  if (a.rep!=b.rep)   { throw rep_mismatch(); }
  if (a.FFTD!=b.FFTD) { throw pr_mismatch();  }
  if (a.element.empty() or b.element.empty())
    {
      ans = Ring_Element(*a.FFTD, a.rep);
      return;
    }

  if (a.rep==evaluation)
    { // In evaluation representation, so we can just multiply componentwise
      if (&ans == &a)
        {
          ans *= b;
          return;
        }
      else if (&ans == &b)
        {
          ans *= a;
          return;
        }
      ans.prepare(a);
      for (int i=0; i<(*ans.FFTD).phi_m(); i++)
        ans.element.push_back(a.element[i].mul(b.element[i], a.FFTD->get_prD()));
    }
  else if ((*a.FFTD).get_twop()!=0)
    { // This is the case where m is not a power of two

      // Here we have to do a poly mult followed by a reduction
      // We could be clever (e.g. use Karatsuba etc), but instead
      // we do the school book method followed by term re-writing

      // School book mult
      vector<modp> aa(2*(*a.FFTD).phi_m());
      for (int i=0; i<2*(*a.FFTD).phi_m(); i++)
        { assignZero(aa[i],(*a.FFTD).get_prD()); }
      modp temp;
      for (int i=0; i<(*a.FFTD).phi_m(); i++)
        { for (int j=0; j<(*a.FFTD).phi_m(); j++)
	    { Mul(temp,a.element[i],b.element[j],(*a.FFTD).get_prD()); 
              int k=i+j;
              Add(aa[k],aa[k],temp,(*a.FFTD).get_prD());
            }
        }
      // Now apply reduction, assumes Ring.poly is monic
      reduce(aa, 2*(*a.FFTD).phi_m(), (*a.FFTD).phi_m(), *a.FFTD);
     // Now stick into answer
     ans.partial_assign(a);
     for (int i=0; i<(*ans.FFTD).phi_m(); i++)
       { ans.element[i]=aa[i]; }
    }
  else if ((*a.FFTD).get_twop()==0)
    { // m a power of two case
      Ring_Element aa(*ans.FFTD,ans.rep);
      aa.partial_assign(a);
      modp temp;
      cerr << "slow polynomial multiplication "
              "(change representation to change this)..." << endl;
      for (int i=0; i<(*ans.FFTD).phi_m(); i++)
        { for (int j=0; j<(*ans.FFTD).phi_m(); j++)
            { Mul(temp,a.element[i],b.element[j],(*a.FFTD).get_prD());
              int k=i+j;
              if (k>=(*ans.FFTD).phi_m())
                 { k-=(*ans.FFTD).phi_m();
                   Negate(temp,temp,(*a.FFTD).get_prD());
                 }
              Add(aa.element[k],aa.element[k],temp,(*a.FFTD).get_prD());
            }
          cerr << "\r" << i << "/" << ans.FFTD->phi_m();
        }
      cerr << endl;
      ans=aa;
    }
  else
    { throw not_implemented(); }
}


void mul(Ring_Element& ans,const Ring_Element& a,const modp& b)
{
  if (&ans == &a)
    {
      ans *= b;
      return;
    }

  ans.prepare(a);
  if (a.element.empty())
    return;

  for (int i=0; i<(*ans.FFTD).phi_m(); i++)
    ans.element.push_back(a.element[i].mul(b, a.FFTD->get_prD()));
}


Ring_Element& Ring_Element::operator +=(const Ring_Element& other)
{
  assert(element.size() == other.element.size());
  assert(FFTD);
  assert(FFTD == other.FFTD);
  assert(rep == other.rep);
  for (size_t i = 0; i < element.size(); i++)
    element[i] = element[i].add(other.element[i], FFTD->get_prD());
  return *this;
}


Ring_Element& Ring_Element::operator -=(const Ring_Element& other)
{
  assert(element.size() == other.element.size());
  assert(FFTD);
  assert(FFTD == other.FFTD);
  assert(rep == other.rep);
  for (size_t i = 0; i < element.size(); i++)
    element[i] = element[i].sub(other.element[i], FFTD->get_prD());
  return *this;
}


Ring_Element& Ring_Element::operator *=(const Ring_Element& other)
{
  assert(element.size() == other.element.size());
  assert(FFTD);
  assert(FFTD == other.FFTD);
  assert(rep == other.rep);
  assert(rep == evaluation);
  for (size_t i = 0; i < element.size(); i++)
    element[i] = element[i].mul(other.element[i], FFTD->get_prD());
  return *this;
}


Ring_Element& Ring_Element::operator *=(const modp& other)
{
  assert(FFTD);
  for (size_t i = 0; i < element.size(); i++)
    element[i] = element[i].mul(other, FFTD->get_prD());
  return *this;
}


Ring_Element Ring_Element::mul_by_X_i(int j) const
{
  CODE_LOCATION_NO_SCOPE

  assert(FFTD);
  Ring_Element ans;
  ans.prepare(*this);
  if (element.empty())
    return ans;

  auto& a = *this;
  if (ans.rep == evaluation)
    {
      modp xj, xj2;
      Power(xj, (*ans.FFTD).get_root(0), j, (*a.FFTD).get_prD());
      Sqr(xj2, xj, (*a.FFTD).get_prD());
      ans.prepare_push();
      modp tmp;
      for (int i= 0; i < (*ans.FFTD).phi_m(); i++)
        {
          Mul(tmp, a.element[i], xj, (*a.FFTD).get_prD());
          ans.element.push_back(tmp);
          Mul(xj, xj, xj2, (*a.FFTD).get_prD());
        }
    }
  else
    {
      Ring_Element aa(*ans.FFTD, ans.rep);
      aa.allocate();
      for (int i= 0; i < (*ans.FFTD).phi_m(); i++)
        {
          int k= j + i, s= 1;
          while (k >= (*ans.FFTD).phi_m())
            {
              k-= (*ans.FFTD).phi_m();
              s= -s;
            }
          if (s == 1)
            {
              aa.element[k]= a.element[i];
            }
          else
            {
              Negate(aa.element[k], a.element[i], (*a.FFTD).get_prD());
            }
        }
      ans= aa;
    }
  return ans;
}


void Ring_Element::randomize(PRNG& G,bool Diag)
{
  assert(FFTD);
  allocate();
  if (Diag==false)
    { for (int i=0; i<(*FFTD).phi_m(); i++) 
       { element[i].randomize(G,(*FFTD).get_prD()); }
    }
  else 
    { element[0].randomize(G,(*FFTD).get_prD());
      if (rep==polynomial)
        { for (int i=1; i<(*FFTD).phi_m(); i++) 
            { assignZero(element[i],(*FFTD).get_prD()); }
        }
      else
        { for (int i=1; i<(*FFTD).phi_m(); i++) 
            { element[i]=element[0]; }  
        }
    }
}


void Ring_Element::change_rep(RepType r)
{ 
  assert(FFTD);
  if (element.empty())
    {
      rep = r;
      return;
    }

  if (rep==r) { return; }
  if (r==evaluation)
    { rep=evaluation;
      if ((*FFTD).get_twop()==0)
        { // m a power of two variant
          FFT_Iter2(element,(*FFTD).phi_m(),(*FFTD).get_roots(),(*FFTD).get_prD());
	}
      else
        { // Non m power of two variant and FFT enabled
          FFT_non_power_of_two(element, element, *FFTD);
	}
    }
  else
    { rep=polynomial;
      if ((*FFTD).get_twop()==0)
	{ // m a power of two variant
          modp root2;
          Sqr(root2,(*FFTD).get_root(1),(*FFTD).get_prD());
          FFT_Iter(element, (*FFTD).phi_m(),root2,(*FFTD).get_prD());
          modp w;
          w = (*FFTD).get_iphi();
          for (int i=0; i<(*FFTD).phi_m(); i++)
            { Mul(element[i], element[i], w, (*FFTD).get_prD());
              Mul(w, w, (*FFTD).get_root(1),(*FFTD).get_prD());
            }
        }
      else
        { // Non power of 2 m variant and FFT enabled
          vector<modp> fft((*FFTD).m());
          for (int i=0; i<(*FFTD).m(); i++) 
            { assignZero(fft[i],(*FFTD).get_prD()); }
          for (int i=0; i<(*FFTD).phi_m(); i++) 
	    { fft[(*FFTD).p(i)]=element[i]; }
          BFFT(fft,fft,*FFTD,false);
          // Need to reduce fft mod Phi_m
          reduce(fft, (*FFTD).m(), (*FFTD).phi_m(), *FFTD);
          for (int i=0; i<(*FFTD).phi_m(); i++) 
	    { element[i]=fft[i]; }
	}
    }
}


bool Ring_Element::equals(const Ring_Element& a) const
{
  assert(FFTD);
  if (rep!=a.rep)   { throw rep_mismatch(); }
  if (*FFTD!=*a.FFTD) { throw pr_mismatch();  }

  if (is_zero() or a.is_zero())
    return is_zero() and a.is_zero();

  for (int i=0; i<(*FFTD).phi_m(); i++)
    { if (!areEqual(element[i],a.element[i],(*FFTD).get_prD())) { return false; } }
  return true;
}


bool Ring_Element::is_zero() const
{
  assert(FFTD);
  if (element.empty())
    return true;
  for (auto& x : element)
    if (not ::isZero(x, FFTD->get_prD()))
      return false;
  return true;
}


ConversionIterator Ring_Element::get_iterator() const
{
  assert(FFTD);
  if (rep != polynomial)
    throw runtime_error("simple iterator only available in polynomial represention");
  assert(not element.empty());
  return {element, (*FFTD).get_prD()};
}

RingReadIterator Ring_Element::get_copy_iterator() const
{
  assert(FFTD);
  return *this;
}

RingWriteIterator Ring_Element::get_write_iterator()
{
  assert(FFTD);
  return *this;
}

vector<bigint>  Ring_Element::to_vec_bigint() const
{
  assert(FFTD);
  vector<bigint> v;
  to_vec_bigint(v);
  return v;
}


void Ring_Element::to_vec_bigint(vector<bigint>& v) const
{
  assert(FFTD);
  v.resize(FFTD->phi_m());
  if (element.empty())
    return;

  if (rep==polynomial)
     { for (int i=0; i<(*FFTD).phi_m(); i++)
         { to_bigint(v[i],element[i],(*FFTD).get_prD()); }
     }
  else
     { Ring_Element a=*this;
       a.change_rep(polynomial);
       for (int i=0; i<(*FFTD).phi_m(); i++)
         { to_bigint(v[i],a.element[i],(*FFTD).get_prD()); }
     }
}





modp Ring_Element::get_constant() const
{
  assert(FFTD);
  if (element.empty())
    return {};
  else
    return element[0];
}



void store(octetStream& o,const vector<modp>& v,const Zp_Data& ZpD)
{
  ZpD.pack(o);
  o.store((int)v.size());
  for (auto& x : v)
    x.pack(o, ZpD);
}


void get(octetStream& o,vector<modp>& v,const Zp_Data& ZpD)
{
  Zp_Data check_Zpd;
  check_Zpd.unpack(o);
  if (check_Zpd != ZpD)
    throw runtime_error(
        "mismatch: " + to_string(check_Zpd.pr_bit_length) + "/"
            + to_string(ZpD.pr_bit_length));
  unsigned int length;
  o.get(length);
  v.clear();
  v.reserve(length);
  modp tmp;
  for (unsigned int i=0; i<length; i++)
    {
      tmp.unpack(o,ZpD);
      v.push_back(tmp);
    }
}


void Ring_Element::pack(octetStream& o) const
{
  assert(FFTD);
  check_size();
  o.store(unsigned(rep));
  store(o,element,(*FFTD).get_prD());
}


void Ring_Element::unpack(octetStream& o)
{
  assert(FFTD);
  unsigned int a;
  o.get(a);
  rep=(RepType) a;
  check_rep();
  get(o,element,(*FFTD).get_prD());
  check_size();
}


void Ring_Element::check_rep()
{
  if (rep != evaluation and rep != polynomial)
    throw runtime_error("invalid representation");
}


void Ring_Element::check_size() const
{
  assert(FFTD);
  if (not element.empty() and (int)element.size() != FFTD->phi_m())
    throw runtime_error("invalid element size");
}

void Ring_Element::output(ostream& s) const
{
  assert(FFTD);
  s.write((char*)&rep, sizeof(rep));
  auto size = element.size();
  s.write((char*)&size, sizeof(size));
  for (auto& x : element)
    x.output(s, FFTD->get_prD(), false);
}


void Ring_Element::input(istream& s)
{
  assert(FFTD);
  s.read((char*)&rep, sizeof(rep));
  check_rep();
  auto size = element.size();
  s.read((char*)&size, sizeof(size));
  element.resize(size);
  for (auto& x : element)
    x.input(s, FFTD->get_prD(), false);
}


void Ring_Element::check(const FFT_Data& FFTD) const
{
  if (&FFTD != this->FFTD)
    throw params_mismatch();
  if (is_zero())
    throw runtime_error("element is zero");
}


size_t Ring_Element::report_size(ReportType type) const
{
  assert(FFTD);
  if (type == CAPACITY)
    return sizeof(modp) * element.capacity();
  else
    return sizeof(mp_limb_t) * (*FFTD).get_prD().get_t() * element.size();
}

template void Ring_Element::from(const Generator<bigint>& generator);
template void Ring_Element::from(const Generator<int>& generator);
