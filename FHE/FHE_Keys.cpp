
#include "FHE_Keys.h"
#include "Ciphertext.h"
#include "P2Data.h"
#include "FFT_Data.h"
#include "Tools/CodeLocations.h"
#include "Processor/OnlineOptions.h"

#include "Math/modp.hpp"


FHE_SK::FHE_SK(const FHE_PK& pk) : FHE_SK(pk.get_params(), pk.p())
{
}

FHE_SK::FHE_SK(const FHE_Params& pms) :
    FHE_SK(pms, pms.get_plaintext_modulus())
{
}


FHE_SK& FHE_SK::operator+=(const FHE_SK& c)
{ 
  auto& a = *this;
  auto& b = *this;

  if (a.params!=c.params) { throw params_mismatch(); }

  ::add(a.sk,b.sk,c.sk);

  return *this;
}



void KeyGen(FHE_PK& PK,FHE_SK& SK,PRNG& G)
{
  if (PK.params!=SK.params) { throw params_mismatch(); }
  if (PK.pr!=SK.pr)         { throw pr_mismatch(); }

  Rq_Element sk = PK.sample_secret_key(G);
  SK.assign(sk);
  PK.KeyGen(sk, G);
}


FHE_PK::FHE_PK(const FHE_Params& pms) :
    FHE_PK(pms, pms.get_plaintext_modulus())
{
}

Rq_Element FHE_PK::sample_secret_key(PRNG& G)
{
  Rq_Element sk = FHE_SK(*this).s();
  // Generate the secret key
  sk.from(GaussianGenerator<bigint>(params->get_DG(), G));
  return sk;
}

void FHE_PK::KeyGen(Rq_Element& sk, PRNG& G, int noise_boost)
{
  Rq_Element a(*this);
  a.randomize(G);
  partial_key_gen(sk, a, G, noise_boost);
}

void FHE_PK::partial_key_gen(const Rq_Element& sk, const Rq_Element& a, PRNG& G,
    int noise_boost)
{
  CODE_LOCATION_NO_SCOPE

  FHE_PK& PK = *this;

  a0 = a;

  // b0=a0*s+p*e0
  Rq_Element e0((*PK.params).FFTD(),evaluation,evaluation);
  e0.from(GaussianGenerator<bigint>(params->get_DG(), G, noise_boost));
  mul(PK.b0,PK.a0,sk);
  mul(e0,e0,PK.pr);
  add(PK.b0,PK.b0,e0);

#ifdef CHECK_NOISE
  // strict check not working for GF(2^n)
  PK.check_noise(PK.b0 - PK.a0 * sk, false);
#endif

  if (params->n_mults() > 0)
    {
      // Generating the switching key data
      PK.Sw_a.randomize(G);

      // bs=as*s+p*es
      Rq_Element es((*PK.params).FFTD(),evaluation,evaluation);
      es.from(GaussianGenerator<bigint>(params->get_DG(), G, noise_boost));
      mul(PK.Sw_b,PK.Sw_a,sk);
      mul(es,es,PK.pr);
      add(PK.Sw_b,PK.Sw_b,es);

      // bs=bs-p1*s^2
      // Mult at level 0
      auto s2 = sk * sk;
      s2.mul_by_p1();         // This raises back to level 1
      sub(PK.Sw_b,PK.Sw_b,s2);
    }
}

void FHE_PK::check_noise(const FHE_SK& SK) const
{
  Rq_Element sk = SK.s();
  if (params->n_mults() > 0)
    sk.mul_by_p1();
  check_noise(b0 - a0 * sk);
}

void FHE_PK::check_noise(const Rq_Element& x, bool check_modulo) const
{
  assert(pr != 0);
  vector<bigint> noise = x.to_vec_bigint();
  bigint m = 0;
  if (check_modulo)
    cout << "checking multiplicity of noise" << endl;
  for (size_t i = 0; i < noise.size(); i++)
    {
//	  cout << "noise mod pr: " << noise[i] << " pr: " << pr << " " << noise[i] % pr << "\n";
      if (check_modulo and noise[i] % pr != 0)
        {
          cout << i << " " << noise[i] % pr << endl;
          throw runtime_error("invalid public key");
        }
      noise[i] /= pr;
      m = m > noise[i] ? m : noise[i];
    }
#ifdef VERBOSE_KEYGEN
  cerr << "max noise: " << m << endl;
#endif
}


template<class T, class FD, class S>
void FHE_PK::encrypt(Ciphertext& c,
                     const Plaintext<T, FD, S>& mess,const Random_Coins& rc) const
{
  if (&c.get_params()!=params)  { throw params_mismatch(); }
  if (&rc.get_params()!=params) { throw params_mismatch(); }
  if (T::characteristic_two ^ (pr == 2))
    throw pr_mismatch();

  Rq_Element mm((*params).FFTD(),polynomial,polynomial);
  mm.from(mess.get_iterator());

  quasi_encrypt(c,mm,rc);
}

void FHE_PK::quasi_encrypt(Ciphertext& c,
                           const Rq_Element& mess,const Random_Coins& rc) const
{
  CODE_LOCATION_NO_SCOPE

  if (&c.get_params()!=params)  { throw params_mismatch(); }
  if (&rc.get_params()!=params) { throw params_mismatch(); }
  assert(pr != 0);

  // c1=a0*u+p*v
  auto c1 = a0 * rc.u() + rc.v() * pr;

  // c0 = b0 * u + p * w + mess
  auto c0 = b0 * rc.u();
  auto edd = rc.w() * pr + mess;
  if (params->n_mults() == 0)
    edd.change_rep(evaluation);
  else
    edd.change_rep(evaluation, evaluation);
  add(c0,c0,edd);

  c.set(c0,c1,*this);
}

template<class FD>
Ciphertext FHE_PK::encrypt(const Plaintext<typename FD::T, FD, typename FD::S>& mess,
    const Random_Coins& rc) const
{
  Ciphertext res(*params);
  encrypt(res, mess, rc);
  return res;
}


template<class FD>
Ciphertext FHE_PK::encrypt(
    const Plaintext<typename FD::T, FD, typename FD::S>& mess) const
{
  return encrypt(Rq_Element(*params, mess));
}

Ciphertext FHE_PK::encrypt(const Rq_Element& mess) const
{
  Random_Coins rc(*params);
  PRNG G;
  G.ReSeed();
  rc.generate(G);
  Ciphertext res(*params);
  quasi_encrypt(res, mess, rc);
  return res;
}


template<class T, class FD, class S>
void FHE_SK::decrypt(Plaintext<T,FD,S>& mess,const Ciphertext& c) const
{
  if (T::characteristic_two ^ (pr == 2))
    throw pr_mismatch();

  Rq_Element ans = quasi_decrypt(c);
  mess.set_poly_mod(ans.get_iterator(), ans.get_modulus());
}

Rq_Element FHE_SK::quasi_decrypt(const Ciphertext& c) const
{
  CODE_LOCATION_NO_SCOPE

  if (&c.get_params()!=params)  { throw params_mismatch(); }

  auto ans = c.c0() - c.c1() * sk;
  ans.change_rep(polynomial);
  return ans;
}



Plaintext_<FFT_Data> FHE_SK::decrypt(const Ciphertext& c)
{
  return decrypt(c, params->get_plaintext_field_data<FFT_Data>());
}

template<class FD>
Plaintext<typename FD::T, FD, typename FD::S> FHE_SK::decrypt(const Ciphertext& c, const FD& FieldD)
{
  Plaintext<typename FD::T, FD, typename FD::S> res(FieldD);
  decrypt_any(res, c);
  return res;
}

template <class FD>
void FHE_SK::decrypt_any(Plaintext_<FD>& res, const Ciphertext& c)
{
  if (sk.level())
      sk.lower_level();
  if (c.level())
    {
      Ciphertext cc = c;
      cc.Scale(res.get_field().get_prime());
      decrypt(res, cc);
    }
  else
    decrypt(res, c);
}





/* Distributed Decryption Stuff */
void FHE_SK::dist_decrypt_1(vector<bigint>& vv,const Ciphertext& ctx,int player_number,int num_players) const
{
  // Need Ciphertext to be at level 0, so we force this here
  Ciphertext cc=ctx; cc.Scale(pr);

  // First do the basic decryption
  auto dec_sh = cc.c1() * sk;
  if (player_number==0)
    { sub(dec_sh,cc.c0(),dec_sh); }
  else
    { dec_sh.negate(); }

  // Now convert to a vector of bigint's and add the required randomness
  assert(pr != 0);
  bigint Bd=((*params).B()<<(*params).secp())/(num_players*pr);
  Bd=Bd/2; // make slightly smaller due to rounding issues

  dec_sh.to_vec_bigint(vv);
  if ((int)vv.size() != params->phi_m())
    throw length_error("wrong length of ring element");
  bigint mod=(*params).p0();
  PRNG G;  G.ReSeed();
  bigint mask;
  bigint two_Bd = 2 * Bd;

  bool verbose = OnlineOptions::singleton.has_option("verbose_dd");
  int max_bits = 0;

  if (verbose)
    cerr << "Random bits in distributed decryption: " << two_Bd.numBits()
        << endl;

  for (int i=0; i<(*params).phi_m(); i++)
    {
      G.randomBnd(mask, two_Bd);
      mask -= Bd;
      mask *= pr;
      vv[i] += mask;
      vv[i] %= mod;
      if (vv[i]<0) { vv[i]+=mod; }

      if (verbose)
        max_bits = max(max_bits, vv[i].numBits());
    }

  if (verbose)
    cerr << "Maximum bits in distributed decryption: " << max_bits << endl;
}


void FHE_SK::dist_decrypt_2(vector<bigint>& vv,const vector<bigint>& vv1) const
{
  bigint mod=(*params).p0();
  for (int i=0; i<(*params).phi_m(); i++)
    {
      vv[i] += vv1[i];
      vv[i] %= mod;
    }
}

void FHE_PK::pack(octetStream& o) const
{
  o.append((octet*) "PKPKPKPK", 8);
  a0.pack(o);
  b0.pack(o);
  if (params->n_mults() > 0)
    {
      Sw_a.pack(o);
      Sw_b.pack(o);
    }
  pr.pack(o);
}

void FHE_PK::unpack(octetStream& o)
{
  char tag[8];
  o.consume((octet*) tag, 8);
  if (memcmp(tag, "PKPKPKPK", 8))
    throw runtime_error("invalid serialization of public key");
  a0.unpack(o, *params);
  b0.unpack(o, *params);
  if (params->n_mults() > 0)
    {
      Sw_a.unpack(o, *params);
      Sw_b.unpack(o, *params);
    }
  pr.unpack(o);
}


bool FHE_PK::operator!=(const FHE_PK& x) const
{
  if ((*params) != *(x.params) or pr != x.pr or a0 != x.a0 or b0 != x.b0
      or Sw_a != x.Sw_a or Sw_b != x.Sw_b)
    {
      throw runtime_error("pk");
      return true;
    }
  else
    return false;
}

void FHE_SK::check(const FHE_Params& params, const FHE_PK& pk,
        const bigint& pr) const
{
  if (this->params != &params)
    throw params_mismatch();
  if (this->pr != pr)
    throw pr_mismatch();
  pk.check(params, pr);
  sk.check(params);
}


template<class FD>
void FHE_SK::check(const FHE_PK& pk, const FD& FieldD)
{
  check(*params, pk, FieldD.get_prime());
  pk.check_noise(*this);
  if (decrypt(pk.encrypt(Plaintext_<FD>(FieldD)), FieldD) !=
      Plaintext_<FD>(FieldD))
    throw runtime_error("incorrect key pair");
}

void FHE_PK::check(const FHE_Params& params, const bigint& pr) const
{
  if (this->pr != pr)
    throw pr_mismatch();
  a0.check(params);
  b0.check(params);

  if (params.n_mults() > 0)
    {
      Sw_a.check(params);
      Sw_b.check(params);
    }
}

bigint FHE_SK::get_noise(const Ciphertext& c)
{
  sk.lower_level();
  Ciphertext cc = c;
  if (cc.level())
    cc.Scale();
  Rq_Element tmp = quasi_decrypt(cc);
  bigint res;
  bigint q = tmp.get_modulus();
  bigint half_q = q / 2;
  for (auto& x : tmp.to_vec_bigint())
    {
//      cout << numBits(x) << "/" << (x > half_q) << "/" << (x < 0) << " ";
      res = max(res, x > half_q ? x - q : x);
    }
  return res;
}


#define X(FD) \
        template void FHE_PK::encrypt(Ciphertext&, const Plaintext_<FD>& mess, \
                const Random_Coins& rc) const; \
        template Ciphertext FHE_PK::encrypt(const Plaintext_<FD>& mess) const; \
        template Plaintext_<FD> FHE_SK::decrypt(const Ciphertext& c, \
                const FD& FieldD); \
        template void FHE_SK::decrypt(Plaintext_<FD>& res, \
		const Ciphertext& c) const; \
        template void FHE_SK::decrypt_any(Plaintext_<FD>& res, \
		const Ciphertext& c); \
        template void FHE_SK::check(const FHE_PK& pk, const FD&);

X(FFT_Data)
X(P2Data)
