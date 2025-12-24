
#include "FHE/NTL-Subs.h"
#include "Math/Setup.h"

#include "Math/gfpvar.h"
#include "Math/gf2n.h"

#include "FHE/P2Data.h"
#include "FHE/QGroup.h"
#include "FHE/NoiseBounds.h"

#include "Tools/mkpath.h"
#include "Tools/CodeLocations.h"

#include "FHEOffline/Proof.h"

#include "Processor/OnlineOptions.h"

#include <fstream>
using namespace std;

#ifdef USE_NTL
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/GF2EXFactoring.h>
#include <NTL/GF2XFactoring.h>
NTL_CLIENT
#endif

#include "FHEOffline/DataSetup.h"

void generate_setup(int n, int lgp, int lg2, int sec, bool skip_2,
    int slack, bool round_up)
{
  DataSetup setup;

  // do the full setup for SHE data
  Parameters(n, lgp, sec, slack, round_up).generate_setup(setup.setup_p.params,
      setup.setup_p.FieldD);
  if (!skip_2)
    Parameters(n, lg2, sec, slack, round_up).generate_setup(
        setup.setup_2.params, setup.setup_2.FieldD);
}


bool same_word_length(int l1, int l2)
{
  return l1 / 64 == l2 / 64;
}

template <>
int generate_semi_setup(int plaintext_length, int sec,
    FHE_Params& params, FFT_Data& FTD, bool round_up, int n)
{
  CODE_LOCATION_NO_SCOPE
  int m = 1024;
  int lgp = plaintext_length;
  bigint p;
  generate_prime(p, lgp, m);
  int lgp0, lgp1;
  FHE_Params tmp_params;
  while (true)
    {
      tmp_params = params;
      SemiHomomorphicNoiseBounds nb(p, phi_N(m), n, sec,
          numBits(NonInteractiveProof::slack(sec, phi_N(m))), true, tmp_params);
      bigint p1 = 2 * p * m, p0 = p;
      while (nb.min_p0(params.n_mults() > 0, p1) > p0)
        {
          p0 *= 2;
        }
      if (phi_N(m) < nb.min_phi_m(2 + numBits(p0 * (params.n_mults() > 0 ? p1 : 1)),
          params.get_R()))
        {
          m *= 2;
          generate_prime(p, lgp, m);
        }
      else
        {
          lgp0 = numBits(p0) + 1;
          lgp1 = numBits(p1) + 1;
          break;
        }
    }

  params = tmp_params;
  int extra_slack = common_semi_setup(params, m, p, lgp0, lgp1, round_up);

  FTD.init(params.get_ring(), p);
  gfp::init_field(p);
  return extra_slack;
}

template <>
int generate_semi_setup(int plaintext_length, int sec,
    FHE_Params& params, P2Data& P2D, bool round_up, int n)
{
  CODE_LOCATION_NO_SCOPE

  if (params.n_mults() > 0)
    throw runtime_error("only implemented for 0-level BGV");
  gf2n_short::init_field(plaintext_length);
  int m;
  char_2_dimension(m, plaintext_length);
  SemiHomomorphicNoiseBounds nb(2, phi_N(m), n, sec,
      numBits(NonInteractiveProof::slack(sec, phi_N(m))), true, params);
  int lgp0 = numBits(nb.min_p0(false, 0));
  int extra_slack = common_semi_setup(params, m, 2, lgp0, -1, round_up);
  assert(nb.min_phi_m(lgp0, false) * 2 <= m);
  load_or_generate(P2D, params.get_ring());
  return extra_slack;
}

int common_semi_setup(FHE_Params& params, int m, bigint p, int& lgp0, int lgp1, bool round_up)
{
  if (OnlineOptions::singleton.has_option("verbose_he_setup"))
    {
      cout << "Need ciphertext modulus of length " << lgp0;
      if (params.n_mults() > 0)
        cout << "+" << lgp1;
      cout << " and " << phi_N(m) << " slots" << endl;
    }

  int extra_slack = 0;
  if (round_up)
    {
      int i;
      for (i = 0; i <= 20; i++)
        {
          if (SemiHomomorphicNoiseBounds::min_phi_m(lgp0 + i, params) > phi_N(m))
            break;
          if (not same_word_length(lgp0, lgp0 + i))
            break;
        }
      extra_slack = i - 1;
      lgp0 += extra_slack;
#ifdef VERBOSE
      cout << "Rounding up to " << lgp0 << ", giving extra slack of "
          << extra_slack << " bits" << endl;
#endif
    }

  Ring R;
  ::init(R, m);
  bigint p0, p1 = 1;
  if (params.n_mults() > 0)
  {
    generate_moduli(p0, p1, m, p, lgp0, lgp1);
    params.set(R, {p0, p1});
  }
  else
  {
    generate_modulus(p0, m, p, lgp0);
    params.set(R, {p0});
  }
  return extra_slack;
}

int finalize_lengths(int& lg2p0, int& lg2p1, int n, int m, int* lg2pi,
    bool round_up, FHE_Params& params)
{
  (void) lg2pi, (void) n;

  bool verbose = OnlineOptions::singleton.has_option("verbose_he_setup");

  if (verbose)
    {
        if (n >= 2 and n <= 10)
            cerr << "Difference to suggestion for p0: " << lg2p0 - lg2pi[n - 2]
                    << ", for p1: " << lg2p1 - lg2pi[9 + n - 2] << endl;
        cerr << "p0 needs " << int(ceil(1. * lg2p0 / 64)) << " words" << endl;
        cerr << "p1 needs " << int(ceil(1. * lg2p1 / 64)) << " words" << endl;
    }

  int extra_slack = 0;
  if (round_up)
    {
      int i = 0;
      for (i = 0; i < 10; i++)
        {
          if (phi_N(m) < NoiseBounds::min_phi_m(lg2p0 + lg2p1 + 2 * i, params))
            break;
          if (not same_word_length(lg2p0 + i, lg2p0))
            break;
          if (not same_word_length(lg2p1 + i, lg2p1))
            break;
        }
      i--;
      extra_slack = 2 * i;
      lg2p0 += i;
      lg2p1 += i;

        if (verbose)
            cerr << "Rounding up to " << lg2p0 << "+" << lg2p1
                    << ", giving extra slack of " << extra_slack << " bits"
                    << endl;
    }

    if (verbose)
        cerr << "Total length: " << lg2p0 + lg2p1 << " = " << lg2p0 << " + "
                << lg2p1 << endl;

  return extra_slack;
}
 


/*
 * Subroutine for creating the FHE parameters
 */
int Parameters::SPDZ_Data_Setup_Char_p_Sub(int idx, int& m, bigint& p,
    FHE_Params& params)
{
  int n = n_parties;
  int lg2pi[5][2][9]
             = {  {  {130,132,132,132,132,132,132,132,132},
                     {104,104,104,106,106,108,108,110,110} },
                  {  {196,196,196,196,198,198,198,198,198},
                     {136,138,140,142,140,140,140,142,142} },
                  {  {325,325,325,325,330,330,330,330,330},
                     {205,205,205,210,205,205,205,205,210} },
                  {  {580,585,585,585,585,585,585,585,585},
                     {330,330,330,335,335,335,335,335,335} },
                  {  {1095,1095,1095,1095,1095,1095,1095,1095,1095},
                     {590,590,590,590,590,595,595,595,595} }
               };

  int lg2p0 = 0, lg2p1 = 0;
  if (n >= 2 and n <= 10)
    {
      lg2p0=lg2pi[idx][0][n-2];
      lg2p1=lg2pi[idx][1][n-2];
    }
  else if (sec == -1)
    throw runtime_error("no precomputed parameters available");

  while (sec != -1)
    {
      double phi_m_bound =
              NoiseBounds(p, phi_N(m), n, sec, slack, params).optimize(lg2p0, lg2p1);

#ifdef VERBOSE
      cout << "Trying primes of length " << lg2p0 << " and " << lg2p1 << endl;
#endif

      if (phi_N(m) < phi_m_bound)
        {
          int old_m = m;
          (void) old_m;
          m = 2 << int(ceil(log2(phi_m_bound)));

#ifdef VERBOSE
          cout << "m = " << old_m << " too small, increasing it to " << m << endl;
#endif

          generate_prime(p, numBits(p), m);
        }
      else
        break;
    }

  init(R,m);
  int extra_slack = finalize_lengths(lg2p0, lg2p1, n, m, lg2pi[idx][0],
      round_up, params);
  generate_moduli(pr0, pr1, m, p, lg2p0, lg2p1);
  return extra_slack;
}

void generate_moduli(bigint& pr0, bigint& pr1, const int m, const bigint p,
        const int lg2p0, const int lg2p1)
{
  generate_modulus(pr0, m, p, lg2p0, "0");
  generate_modulus(pr1, m, p, lg2p1, "1", pr0);
}

void generate_modulus(bigint& pr, const int m, const bigint p, const int lg2pr,
    const string& i, const bigint& pr0)
{
  (void) i;

  if (lg2pr==0) { throw invalid_params(); }

  bigint step=m;
  bigint twop=1<<(numBits(m)+1);
  bigint gc=gcd(step,twop);
  step=step*twop/gc;

  step *= p;
  pr = (bigint(1) << lg2pr) / step * step + 1;

  while (pr == pr0 || !probPrime(pr))
    {
      pr -= step;
      assert(numBits(pr) == lg2pr);
    }

#ifdef VERBOSE
  cout << "\t pr" << i << " = " << pr << "  :   " << numBits(pr) <<  endl;
  cout << "Minimal MAX_MOD_SZ = " << int(ceil(1. * lg2pr / 64)) << endl;
#endif

  assert(pr % m == 1);
  assert(pr % p == 1);
  assert(numBits(pr) == lg2pr);
}

/*
 * Create the char p FHE parameters
 */
template <>
void Parameters::SPDZ_Data_Setup(FHE_Params& params, FFT_Data& FTD)
{
  CODE_LOCATION_NO_SCOPE

  bigint p;
  int idx, m;
  SPDZ_Data_Setup_Primes(p, plaintext_length, idx, m);
  SPDZ_Data_Setup_Char_p_Sub(idx, m, p, params);

  Zp_Data Zp(p);
  gfp::init_field(p);
  FTD.init(R,Zp);
}

#ifdef USE_NTL
/* Compute Phi(N) */
int phi_N(int N)
{
  int phiN=1,p,e;
  PrimeSeq s;
  while (N!=1)
    { p=s.next();
      e=0;
      while ((N%p)==0) { N=N/p; e++; }
      if (e!=0)
        { phiN=phiN*(p-1)*power_long(p,e-1); }
    }
  return phiN;
}


/* Compute mobius function (naive method as n is small) */
int mobius(int n)
{
  int p,e,arity=0;
  PrimeSeq s;
  while (n!=1)
    { p=s.next();
      e=0;
      while ((n%p)==0) { n=n/p; e++; }
      if (e>1) { return 0; }
      if (e!=0) { arity^=1; }
    }     
  if (arity==0) { return 1; }
  return -1;
}



/* Compute cyclotomic polynomial */
ZZX Cyclotomic(int N)
{
  ZZX Num,Den,G,F;
  NTL::set(Num); NTL::set(Den);
  int m,d;

  for (d=1; d<=N; d++)
    { if ((N%d)==0)
         { clear(G);
           SetCoeff(G,N/d,1); SetCoeff(G,0,-1);
           m=mobius(d);
           if (m==1)       { Num*=G; }
           else if (m==-1) { Den*=G; }
         }
    } 
  F=Num/Den;
  return F;
}
#else
// simplified version powers of two
int phi_N(int N)
{
  if (((N - 1) & N) != 0)
    throw runtime_error(
        "compile with NTL support (USE_NTL=1 in CONFIG.mine)");
  else if (N == 1)
    return 1;
  else
    return N / 2;
}
#endif


void init(Ring& Rg, int m, bool generate_poly)
{
  Rg.mm=m;
  Rg.phim=phi_N(Rg.mm);

  Rg.pi.resize(Rg.phim);    Rg.pi_inv.resize(Rg.mm);
  for (int i=0; i<Rg.mm; i++) { Rg.pi_inv[i]=-1; }

  if (((m - 1) & m) == 0 and not generate_poly)
    {
      // m is power of two
      // no need to generate poly
      int k = 0;
      for (int i = 1; i < Rg.mm; i++)
        {
          // easy GCD
          if (i % 2 == 1)
            {
              Rg.pi[k] = i;
              Rg.pi_inv[i] = k;
              k++;
            }
        }
    }
  else
    {
#ifdef USE_NTL
      int k=0;
      for (int i=1; i<Rg.mm; i++)
        { if (gcd(i,Rg.mm)==1)
          { Rg.pi[k]=i;
          Rg.pi_inv[i]=k;
          k++;
          }
        }

      ZZX P=Cyclotomic(Rg.mm);
      Rg.poly.resize(Rg.phim+1);
      for (int i=0; i<Rg.phim+1; i++)
        { Rg.poly[i]=to_int(coeff(P,i)); }
#else
      throw runtime_error(
          "compile with NTL support (USE_NTL=1 in CONFIG.mine)");
#endif
    }
}


#ifdef USE_NTL
// Computes a(b) mod c
GF2X Subs_Mod(const GF2X& a,const GF2X& b,const GF2X& c)
{
  GF2X ans,pb,bb=b%c;
  ans=to_GF2X(coeff(a,0));
  pb=bb;
  for (int i=1; i<=deg(a); i++)
    { ans=ans+pb*coeff(a,i);
      pb=MulMod(pb,bb,c);
    }
  return ans;
}


// Computes a(x^pow) mod c  where x^m=1
GF2X Subs_PowX_Mod(const GF2X& a,int pow,int m,const GF2X& c)
{
  GF2X ans; ans.SetMaxLength(m);
  for (int i=0; i<=deg(a); i++)
    { int j=MulMod(i,pow,m);
      if (IsOne(coeff(a,i))) { SetCoeff(ans,j,1); }
    }
  ans=ans%c;
  return ans;
}



GF2X get_F(const Ring& Rg)
{
  GF2X F;
  for (int i=0; i<=Rg.phi_m(); i++)
    { if (((Rg.Phi()[i])%2)!=0)
        { SetCoeff(F,i,1); }
    }
  //cout << "F = " << F << endl;
  return F;
}

void init(P2Data& P2D,const Ring& Rg)
{
  GF2X G,F;
  SetCoeff(G,gf2n_short::degree(),1);
  SetCoeff(G,0,1);
  for (int i=0; i<gf2n_short::get_nterms(); i++)
    { SetCoeff(G,gf2n_short::get_t(i),1); }
  //cout << "G = " << G << endl;

  F = get_F(Rg);

  // seed randomness to achieve same result for all players
  // randomness is used in SFCanZass and FindRoot
  SetSeed(ZZ(0));

  // Now factor F modulo 2
  vec_GF2X facts=SFCanZass(F);

  // Check all is compatible
  int d=deg(facts[0]);
  if (d%deg(G)!=0)
    { throw invalid_params(); }

  // Compute the quotient group
  QGroup QGrp;
  int Gord=-1,e=Rg.phi_m()/d; // e = # of plaintext slots, phi(m)/degree

  if ((e*gf2n_short::degree())!=Rg.phi_m())
    { cout << "Plaintext type requires Gord*gf2n_short::degree ==  phi_m" << endl;
      cout << e << " * " << gf2n_short::degree() << " != " << Rg.phi_m() << endl;
      throw invalid_params();
    }

  int max_tries = 10;
  for (int seed = 0;; seed++)
    { QGrp.assign(Rg.m(),seed);       // QGrp encodes the the quotient group Z_m^*/<2>
      Gord = QGrp.order();
      if (Gord == e)
        {
          break;
        }
      else
        {
          if (seed == max_tries)
            {
              cerr << "abort after " << max_tries << " tries" << endl;
              throw invalid_params();
            }
          else
            cout << "Group order wrong, need to repeat the Haf-Mc algorithm"
                << endl;
        }
    }
  //cout << " l = " << Gord << " , d = " << d << endl;

  vector<GF2X> Fi(Gord);
  vector<GF2X> Rts(Gord);
  vector<GF2X> u(Gord);
  /*
     Find map from Type 0 (mod G) -> Type 1 (mod Fi)
     for the first of the Fi's only
  */
  Fi[0]=facts[0];
  GF2E::init(facts[0]);     // work with the extension field GF_2[X]/Fi[0]
  GF2EX Ga=to_GF2EX(G);     // represent G as a polynomial over the extension field
  Rts[0]=rep(FindRoot(Ga)); // Find a roof of G in this field

  cout << "Fixing field ordering and the maps (Need to count to " << Gord << " here)\n\t";
  GF2E::init(G);
  GF2X g;
  vector<int> used(facts.length());
  for (int i=0; i<facts.length(); i++) { used[i]=0; }
  used[0]=1;
  for (int i=0; i<Gord; i++)
    { cout << i << " " << flush;
      if (i!=0)
        { int hpow=QGrp.nth_element(i);
          Rts[i]=Subs_PowX_Mod(Rts[0],hpow,Rg.m(),F);
          bool flag=false;
          for (int j=0; j<facts.length(); j++)
            { if (used[j]==0)
                { g=Subs_PowX_Mod(facts[0],hpow,Rg.m(),facts[j]);
                  if (IsZero(g))
                    { g=Subs_Mod(G,Rts[i],facts[j]);
                      if (!IsZero(g))
                        { cout << "Something wrong - G" << endl;
                          throw invalid_params();
                        }
                      Fi[i]=facts[j];
                      used[j]=1;
                      flag=true;
                      break;
                    }
                }
            }
          if (flag==false)
           { cout << "Something gone wrong" << endl;
             throw invalid_params();
           }
          Rts[i]=Rts[i]%Fi[i];
        }

     // Now sort out the projection map (for CRT reconstruction)
     GF2X te=(F/Fi[i]);
     GF2X tei=InvMod(te%Fi[i],Fi[i]);
     u[i]=MulMod(te,tei,F); // u[i] = \prod_{j!=i} F[j]*(F[j]^{-1} mod F[i])
   }
  cout << endl;

  // Make the forward matrix
  //   This is a deg(F) x (deg(G)*Gord)  matrix which maps elements
  //   vectors in the SIMD representation into plaintext vectors
  
  imatrix A;
  A.resize(Rg.phi_m(), imatrix::value_type(Gord*gf2n_short::degree()));
  P2D.A.resize(A[0].size());
  for (auto& x : P2D.A)
    x.resize(A.size());
  for (int slot=0; slot<Gord; slot++)
    { for (int co=0; co<gf2n_short::degree(); co++)
        { // Work out how x^co in given slot maps to plaintext vector
          GF2X av;
          SetCoeff(av,co,1);
          // av is mod G, now map to mod Fi
          av=Subs_Mod(av,Rts[slot],Fi[slot]);
          // Now need to map using CRT to the plaintext vector
          av=MulMod(av,u[slot],F);
          //cout << slot << " " << co << " : " << av << endl;
          for (int k=0; k<Rg.phi_m(); k++)
	    {
              int i = slot*gf2n_short::degree()+co;
              if (IsOne(coeff(av,k)))
                { A[k][i]=1; }
              else
                { A[k][i]=0; }
	      P2D.A[i][k] = A[k][i];
	    }
       }
    }
  //cout << "Forward Matrix : " << endl; print(P2D.A);

  // Find pseudo inverse modulo 2
  pinv(P2D.Ai, A);
  P2D.Ai.resize(Gord*gf2n_short::degree());

  //cout << "Inverse Matrix : " << endl; print(P2D.Ai);

  P2D.slots=Gord;

}
#else
void init(P2Data&, const Ring&)
{
  throw runtime_error("need to compile with 'USE_NTL=1' in 'CONFIG'");
}
#endif

/*
 * Create the FHE parameters
 */
void char_2_dimension(int& m, int& lg2)
{
  switch (lg2)
    { case -1:
        m=17;
        lg2=8;
        break;
      case 40:
        m=13175;
        break;
      case -40:
        m=5797;
        lg2=40;
        break;
      case 64:
        m = 9615;
        break;
      case 63:
        m = 9271;
        break;
      case 28:
        m = 3277;
        break;
      case 16:
        m = 4369;
        break;
      case 15:
        m = 4681;
        break;
      case 12:
        m = 4095;
        break;
      case 11:
        m = 2047;
        break;
      default:
        throw runtime_error("field size not supported");
        break;
    }
}

template <>
void Parameters::SPDZ_Data_Setup(FHE_Params& params, P2Data& P2D)
{
  CODE_LOCATION_NO_SCOPE

  int n = n_parties;
  int lg2 = plaintext_length;

  int lg2pi[2][9]
             = {  {70,70,70,70,70,70,70,70,70},
                  {70,75,75,75,75,80,80,80,80}
               };

  cout << "Setting up parameters\n";
  if ((n<2 || n>10) and sec == -1) { throw invalid_params(); }

  int m,lg2p0,lg2p1,ex;

  char_2_dimension(m, lg2);

  if (sec == -1)
  {
    lg2p0=lg2pi[0][n-2];
    lg2p1=lg2pi[1][n-2];
  }
  else
  {
    NoiseBounds(2, phi_N(m), n, sec, slack, params).optimize(lg2p0, lg2p1);
    finalize_lengths(lg2p0, lg2p1, n, m, lg2pi[0], round_up, params);
  }

  if (NoiseBounds::min_phi_m(lg2p0 + lg2p1, params) * 2 > m)
    throw runtime_error("number of slots too small");

  cout << "m = " << m << endl;
  init(R,m);

  if (lg2p0==0 || lg2p1==0) { throw invalid_params(); }

  // We want pr0=pr1=1 mod (m*twop) where twop is the smallest 
  // power of two bigger than 2*m. This means we have m'th roots of
  // unity and twop'th roots of unity. This means FFT's are easier
  // to implement
  int lg2m=numBits(m);
  bigint step=m<<(lg2m+1);
  
  ex=lg2p0-2*lg2m;
  pr0=1; pr0=(pr0<<ex)*step+1;
  while (!probPrime(pr0)) { pr0=pr0+step; }
  cout << "\t pr0 = " << pr0 << "  :   " << numBits(pr0) << endl;

  ex=lg2p1-2*lg2m;
  pr1=1; pr1=(pr1<<ex)*step+1;
  while (!probPrime(pr1) || pr1==pr0) { pr1=pr1+step; }
  cout << "\t pr1 = " << pr1 << "  :   " << numBits(pr1) <<  endl;

  cout << "\t\tFollowing should be both 1" << endl;
  cout << "\t\tpr1 mod m = " << pr1%m << endl;
  cout << "\t\tpr1 mod 2^lg2m = " << pr1%(1<<lg2m) << endl;

  gf2n_short::init_field(lg2);
  load_or_generate(P2D, R);
}

void load_or_generate(P2Data& P2D, const Ring& R)
{
  try
  {
      P2D.load(R);
  }
  catch (exception& e)
  {
      cerr << "Loading parameters failed, generating (" << e.what() << ")" << endl;
      init(P2D,R);
      P2D.store(R);
  }
}
