#ifndef _Proof
#define _Proof

#include <math.h>
#include <vector>
using namespace std;

#include "Math/bigint.h"
#include "FHE/Ciphertext.h"
#include "FHE/AddableVector.h"
#include "Protocols/CowGearOptions.h"
#include "Processor/OnlineOptions.h"

#include "config.h"

enum SlackType
{
  NONINTERACTIVE_SPDZ1_SLACK = -1,
  INTERACTIVE_SPDZ1_SLACK = -2,
  COVERT_SPDZ2_SLACK = -3,
  ACTIVE_SPDZ2_SLACK = -4,
};

class Proof
{
  protected:

  unsigned int sec;

  bool diagonal;

  Proof();   // Private to avoid default 

  public:

  typedef AddableVector< Int_Random_Coins > Randomness;
  typedef typename FFT_Data::poly_type bound_type;

  class Preimages
  {
    typedef Int_Random_Coins::value_type::value_type r_type;

    bound_type m_tmp;
    AddableVector<r_type> r_tmp;

  public:
    Preimages(int size, const FHE_PK& pk, const bigint& p, int n_players);
    AddableMatrix<bound_type> m;
    Randomness r;
    void add(octetStream& os);
    void pack(octetStream& os);
    void unpack(octetStream& os);
    void check_sizes();
    size_t report_size(ReportType type) { return m.report_size(type) + r.report_size(type); }
  };

  bigint tau,rho;

  unsigned int phim;
  int B_plain_length, B_rand_length;
  bigint plain_check, rand_check;
  unsigned int V;
  unsigned int U;

  const FHE_PK* pk;

  int n_proofs;

  vector<int> e;
  vector<vector<int>> W;
  bool top_gear;

  static double dist;

  protected:
    typedef AddableVector<bound_type> T;
    typedef AddableMatrix<typename Int_Random_Coins::rand_type> X;

    Proof(int sc, const bigint& Tau, const bigint& Rho, const FHE_PK& pk,
            int n_proofs = 1, bool diagonal = false) :
              diagonal(diagonal),
              B_plain_length(0), B_rand_length(0), pk(&pk), n_proofs(n_proofs)
    { sec=sc;
      assert(sec > 0);
      tau=Tau; rho=Rho;

      phim=(pk.get_params()).phi_m();

      top_gear = use_top_gear(pk);
      if (top_gear)
        {
          V = ceil((sec + 2) / log2(2 * phim + 1));
          U = 2 * V;
        }
      else
        {
          U = sec;
          V = 2 * sec - 1;
        }
    }

  Proof(int sec, const FHE_PK& pk, int n_proofs = 1, bool diagonal = false) :
      Proof(sec, pk.p() / 2,
          pk.get_params().get_DG().get_NewHopeB(), pk,
          n_proofs, diagonal) {}

  virtual ~Proof() {}

  public:
  static bigint slack(int slack, int sec, int phim);

  bool use_top_gear(const FHE_PK& pk)
  {
    return CowGearOptions::singleton.top_gear() and pk.p() > 2 and
        not diagonal;
  }

  bool get_diagonal() const
  {
    return diagonal;
  }

  static int n_ciphertext_per_proof(int sec, const FHE_PK& pk, bool diagonal =
      false)
  {
    return Proof(sec, pk, 1, diagonal).U;
  }

  void set_challenge(const octetStream& ciphertexts);
  void set_challenge(PRNG& G);
  void generate_challenge(const Player& P);

  bool check_bounds(T& z, X& t, int i) const;

  template<class T, class U>
  void apply_challenge(int i, T& output, const U& input, const FHE_PK& pk) const
  {
    if (top_gear)
      {
        for (unsigned j = 0; j < this->U; j++)
          if (W[i][j] >= 0)
            output += input[j].mul_by_X_i(W[i][j], pk);
      }
    else
      for (unsigned k = 0; k < sec; k++)
        {
          unsigned j = (i + 1) - (k + 1);
          if (j < sec && e.at(j))
            output += input.at(j);
        }
  }

  void debugging()
  {
    if (OnlineOptions::singleton.has_option("verbose_he"))
      {
        cerr << "Using " << U << " ciphertexts per proof" << endl;
        cerr << "Plaintext bound check bit length: " << B_plain_length << endl;
        cerr << "Randomness bound check bit length: " << B_rand_length << endl;
      }
  }
};

class NonInteractiveProof : public Proof
{
public:
  // sec = 0 used for protocols without proofs
  static int comp_sec(int sec);

  bigint static slack(int sec, int phim)
  { sec = comp_sec(sec); return bigint(phim * sec * sec) << (sec / 2 + 8); }

  NonInteractiveProof(int sec, const FHE_PK& pk,
      int extra_slack, bool diagonal = false) :
      Proof(comp_sec(sec), pk, 1, diagonal)
  {
    sec = this->sec;
    bigint B;
    B=128*sec*sec;
    B <<= extra_slack;
    B_plain_length = numBits(B*phim*tau);
    B_rand_length = numBits(B*3*phim*rho);
    plain_check = (bigint(1) << B_plain_length) - sec * tau;
    rand_check = (bigint(1) << B_rand_length) - sec * rho;
    debugging();
  }
};

class InteractiveProof : public Proof
{
public:
  bigint static slack(int sec, int phim)
  { (void)phim; return pow(2, 1.5 * sec + 1); }

  InteractiveProof(int sec, const FHE_PK& pk,
      int n_proofs = 1, bool diagonal = false) :
      Proof(sec, pk, n_proofs, diagonal)
  {
    bigint B;
    B = bigint(1) << sec;
    B_plain_length = numBits(B * tau);
    B_rand_length = numBits(B * rho);
    // leeway for completeness
    plain_check = (bigint(2) << B_plain_length);
    rand_check = (bigint(2) << B_rand_length);
    debugging();
  }
};

#endif
