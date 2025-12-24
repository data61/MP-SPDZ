/*
 * Proof.cpp
 *
 */

#include "Proof.h"
#include "FHE/P2Data.h"
#include "FHEOffline/EncCommit.h"
#include "Math/Z2k.hpp"

double Proof::dist = 0;

bigint Proof::slack(int slack, int sec, int phim)
{
  switch (slack)
  {
    case NONINTERACTIVE_SPDZ1_SLACK:
      cout << "Computing slack for non-interactive SPDZ1 proof" << endl;
      return NonInteractiveProof::slack(sec, phim);
    case INTERACTIVE_SPDZ1_SLACK:
      cout << "Computing slack for interactive SPDZ1 proof" << endl;
      return InteractiveProof::slack(sec, phim);
    case COVERT_SPDZ2_SLACK:
      cout << "No slack for covert SPDZ2 proof" << endl;
      return 0;
    case ACTIVE_SPDZ2_SLACK:
      cout << "Computing slack for active SPDZ2 proof" << endl;
      return EncCommit_<FFT_Data>::active_slack(phim);
    default:
      if (slack < 0)
        throw runtime_error("slack type unknown");
      return bigint(1) << slack;
  }
}

void Proof::set_challenge(const octetStream& ciphertexts)
{
  octetStream hash = ciphertexts.hash();
  PRNG G;
  assert(hash.get_length() >= SEED_SIZE);
  G.SetSeed(hash.get_data());
  set_challenge(G);
}

void Proof::set_challenge(PRNG& G)
{
  unsigned int i;

  if (top_gear)
    {
      W.resize(V, vector<int>(U));
      for (i = 0; i < V; i++)
        for (unsigned j = 0; j < U; j++)
          W[i][j] = G.get_uint(2 * phim) - 1;
    }
  else
    {
      e.resize(sec);
      for (i = 0; i < sec; i++)
        {
          e[i] = G.get_bit();
        }
    }
}

void Proof::generate_challenge(const Player& P)
{
  GlobalPRNG G(P);
  set_challenge(G);
}

template<class T>
class AbsoluteBoundChecker
{
  T bound, neg_bound;

public:
  AbsoluteBoundChecker(T bound) : bound(bound), neg_bound(-this->bound) {}
  bool outside(const T& value, double& dist)
  {
    (void)dist;
#ifdef PRINT_MIN_DIST
    dist = max(dist, abs(value.get_d()) / bound.get_d());
#endif
    return value > bound || value < neg_bound;
  }
};

bool Proof::check_bounds(T& z, X& t, int i) const
{
  (void)i;
  unsigned int j,k;

  // Check Bound 1 and Bound 2
  AbsoluteBoundChecker<bound_type> plain_checker(plain_check * n_proofs);
  AbsoluteBoundChecker<typename Int_Random_Coins::rand_type> rand_checker(
      rand_check * n_proofs);
  for (j=0; j<phim; j++)
    {
      auto& te = z[j];
      if (plain_checker.outside(te, dist))
        {
#ifdef VERBOSE
          cout << "Fail on Check 1 " << i << " " << j << endl;
          cout << te << "  " << plain_check << endl;
          cout << tau << " " << sec << " " << n_proofs << endl;
#endif
          return false;
        }
    }
  for (k=0; k<3; k++)
    {
      auto& coeffs = t[k];
      for (j=0; j<coeffs.size(); j++)
        {
          auto& te = coeffs.at(j);
          if (rand_checker.outside(te, dist))
            {
#ifdef VERBOSE
              cout << "Fail on Check 2 " << k << " : " << i << " " << j << endl;
              cout << te << "  " << rand_check << endl;
              cout << rho << " " << sec << " " << n_proofs << endl;
#endif
              return false;
            }
        }
    }
  return true;
}

Proof::Preimages::Preimages(int size, const FHE_PK& pk, const bigint& p, int n_players) :
    r(size, pk.get_params())
{
  m.resize(size, pk.get_params().phi_m());
  // extra limb for addition
  bigint limit = p << (64 + n_players);
  m.allocate_slots(limit);
  r.allocate_slots(n_players);
  m_tmp = m[0][0];
  r_tmp = r[0][0];
}

void Proof::Preimages::add(octetStream& os)
{
  check_sizes();
  unsigned int size;
  os.get(size);
  if (size != m.size())
    throw length_error("unexpected size received");
  for (size_t i = 0; i < m.size(); i++)
    {
      m[i].add(os, m_tmp);
      r[i].add(os, r_tmp);
    }
}

void Proof::Preimages::pack(octetStream& os)
{
  check_sizes();
  os.store((unsigned int)m.size());
  for (size_t i = 0; i < m.size(); i++)
    {
      m[i].pack(os);
      r[i].pack(os);
    }
}

void Proof::Preimages::unpack(octetStream& os)
{
  unsigned int size;
  os.get(size);
  m.resize(size);
  assert(not r.empty());
  r.resize(size, r[0]);
  for (size_t i = 0; i < m.size(); i++)
    {
      m[i].unpack(os);
      r[i].unpack(os);
    }
}

void Proof::Preimages::check_sizes()
{
  if (m.size() != r.size())
    throw runtime_error("preimage sizes don't match");
}

int NonInteractiveProof::comp_sec(int sec)
{
  if (sec > 0)
    return OnlineOptions::singleton.comp_sec();
  else
    return 0;
}
