
#include "Prover.h"
#include "Verifier.h"

#include "FHE/P2Data.h"
#include "Tools/random.h"
#include "Math/Z2k.hpp"
#include "Math/modp.hpp"
#include "FHE/AddableVector.hpp"


template <class FD, class U>
Prover<FD,U>::Prover(Proof& proof, const FD& FieldD) :
  volatile_memory(0)
{
  s.resize(proof.V, proof.pk->get_params());
  y.resize(proof.V, FieldD);
#ifdef LESS_ALLOC_MORE_MEM
  t = s[0];
  z = y[0];
  // extra limb to prevent reallocation
  t.allocate_slots(bigint(1) << (proof.B_rand_length + 64));
  z.allocate_slots(bigint(1) << (proof.B_plain_length + 64));
  s.allocate_slots(bigint(1) << proof.B_rand_length);
  y.allocate_slots(bigint(1) << proof.B_plain_length);
#endif
}

template <class FD, class U>
void Prover<FD,U>::Stage_1(const Proof& P, octetStream& ciphertexts,
    const AddableVector<Ciphertext>& c,
    const FHE_PK& pk)
{
  size_t allocate = 3 * c.size() * c[0].report_size(USED);
  ciphertexts.resize_precise(allocate);
  ciphertexts.reset_write_head();
  c.pack(ciphertexts);

  int V=P.V;

//  AElement<T> AE;
//  ZZX rd;
//  ZZ pr=(*AE.A).prime();
//  ZZ bd=B_plain/(pr+1);
  PRNG G;
  G.ReSeed();
  Random_Coins rc(pk.get_params());
  Ciphertext ciphertext(pk.get_params());
  ciphertexts.store(V);
  for (int i=0; i<V; i++)
    {
//      AE.randomize(Diag,binary);
//      rd=RandPoly(phim,bd<<1);
//      y[i]=AE.plaintext()+pr*rd;
      y[i].randomize(G, P.B_plain_length, P.get_diagonal());
      if (P.get_diagonal())
        assert(y[i].is_diagonal());
      s[i].resize(3, P.phim);
      s[i].generateUniform(G, P.B_rand_length);
      rc.assign(s[i][0], s[i][1], s[i][2]);
      pk.encrypt(ciphertext,y[i],rc);
      ciphertext.pack(ciphertexts);
    }
}


template <class FD, class U>
bool Prover<FD,U>::Stage_2(Proof& P, octetStream& cleartexts,
                        const vector<U>& x,
                        const Proof::Randomness& r,
                        const FHE_PK& pk)
{
  size_t allocate = P.V * P.phim
      * (5 + numBytes(P.plain_check) + 3 * (5 + numBytes(P.rand_check)));
  cleartexts.resize_precise(allocate);
  cleartexts.reset_write_head();

  unsigned int i;
#ifndef LESS_ALLOC_MORE_MEM
  AddableVector<fixint<gfp::N_LIMBS>> z;
  AddableMatrix<fixint<gfp::N_LIMBS>> t;
#endif
  cleartexts.reset_write_head();
  cleartexts.store(P.V);
  if (P.get_diagonal())
    for (auto& xx : x)
      assert(xx.is_diagonal());
  for (i=0; i<P.V; i++)
    { z=y[i];
      t=s[i];
      P.apply_challenge(i, z, x, pk);
      Check_Decoding(z, P.get_diagonal(), x[0].get_field());
      P.apply_challenge(i, t, r, pk);
      if (not P.check_bounds(z, t, i))
          return false;
      z.pack(cleartexts);
      t.pack(cleartexts);
   }
#ifndef LESS_ALLOC_MORE_MEM
  volatile_memory = t.report_size(CAPACITY) + z.report_size(CAPACITY);
#endif
#ifdef PRINT_MIN_DIST
  cout << "Minimal distance (log) " << log2(P.dist) << ", compare to " <<
      log2(P.plain_check.get_d() / pow(2, P.B_plain_length))  << endl;
#endif
  return true;
}



/* This is the non-interactive version using the ROM 
*/
template <class FD, class U>
size_t Prover<FD,U>::NIZKPoK(Proof& P, octetStream& ciphertexts, octetStream& cleartexts,
                        const FHE_PK& pk,
                        const AddableVector<Ciphertext>& c,
                        const vector<U>& x,
                        const Proof::Randomness& r,
                        int prover)
{
//  AElement<T> AE;
//  for (i=0; i<P.sec; i++)
//    { AE.assign(x.at(i));
//      if (!AE.to_type(0))
//         { cout << "Error in making x[i]" << endl;
//           cout << i << endl;
//         }
//    }

  bool ok=false;
  int cnt=0;
  (void) cnt;
  while (!ok)
    { cnt++;
      Stage_1(P,ciphertexts,c,pk);
      P.set_challenge(ciphertexts, prover, pk);
      // Check check whether we are OK, or whether we should abort
      ok = Stage_2(P,cleartexts,x,r,pk);
    }
#ifdef VERBOSE
  if (cnt > 1)
      cout << "\t\tNumber iterations of prover = " << cnt << endl;
#endif
  return report_size(CAPACITY) + volatile_memory;
}


template<class FD, class U>
size_t Prover<FD,U>::report_size(ReportType type)
{
  size_t res = 0;
  for (unsigned int i = 0; i < s.size(); i++)
    res += s[i].report_size(type);
  for (unsigned int i = 0; i < y.size(); i++)
    res += y[i].report_size(type);
#ifdef LESS_ALLOC_MORE_MEM
  res += z.report_size(type) + t.report_size(type);
#endif
  return res;
}


template<class FD, class U>
void Prover<FD, U>::report_size(ReportType type, MemoryUsage& res)
{
  res.update("prover s", s.report_size(type));
  res.update("prover y", y.report_size(type));
#ifdef LESS_ALLOC_MORE_MEM
  res.update("prover z", z.report_size(type));
  res.update("prover t", t.report_size(type));
#endif
  res.update("prover volatile", volatile_memory);
}


template class Prover<FFT_Data, Plaintext_<FFT_Data> >;
//template class Prover<FFT_Data, AddableVector<bigint> >;

template class Prover<P2Data, Plaintext_<P2Data> >;
//template class Prover<P2Data, AddableVector<bigint> >;
