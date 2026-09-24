#include "Verifier.h"
#include "FHE/P2Data.h"
#include "Math/Z2k.hpp"
#include "Math/modp.hpp"

template <class FD>
Verifier<FD>::Verifier(Proof& proof, const FD& FieldD) :
    P(proof), FieldD(FieldD)
{
#ifdef LESS_ALLOC_MORE_MEM
  z.resize(proof.phim);
  z.allocate_slots(bigint(1) << proof.B_plain_length);
  t.resize(3, proof.phim);
  t.allocate_slots(bigint(1) << proof.B_rand_length);
#endif
}


template <class T, class FD, class S>
bool Check_Decoding(const Plaintext<T,FD,S>& AE,bool Diag)
{
//  // Now check decoding z[i]
//  if (!AE.to_type(0))
//    { cout << "Fail Check 4 " << endl;
//      return false;
//    }
  if (Diag && !AE.is_diagonal())
    {
#ifdef VERBOSE
      cout << "Fail Check 5 " << endl;
#endif
      return false;
    }
  return true;
}

template <>
bool Check_Decoding(const vector<Proof::bound_type>& AE, bool Diag, const FFT_Data&)
{
  if (Diag)
    {
      for (size_t i = 1; i < AE.size(); i++)
        if (AE[i] != 0)
          return false;
    }
  return true;
}

template <>
bool Check_Decoding(const vector<Proof::bound_type>& AE, bool Diag, const P2Data& p2d)
{
  if (Diag)
    {
      Plaintext_<P2Data> tmp(p2d);
      for (size_t i = 0; i < AE.size(); i++)
        tmp.set_coeff(i, AE[i].get_limb(0) % 2);
      return tmp.is_diagonal();
    }
  return true;
}



template <class FD>
void Verifier<FD>::Stage_2(
                          AddableVector<Ciphertext>& c,octetStream& ciphertexts,
                          octetStream& cleartexts,
                          const FHE_PK& pk)
{
  unsigned int i, V;

  c.unpack(ciphertexts, pk);
  if (c.size() != P.U)
    throw length_error("number of received ciphertexts incorrect");

  // Now check the encryptions are correct
  Ciphertext d1(pk.get_params()), d2(pk.get_params());
  Random_Coins rc(pk.get_params());
  ciphertexts.get(V);
  if (V != P.V)
    throw length_error("number of received commitments incorrect");
  cleartexts.get(V);
  if (V != P.V)
    throw length_error("number of received cleartexts incorrect");
  for (i=0; i<V; i++)
    {
      z.unpack(cleartexts);
      t.unpack(cleartexts);
      if (!P.check_bounds(z, t, i))
        throw runtime_error("preimage out of bounds");
      d1.unpack(ciphertexts);
      P.apply_challenge(i, d1, c, pk);
      rc.assign(t[0], t[1], t[2]);
      pk.encrypt(d2,z,rc);
      if (!(d1 == d2))
        {
#ifdef VERBOSE
          cout << "Fail Check 6 " << i << endl;
#endif
          throw runtime_error("ciphertexts don't match");
        }
      if (!Check_Decoding(z,P.get_diagonal(),FieldD))
         {
#ifdef VERBOSE
          cout << "\tCheck : " << i << endl;
#endif
           throw runtime_error("cleartext isn't diagonal");
         }
    }
}

  

/* This is the non-interactive version using the ROM
*/
template <class FD>
void Verifier<FD>::NIZKPoK(AddableVector<Ciphertext>& c,
                          octetStream& ciphertexts, octetStream& cleartexts,
                          const FHE_PK& pk, int prover)
{
  P.set_challenge(ciphertexts, prover, pk);

  Stage_2(c,ciphertexts,cleartexts,pk);

  if (P.top_gear)
    {
      assert(not P.get_diagonal());
      c += c;
    }
}


template class Verifier<FFT_Data>;
template class Verifier<P2Data>;
