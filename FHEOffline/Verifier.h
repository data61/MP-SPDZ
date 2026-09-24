#ifndef _Verifier
#define _Verifier

#include "Proof.h"

template <class FD>
bool Check_Decoding(const vector<Proof::bound_type>& AE, bool Diag, FD& FieldD);

/* Defines the Verifier */
template <class FD>
class Verifier
{
  AddableVector<typename Proof::bound_type> z;
  AddableMatrix<Int_Random_Coins::value_type::value_type> t;

  Proof& P;
  const FD& FieldD;

public:
  Verifier(Proof& proof, const FD& FieldD);

  void Stage_2(
      AddableVector<Ciphertext>& c, octetStream& ciphertexts,
      octetStream& cleartexts,const FHE_PK& pk);

  /* This is the non-interactive version using the ROM
      - Creates space for all output values
      - Diag flag mirrors that in Prover
  */
  void NIZKPoK(AddableVector<Ciphertext>& c,octetStream& ciphertexts,octetStream& cleartexts,
               const FHE_PK& pk, int prover);

  size_t report_size(ReportType type) { return z.report_size(type) + t.report_size(type); }
};

#endif
