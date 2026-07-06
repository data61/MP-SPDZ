
#include "FHEOffline/Reshare.h"
#include "FHEOffline/DistDecrypt.h"
#include "FHE/P2Data.h"
#include "Tools/random.h"

#include "Math/modp.hpp"

template<class T,class FD,class S>
void Reshare(Plaintext<T,FD,S>& m,Ciphertext& cc,
             const Ciphertext& cm,bool NewCiphertext,
             const Player& P,EncCommitBase<T,FD,S>& EC,
             const FHE_PK& pk,const FHE_SK& share)
{
  DistDecrypt<FD> dd(P, share, pk, m.get_field());
  Reshare(m, cc, cm, NewCiphertext, P, EC, pk, dd);
}

template<class T,class FD,class S>
void Reshare(Plaintext<T,FD,S>& m,Ciphertext& cc,
             const Ciphertext& cm,bool NewCiphertext,
             const Player& P,EncCommitBase<T,FD,S>& EC,
             const FHE_PK& pk,DistDecrypt<FD>& dd)
{
  const FHE_Params& params=pk.get_params();

  // Step 1
  Ciphertext cf(params);
  Plaintext_<FD>& f = dd.f;
  EC.next(f,cf);

  // Step 2
  // We could be resharing a level 0 ciphertext so adjust if we are
  if (cm.level()==0) { cf.Scale(m.get_field().get_prime()); }
  Ciphertext cmf(params);
  add(cmf,cf,cm);

  // Step 3
  Plaintext_<FD>& mf = dd.mf;
  dd.run(cmf, NewCiphertext);
  
  // Step 4
  if (P.my_num()==0)
    { sub(m,mf,f); }
  else
    { m=f; m.negate(); }
 
  // Step 5
  if (NewCiphertext)
    {
      Random_Coins rc(params);
      pk.encrypt(cc,mf,rc);
      // And again
      if (cf.level()==0) { cc.Scale(m.get_field().get_prime()); }
      sub(cc,cc,cf);
    }
}




template void Reshare(Plaintext<gfp,FFT_Data,bigint>& m,Ciphertext& cc,
                      const Ciphertext& cm,bool NewCiphertext,
                      const Player& P,EncCommitBase<gfp,FFT_Data,bigint>& EC,
                      const FHE_PK& pk,DistDecrypt<FFT_Data>& dd);

template void Reshare(Plaintext<gf2n_short,P2Data,int>& m,Ciphertext& cc,
                      const Ciphertext& cm,bool NewCiphertext,
                      const Player& P,EncCommitBase<gf2n_short,P2Data,int>& EC,
                      const FHE_PK& pk,DistDecrypt<P2Data>& dd);


template void Reshare(Plaintext<gfp,FFT_Data,bigint>& m,Ciphertext& cc,
                      const Ciphertext& cm,bool NewCiphertext,
                      const Player& P,EncCommitBase<gfp,FFT_Data,bigint>& EC,
                      const FHE_PK& pk,const FHE_SK& share);

template void Reshare(Plaintext<gf2n_short,P2Data,int>& m,Ciphertext& cc,
                      const Ciphertext& cm,bool NewCiphertext,
                      const Player& P,EncCommitBase<gf2n_short,P2Data,int>& EC,
                      const FHE_PK& pk,const FHE_SK& share);


