
#include "DistDecrypt.h"
#include "FHE/P2Data.h"
#include "Protocols/MAC_Check.h"

template<class FD>
DistDecrypt<FD>::DistDecrypt(const Player& P, const FHE_SK& share,
    const FHE_PK& pk, const FD& FTD) :
    P(P), share(share), pk(pk), mf(FTD), f(FTD)
{
  vv.resize(pk.get_params().phi_m());
  vv1.resize(pk.get_params().phi_m());
  // extra limb for operations
  bigint limit = pk.get_params().p0() << 64;
  vv.allocate_slots(limit);
  vv1.allocate_slots(limit);
  mf.allocate_slots(pk.p() << 64);
}

class ModuloTreeSum : public TreeSum<bigint>
{
  typedef TreeSum<bigint> super;

  bigint modulo;

  void post_add_process(vector<bigint>& values)
  {
    for (auto& v : values)
      v %= modulo;
  }

public:
  ModuloTreeSum(bigint modulo) :
      modulo(modulo)
  {
  }

  void run(vector<bigint>& values, const Player& P)
  {
    lengths.resize(values.size(), numBytes(modulo));
    super::run(values, P);
  }
};

template<class FD>
Plaintext_<FD>& DistDecrypt<FD>::run(const Ciphertext& ctx, bool NewCiphertext)
{
  CODE_LOCATION
  const FHE_Params& params=ctx.get_params();

  share.dist_decrypt_1(vv, ctx,P.my_num(),P.num_players());

  if (not NewCiphertext)
    intermediate_step();

  if ((int)vv.size() != params.phi_m())
    throw length_error("wrong length of ring element");

  size_t length = numBytes(pk.get_params().p0());

  if (OnlineOptions::singleton.direct)
    {
      // Now pack into an octetStream for broadcasting
      vector<octetStream> os(P.num_players());

      for (int i=0; i<params.phi_m(); i++)
        { (os[P.my_num()]).store(vv[i], length); }

      // Broadcast and Receive the values
      P.Broadcast_Receive(os);

      // Reconstruct the value mod p0 from all shares
      vv1.resize(params.phi_m());
      for (int i = 0; i < P.num_players(); i++)
        {
          if (i != P.my_num())
            {
              for (int j = 0; j < params.phi_m(); j++)
                {
                  os[i].get(vv1[j], length);
                }
              share.dist_decrypt_2(vv, vv1);
            }
        }
    }
  else
    {
      ModuloTreeSum(params.p0()).run(vv, P);
    }

  // Now get the final message
  bigint mod=params.p0();
  mf.set_poly_mod(vv,mod);
  return mf;
}


template class DistDecrypt<FFT_Data>;
template class DistDecrypt<P2Data>;


