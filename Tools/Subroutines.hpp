/*
 * Subroutines.hpp
 *
 */

#ifndef TOOLS_SUBROUTINES_HPP_
#define TOOLS_SUBROUTINES_HPP_

#include "Subroutines.h"
#include "CodeLocations.h"

template<class T>
void Create_Random(T& ans,const Player& P)
{
  CODE_LOCATION
  PRNG G;
  G.ReSeed();
  vector<T> e(P.num_players());
  vector<octetStream> Comm_e(P.num_players());
  vector<octetStream> Open_e(P.num_players());

  e[P.my_num()].randomize(G);
  octetStream ee;
  e[P.my_num()].pack(ee);
  CommitSession session(P);
  session.Commit(Comm_e[P.my_num()],Open_e[P.my_num()],ee,P.my_num());
  P.Broadcast_Receive(Comm_e);

  P.Broadcast_Receive(Open_e);

  ans.assign_zero();
  for (int i = 0; i < P.num_players(); i++)
    { if (i != P.my_num())
        { if (!session.Open(ee,Comm_e[i],Open_e[i],i))
             { throw invalid_commitment(); }
          e[i].unpack(ee);
          }
      ans += e[i];
    }
}

#endif /* TOOLS_SUBROUTINES_HPP_ */
