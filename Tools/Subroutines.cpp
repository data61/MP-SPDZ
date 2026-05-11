
#include "Tools/Subroutines.h"

#include "Tools/random.h"
#include "Tools/Exceptions.h"
#include "Tools/Commit.h"
#include "Tools/CodeLocations.h"
#include "Math/Z2k.h"
#include "Math/gfp.h"
#include "Math/gf2n.h"

/* To ease readability as I re-write this program the following conventions
 * will be used.
 *   For a variable v index by a player i
 *   Comm_v[i] is the commitment string for player i
 *   Open_v[i] is the opening data for player i
 */


// Special version for octetStreams
void Commit(vector< vector<octetStream> >& Comm_data,
            vector<octetStream>& Open_data,
            const vector< vector<octetStream> >& data,const Player& P,int num_runs)
{
  CODE_LOCATION
  int my_number=P.my_num();
  for (int i=0; i<num_runs; i++)
     { Comm_data[i].resize(P.num_players());
       Commit(Comm_data[i][my_number],Open_data[i],data[i][my_number],my_number);
       P.Broadcast_Receive(Comm_data[i]);
     }
}




// Special version for octetStreams
void Open(vector< vector<octetStream> >& data,
          const vector< vector<octetStream> >& Comm_data,
          const vector<octetStream>& My_Open_data,
          const Player& P,int num_runs,int dont)
{
  CODE_LOCATION
  int my_number=P.my_num();
  int num_players=P.num_players();
  vector<octetStream> Open_data(num_players);
  for (int i=0; i<num_runs; i++)
     { if (i!=dont)
        { Open_data[my_number]=My_Open_data[i];
          P.Broadcast_Receive(Open_data);
          for (int j=0; j<num_players; j++) 
            { if (j!=my_number)
	        { if (!Open(data[i][j],Comm_data[i][j],Open_data[j],j))
	             { throw invalid_commitment(); }
	        }
	    }
        }
     }
}


void Open(vector< vector<octetStream> >& data,
          const vector< vector<octetStream> >& Comm_data,
          const vector<octetStream>& My_Open_data,
          const vector<int> open,
          const Player& P,int num_runs)
{
  CODE_LOCATION
  int my_number=P.my_num();
  int num_players=P.num_players();
  vector<octetStream> Open_data(num_players);
  for (int i=0; i<num_runs; i++)
     { if (open[i]==1)
        { Open_data[my_number]=My_Open_data[i];
          P.Broadcast_Receive(Open_data);
          for (int j=0; j<num_players; j++) 
            { if (j!=my_number)
	         { if (!Open(data[i][j],Comm_data[i][j],Open_data[j],j))
	             { throw invalid_commitment(); }
	        }
	    }
        }
     }
}





void Commit_To_Challenge(vector<unsigned int>& e,
                         vector<octetStream>& Comm_e,vector<octetStream>& Open_e,
                         const Player& P,int num_runs)
{
  CODE_LOCATION
  PRNG G;
  G.ReSeed();

  e.resize(P.num_players());
  Comm_e.resize(P.num_players());
  Open_e.resize(P.num_players());
  
  e[P.my_num()]=G.get_uint(num_runs);
  octetStream ee; ee.store(e[P.my_num()]);
  Commit(Comm_e[P.my_num()],Open_e[P.my_num()],ee,P.my_num());
  P.Broadcast_Receive(Comm_e);
}


int Open_Challenge(vector<unsigned int>& e,vector<octetStream>& Open_e,
                   const vector<octetStream>& Comm_e,
                   const Player& P,int num_runs)
{
  CODE_LOCATION
  // Now open the challenge commitments and determine which run was for real
  P.Broadcast_Receive(Open_e);
  
  int challenge=0;
  octetStream ee;
  for (int i = 0; i < P.num_players(); i++)
    { if (i != P.my_num())
        { if (!Open(ee,Comm_e[i],Open_e[i],i))
	     { throw invalid_commitment(); }
          ee.get(e[i]);
          }
      challenge+=e[i];
    }
  challenge = challenge % num_runs;

  return challenge;
}


void Create_Random_Seed(octet* seed, const PlayerBase& P, int len,
    const vector<bool>& parties)
{
  CODE_LOCATION

  vector<bool> my_parties = parties;
  if (my_parties.empty())
    my_parties.resize(P.num_players(), true);

  PRNG G;
  G.ReSeed();
  vector<octetStream> e(P.num_players());
  vector<octetStream> Comm_e(P.num_players());
  vector<octetStream> Open_e(P.num_players());

  G.get_octetStream(e[P.my_num()],len);
  Commit(Comm_e[P.my_num()],Open_e[P.my_num()],e[P.my_num()],P.my_num());
  P.partial_broadcast(my_parties, my_parties, Comm_e);

  P.partial_broadcast(my_parties, my_parties, Open_e);

  memset(seed,0,len*sizeof(octet));
  for (int i = 0; i < P.num_players(); i++)
    if (my_parties.at(i))
      {
        if (i != P.my_num())
          {
            if (!Open(e[i], Comm_e[i], Open_e[i], i))
              throw invalid_commitment();
          }
        for (int j = 0; j < len; j++)
          seed[j] ^= *e[i].consume(1);
      }
    else
      {
        if (Open_e[i].get_length() > 0)
          throw runtime_error("unexpected information from " + to_string(i));
      }
}


void Commit_And_Open_(vector<octetStream>& datas, const Player& P, Coordinator& coordinator)
{
  CODE_LOCATION
  vector<octetStream> Comm_data(P.num_players());
  vector<octetStream> Open_data(P.num_players());

  Commit(Comm_data[P.my_num()],Open_data[P.my_num()],datas[P.my_num()],P.my_num());
  P.Broadcast_Receive(Comm_data);

  coordinator.wait(P.get_id());
  P.Broadcast_Receive(Open_data);

  for (int i = 0; i < P.num_players(); i++)
    { if (i != P.my_num())
        { if (!Open(datas[i],Comm_data[i],Open_data[i],i))
             { throw invalid_commitment(); }
        }
    }
}


void Commit_To_Seeds(vector<PRNG>& G,
                     vector< vector<octetStream> >& seeds,
                     vector< vector<octetStream> >& Comm_seeds,
		     vector<octetStream>& Open_seeds,
		     const Player& P,int num_runs)
{
  CODE_LOCATION
  seeds.resize(num_runs);
  Comm_seeds.resize(num_runs);
  Open_seeds.resize(num_runs);
  for (int i=0; i<num_runs; i++)
    { G[i].ReSeed();
      seeds[i].resize(P.num_players());
      Comm_seeds[i].resize(P.num_players());
      Open_seeds[i].resize(P.num_players());
      seeds[i][P.my_num()].reset_write_head();
      seeds[i][P.my_num()].append(G[i].get_seed(),SEED_SIZE);
    }
  Commit(Comm_seeds,Open_seeds,seeds,P,num_runs);
}
