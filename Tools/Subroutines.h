#ifndef _Subroutines
#define _Subroutines

/* Defines subroutines for use in both KeyGen and Offline phase
 * Mainly focused around commiting and decommitting to various
 * bits of data
 */

#include "Tools/random.h"
#include "Networking/Player.h"
#include "Tools/Commit.h"
#include "Coordinator.h"

#include "Subroutines.hpp"





/* This runs the Commit and Open Protocol for data[i][j] of type T
 *   0 <= i < num_runs
 *   0 <= j < num_players
 * On input data[i][j] is only defined for j=my_number
 */
template<class T>
void Commit_And_Open(vector< vector<T> >& data,const Player& P,int num_runs);

template<class T>
void Commit_And_Open(vector<T>& data, const Player& P, Coordinator& coordinator);

void Commit_And_Open_(vector<octetStream>& datas, const Player& P, Coordinator& coordinator);

template<class T>
void Commit_And_Open(vector<T>& data, const Player& P, Coordinator& coordinator)
{
  vector<octetStream> datas(P.num_players());
  data[P.my_num()].pack(datas[P.my_num()]);
  Commit_And_Open_(datas, P, coordinator);
  for (int i = 0; i < P.num_players(); i++)
    data[i].unpack(datas[i]);
}


template<class T>
void Transmit_Data(vector< vector<T> >& data,const Player& P,int num_runs);

/* Functions to Commit and Open a Challenge Value */
void Commit_To_Challenge(vector<unsigned int>& e,
                         vector<octetStream>& Comm_e,vector<octetStream>& Open_e,
                         const Player& P,int num_runs);

int Open_Challenge(vector<unsigned int>& e,vector<octetStream>& Open_e,
                   const vector<octetStream>& Comm_e,
                   const Player& P,int num_runs);


/* Function to create a shared random value for T=gfp/gf2n */
template<class T>
void Create_Random(T& ans,const Player& P);

template<class T>
T Create_Random(const Player& P)
{
  T res;
  Create_Random(res, P);
  return res;
}

/* Produce a random seed of length len */
void Create_Random_Seed(octet* seed, const PlayerBase& P, int len,
    const vector<bool>& parties = {});




/* Run just the Commit Protocol for data[i][j] of type T
 *   0 <= i < num_runs
 *   0 <= j < num_players
 * On input data[i][j] is only defined for j=my_number
 */
template<class T>
void CommitSession::Commit(vector< vector<octetStream> >& Comm_data,
            vector<octetStream>& Open_data,
            const vector< vector<T> >& data,const Player& P,int num_runs)
{
  octetStream os;
  int my_number=P.my_num();
  for (int i=0; i<num_runs; i++)
     { os.reset_write_head();
       data[i][my_number].pack(os);
       Comm_data[i].resize(P.num_players());
       Commit(Comm_data[i][my_number],Open_data[i],os,my_number);
       P.Broadcast_Receive(Comm_data[i]);
     }
}


/* Run just the Open Protocol for data[i][j] of type T
 *   0 <= i < num_runs
 *   0 <= j < num_players
 * On output data[i][j] contains all the data
 * If dont!=-1 then dont open this run
 */
template<class T>
void CommitSession::Open(vector< vector<T> >& data,
          const vector< vector<octetStream> >& Comm_data,
          const vector<octetStream>& My_Open_data,
          const Player& P,int num_runs,int dont)
{
  octetStream os;
  int my_number=P.my_num();
  int num_players=P.num_players();
  vector<octetStream> Open_data(num_players);
  for (int i=0; i<num_runs; i++)
     { if (i!=dont)
        { Open_data[my_number]=My_Open_data[i];
          P.Broadcast_Receive(Open_data);
          for (int j=0; j<num_players; j++)
            { if (j!=my_number)
                { if (!Open(os,Comm_data[i][j],Open_data[j],j))
                     { throw invalid_commitment(); }
                  os.reset_read_head();
                  data[i][j].unpack(os);
                }
            }
        }
     }
}


#endif

