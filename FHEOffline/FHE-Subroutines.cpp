
#include "Tools/Subroutines.h"
#include "FHE/Rq_Element.h"
#include "FHE/Ciphertext.h"
#include "Tools/Commit.h"

/* This runs the Commit and Open Protocol for data[i][j] of type T
 *   0 <= i < num_runs
 *   0 <= j < num_players
 * On input data[i][j] is only defined for j=my_number
 */
template<class T>
void Commit_And_Open(vector< vector<T> >& data,const Player& P,int num_runs)
{
  CODE_LOCATION
  int num_players=P.num_players();
  vector< vector<octetStream> > Comm_data(num_runs, vector<octetStream>(num_players));
  vector<octetStream> Open_data(num_runs);
  CommitSession session(P);
  session.Commit(Comm_data,Open_data,data,P,num_runs);
  session.Open(data,Comm_data,Open_data,P,num_runs);
}



/* Just transmit data[i][j] of type T
 *   0 <= i < num_runs
 *   0 <= j < num_players
 * On output data[i][j] contains all the data
 */
template<class T>
void Transmit_Data(vector< vector<T> >& data,const Player& P,int num_runs)
{
  CODE_LOCATION
  int my_number=P.my_num();
  int num_players=P.num_players();
  for (int i=0; i<num_runs; i++)
    {
      vector<octetStream> t_data(num_players);
      data[i][my_number].pack(t_data[my_number]);
      P.Broadcast_Receive(t_data);
      for (int j=0; j<num_players; j++)
        if (j!=my_number)
          data[i][j].unpack(t_data[j]);
    }
}



template void Commit_And_Open(vector< vector<Rq_Element> >& data,const Player& P,int num_runs);
template void Commit_And_Open(vector< vector<Ciphertext> >& data,const Player& P,int num_runs);

template void Transmit_Data(vector< vector<Rq_Element> >& data,const Player& P,int num_runs);
template void Transmit_Data(vector< vector<Ciphertext> >& data,const Player& P,int num_runs);

