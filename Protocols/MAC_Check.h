#ifndef _MAC_Check
#define _MAC_Check

/* Class for storing MAC Check data and doing the Check */

#include <vector>
#include <deque>
using namespace std;

#include "Protocols/Share.h"
#include "Networking/Player.h"
#include "Protocols/MAC_Check_Base.h"
#include "Tools/time-func.h"
#include "Tools/Coordinator.h"
#include "Processor/OnlineOptions.h"


/* The MAX number of things we will partially open before running
 * a MAC Check
 *
 * Keep this at much less than 1MB of data to be able to cope with
 * multi-threaded players
 *
 */
#define POPEN_MAX 1000000


/**
 * Sum and broadcast values via a tree of players
 */
template<class T>
class TreeSum
{
  static const char* mc_timer_names[];

  void start(vector<T>& values, const Player& P);
  void finish(vector<T>& values, const Player& P);

  void add_openings(vector<T>& values, const Player& P, int sum_players,
      int last_sum_players, int send_player);

  virtual void post_add_process(vector<T>&) {}

  void pack(vector<T>& values);
  template<bool ADD>
  void unpack(vector<T>& values, octetStream& os);

  template<bool PACK, bool ADD>
  void pack_or_unpack(vector<T>& values, octetStream& os, false_type);
  template<bool PACK, bool ADD>
  void pack_or_unpack(vector<T>& values, octetStream& os, true_type);

protected:
  int base_player;
  int opening_sum;
  int max_broadcast;
  octetStream os;

  vector<int> lengths;

  void ReceiveValues(vector<T>& values, const Player& P, int sender);
  virtual void AddToValues(vector<T>& values) { (void)values; }

public:
  vector<octetStream> oss;
  vector<Timer> timers;
  vector<Timer> player_timers;

  TreeSum(int opening_sum = OnlineOptions::singleton.opening_sum,
      int max_broadcast = OnlineOptions::singleton.max_broadcast,
      int base_player = 0);
  virtual ~TreeSum();

  void run(vector<T>& values, const Player& P);
  T run(const T& value, const Player& P);

  octetStream& get_buffer() { return os; }

  size_t report_size(ReportType type);
};


template<class U>
class Tree_MAC_Check : public TreeSum<typename U::open_type>, public MAC_Check_Base<U>
{
  typedef typename U::open_type T;

  template<class V> friend class Tree_MAC_Check;

  protected:

  static Coordinator* coordinator;

  /* POpen Data */
  int popen_cnt;
  vector<typename U::mac_type> macs;
  vector<T> vals;

  void AddToValues(vector<T>& values);
  void CheckIfNeeded(const Player& P);
  int WaitingForCheck()
    { return max(macs.size(), vals.size()); }

  public:

  static void setup(Player& P);
  static void teardown();

  Tree_MAC_Check(const typename U::mac_key_type::Scalar& ai, int opening_sum = 10,
      int max_broadcast = 10, int send_player = 0);
  virtual ~Tree_MAC_Check();

  virtual void init_open(const Player& P, int n = 0);
  virtual void prepare_open(const U& secret, int = -1);
  virtual void exchange(const Player& P);

  virtual void AddToCheck(const U& share, const T& value, const Player& P);
  virtual void Check(const Player& P) = 0;
};

template<class U>
Coordinator* Tree_MAC_Check<U>::coordinator = 0;

/**
 * SPDZ opening protocol with MAC check (indirect communication)
 */
template<class U>
class MAC_Check_ : public virtual Tree_MAC_Check<U>
{
  void reset();

public:
  MAC_Check_(const typename U::mac_key_type::Scalar& ai, int opening_sum = 10,
      int max_broadcast = 10, int send_player = 0);
  virtual ~MAC_Check_() {}

  virtual void Check(const Player& P);
};

template<class T>
using MAC_Check = MAC_Check_<Share<T>>;

template<int K, int S> class Spdz2kShare;
template<class T> class Spdz2kPrep;
template<class T> class MascotPrep;

/**
 * SPDZ2k opening protocol with MAC check
 */
template<class T, class U, class V, class W>
class MAC_Check_Z2k : public virtual Tree_MAC_Check<W>
{
protected:
  Preprocessing<W>* prep;

  W get_random_element();

public:
  vector<W> random_elements;

  MAC_Check_Z2k(const T& ai, int opening_sum=10, int max_broadcast=10, int send_player=0);
  MAC_Check_Z2k(const T& ai, Names& Nms, int thread_num);

  void prepare_open(const W& secret, int = -1);
  void prepare_open_no_mask(const W& secret);

  virtual void Check(const Player& P);
  void set_random_element(const W& random_element);
  void set_prep(Preprocessing<W>& prep);
  virtual ~MAC_Check_Z2k() {};
};

template<class W>
using MAC_Check_Z2k_ = MAC_Check_Z2k<typename W::open_type,
        typename W::mac_key_type, typename W::open_type, W>;

/**
 * SPDZ opening protocol with MAC check (pairwise communication)
 */
template<class T>
class Direct_MAC_Check: public virtual MAC_Check_<T>
{
  typedef MAC_Check_<T> super;

  typedef typename T::open_type open_type;

  int open_counter;
  vector<octetStream> oss;

protected:
  void pre_exchange(const Player& P);

public:
  // legacy interface
  Direct_MAC_Check(const typename T::mac_key_type::Scalar& ai, Names& Nms, int thread_num);
  Direct_MAC_Check(const typename T::mac_key_type::Scalar& ai);
  ~Direct_MAC_Check();

  void init_open(const Player& P, int n = 0);
  void prepare_open(const T& secret, int = -1);
  virtual void exchange(const Player& P);
};

template<class T>
class Direct_MAC_Check_Z2k: virtual public MAC_Check_Z2k_<T>,
    virtual public Direct_MAC_Check<T>
{
public:
  Direct_MAC_Check_Z2k(const typename T::mac_key_type& ai) :
    Tree_MAC_Check<T>(ai), MAC_Check_Z2k_<T>(ai), MAC_Check_<T>(ai),
    Direct_MAC_Check<T>(ai)
  {
  }

  void prepare_open(const T& secret, int = -1)
  {
    MAC_Check_Z2k_<T>::prepare_open(secret);
  }

  void exchange(const Player& P)
  {
    Direct_MAC_Check<T>::exchange(P);
  }

  void Check(const Player& P)
  {
    MAC_Check_Z2k_<T>::Check(P);
  }
};


enum mc_timer { SEND, RECV_ADD, BCAST, RECV_SUM, SEED, COMMIT, WAIT_SUMMER, RECV, SUM, SELECT, MAX_TIMER };

template<class T>
TreeSum<T>::TreeSum(int opening_sum, int max_broadcast, int base_player) :
    base_player(base_player), opening_sum(opening_sum), max_broadcast(max_broadcast)
{
  timers.resize(MAX_TIMER);
}

template<class T>
TreeSum<T>::~TreeSum()
{
#ifdef TREESUM_TIMINGS
  for (unsigned int i = 0; i < timers.size(); i++)
    if (timers[i].elapsed() > 0)
      cerr << T::type_string() << " " << mc_timer_names[i] << ": "
        << timers[i].elapsed() << endl;

  for (unsigned int i = 0; i < player_timers.size(); i++)
    if (player_timers[i].elapsed() > 0)
      cerr << T::type_string() << " waiting for " << i << ": "
        << player_timers[i].elapsed() << endl;
#endif
}

template<class T>
void TreeSum<T>::run(vector<T>& values, const Player& P)
{
  if (not values.empty())
    {
      start(values, P);
      finish(values, P);
    }
}

template<class T>
T TreeSum<T>::run(const T& value, const Player& P)
{
  vector<T> values = {value};
  run(values, P);
  return values[0];
}

template<class T>
size_t TreeSum<T>::report_size(ReportType type)
{
  if (type == CAPACITY)
    return os.get_max_length();
  else
    return os.get_length();
}

template<class T>
void TreeSum<T>::pack(vector<T>& values)
{
  os.reset_write_head();
  pack_or_unpack<true, false>(values, os, T::optimized_packing);
  os.append(0);
}

template<class T>
template<bool ADD>
void TreeSum<T>::unpack(vector<T>& values, octetStream& os)
{
  pack_or_unpack<false, ADD>(values, os, T::optimized_packing);
  assert(not os.left());
}

template<class T>
template<bool PACK, bool ADD>
void TreeSum<T>::pack_or_unpack(vector<T>& values, octetStream& os, false_type)
{
  bool use_lengths = lengths.size() == values.size();
  T tmp = values.at(0);
  for (unsigned int i = 0; i < values.size(); i++)
    if (PACK)
      values[i].pack(os, use_lengths ? lengths[i] : -1);
    else
      {
        tmp.unpack(os, use_lengths ? lengths[i] : -1);
        if (ADD)
          values[i] += tmp;
        else
          values[i] = tmp;
      }
}

template<class T>
template<bool PACK, bool ADD>
void TreeSum<T>::pack_or_unpack(vector<T>& values, octetStream& os, true_type)
{
  for (auto length : lengths)
    if (length > 0)
      return pack_or_unpack<PACK, ADD>(values, os, false_type());

  T tmp = values.at(0);
  switch (DIV_CEIL(T::length(), 8))
    {
#define X(N) case N: for (auto& x : values) \
      if (PACK) \
        x.template pack<N>(os); \
      else \
        { \
          tmp.template unpack<N>(os); \
          if (ADD) \
            x += tmp; \
          else \
            x = tmp; \
        } \
        break;
  X(1) X(2) X(3) X(4) X(5) X(6) X(7)
#undef X
    default:
      return pack_or_unpack<PACK, ADD>(values, os, false_type());
    }
}

template<class T>
void TreeSum<T>::add_openings(vector<T>& values, const Player& P,
    int sum_players, int last_sum_players, int send_player)
{
  auto& MC = *this;
  MC.player_timers.resize(P.num_players());
  vector<octetStream>& oss = MC.oss;
  oss.resize(P.num_players());
  vector<int> senders;
  senders.reserve(P.num_players());

  for (int relative_sender = positive_modulo(P.my_num() - send_player, P.num_players()) + sum_players;
      relative_sender < last_sum_players; relative_sender += sum_players)
    {
      int sender = positive_modulo(send_player + relative_sender, P.num_players());
      senders.push_back(sender);
    }

  for (int j = 0; j < (int)senders.size(); j++)
    P.request_receive(senders[j], oss[j]);

  for (int j = 0; j < (int)senders.size(); j++)
    {
      int sender = senders[j];
      MC.player_timers[sender].start();
      P.wait_receive(sender, oss[j]);
      MC.player_timers[sender].stop();
      MC.timers[SUM].start();
      unpack<true>(values, oss[j]);
      post_add_process(values);
      MC.timers[SUM].stop();
    }
}

template<class T>
void TreeSum<T>::start(vector<T>& values, const Player& P)
{
  CODE_LOCATION
  if (opening_sum < 2)
    opening_sum = P.num_players();
  if (max_broadcast < 2)
    max_broadcast = P.num_players();

  int sum_players = P.num_players();
  int my_relative_num = positive_modulo(P.my_num() - base_player, P.num_players());
  while (true)
    {
      // summing phase
      int last_sum_players = sum_players;
      sum_players = (sum_players - 2 + opening_sum) / opening_sum;
      if (sum_players == 0)
        break;
      if (my_relative_num >= sum_players && my_relative_num < last_sum_players)
        {
          // send to the player up the tree
          pack(values);
          int receiver = positive_modulo(base_player + my_relative_num % sum_players, P.num_players());
          timers[SEND].start();
          P.send_to(receiver,os);
          timers[SEND].stop();
        }

      if (my_relative_num < sum_players)
        {
          // if receiving, add the values
          timers[RECV_ADD].start();
          add_openings(values, P, sum_players, last_sum_players, base_player);
          timers[RECV_ADD].stop();
        }
    }

  if (P.my_num() == base_player)
    {
      // send from the root player
      pack(values);
      timers[BCAST].start();
      for (int i = 1; i < max_broadcast && i < P.num_players(); i++)
        {
          P.send_to((base_player + i) % P.num_players(), os);
        }
      timers[BCAST].stop();
      AddToValues(values);
    }
  else if (my_relative_num * max_broadcast < P.num_players())
    {
      // send if there are children
      int sender = (base_player + my_relative_num / max_broadcast) % P.num_players();
      ReceiveValues(values, P, sender);
      timers[BCAST].start();
      for (int i = 0; i < max_broadcast; i++)
        {
          int relative_receiver = (my_relative_num * max_broadcast + i);
          if (relative_receiver < P.num_players())
            {
              int receiver = (base_player + relative_receiver) % P.num_players();
              P.send_to(receiver, os);
            }
        }
      timers[BCAST].stop();
    }
}

template<class T>
void TreeSum<T>::finish(vector<T>& values, const Player& P)
{
  int my_relative_num = positive_modulo(P.my_num() - base_player, P.num_players());
  if (my_relative_num * max_broadcast >= P.num_players())
    {
      // receiving at the leafs
      int sender = (base_player + my_relative_num / max_broadcast) % P.num_players();
      ReceiveValues(values, P, sender);
    }
}

template<class T>
void TreeSum<T>::ReceiveValues(vector<T>& values, const Player& P, int sender)
{
  timers[RECV_SUM].start();
  P.receive_player(sender, os);
  timers[RECV_SUM].stop();
  unpack<false>(values, os);
  AddToValues(values);
}

#endif
