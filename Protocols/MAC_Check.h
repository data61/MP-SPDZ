#ifndef _MAC_Check
#define _MAC_Check

/* Class for storing MAC Check data and doing the Check */

#include <vector>
#include <deque>
#include <map>
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

  // compatibility
  void set_random_element(const U& random_element) { (void) random_element; }
};

template<class U>
Coordinator* Tree_MAC_Check<U>::coordinator = 0;

/**
 * SPDZ opening protocol with MAC check (indirect communication)
 */
template<class U>
class MAC_Check_ : public virtual Tree_MAC_Check<U>
{
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
    assert(this->WaitingForCheck() > 0);
  }

  void Check(const Player& P)
  {
    MAC_Check_Z2k_<T>::Check(P);
  }
};


enum mc_timer { SEND, RECV_ADD, BCAST, RECV_SUM, SEED, COMMIT, WAIT_SUMMER, RECV, SUM, SELECT, RING, TREE, MAX_TIMER };

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
        << timers[i].elapsed() << "\n";

  for (unsigned int i = 0; i < player_timers.size(); i++)
    if (player_timers[i].elapsed() > 0)
      cerr << T::type_string() << " waiting for " << i << ": "
        << player_timers[i].elapsed() << "\n";
#endif
}

template<class T>
void TreeSum<T>::run(vector<T>& values, const Player& P)
{
  // start(values, P);
  // finish(values, P);
  // return;
  // bool printMessage = true;

  clock_t st,end;  //定义clock_t变量
  int num_players = P.num_players();
  int values_size = values.size();

  // ************************ 分割线 ************************
  // 命令行 -v -s 42（s 指的是 opening_sum）

  // -s 如果是 2    --> 一定是 tree
  // -s 100000000  --> star

  // *** tree ***
  // opening_sum用来指定 values_size 的门限
  // 当电路比较窄的时候, 选用tree算法 (values_size < opening_sum)
  std::cout << "opening_sum = " << opening_sum << std::endl;
  std::cout << "values_size = " << values_size << std::endl;
  std::cout << "num_players = " << num_players << std::endl;
  if(opening_sum < num_players || values_size < opening_sum){
    st = clock();
    int old_opening_sum = opening_sum;
    // star
    if (opening_sum == 100000000)
    {
      opening_sum = 0;
    }
    max_broadcast = opening_sum;
    start(values, P);
    finish(values, P);
    end = clock();
    std::cout << "TREE with opening_sum(" << opening_sum << ") = " << double(end - st) / CLOCKS_PER_SEC << "s"
              << " size:" << int(values.size()) << "\n";
    opening_sum = old_opening_sum;
    return;
  }


  // // 当电路比较宽，可以使用 ring or rotated-star 算法
  // //  opening_sum 是奇数 -> ring
  // if ( opening_sum % 2 ) {

  //   // std::cout << opening_sum << std::endl;
  //   // ************************ 分割线 ************************
  //   // *** ring ***
  //   st = clock();
  //   int block_size = values_size / num_players; // 把数据分为多个block
  //   auto indexes = [values_size, num_players, block_size](int index) -> pair<int, int>
  //   {
  //     // 根据总的数据数和当前index求需要传输数据的长度
  //     auto start = index * block_size;
  //     auto end = start + block_size - 1;
  //     if (index == num_players - 1)
  //     {
  //       // 最后一个block
  //       end = values_size - 1;
  //     }
  //     // 返回start_index 和 end_index

  //     return {start, end};
  //   };
  //   int prev = (P.my_num() - 1 + num_players) % num_players;
  //   int next = (P.my_num() + 1) % num_players;
  //   auto &MC = *this;
  //   vector<octetStream> &oss = MC.oss;
  //   oss.resize(2*(num_players-1));  // 一共要传输2(n-1)轮
  //   for (size_t i = 0; i < oss.size(); ++i){
  //     oss[i].reset_read_head();
  //   }

  //   auto my_send = [&](int send_idx)
  //   {
  //     os.reset_write_head();  // 清空发送缓冲区
  //     auto se = indexes(send_idx);
  //     for (int j = se.first; j <= se.second; ++j)
  //     { // 打包信息
  //       values[j].pack(os, -1);
  //     }
  //     os.append(0);
  //     P.send_to(next, os);
  //   };

  //   auto my_receive1 = [&](int receive_idx, int i)
  //   {
  //     P.receive_player(prev, oss[num_players-1+i]);
  //     auto se = indexes(receive_idx);
  //     for (int j = se.first; j <= se.second; ++j)
  //     {
  //       values[j].add(oss[num_players-1+i], -1);
  //     }
  //   };

  //   auto my_receive2 = [&](int receive_idx, int i)
  //   {
  //     P.receive_player(prev, oss[num_players-1+i]);
  //     auto se = indexes(receive_idx);
  //     for (int j = se.first; j <= se.second; ++j)
  //     {
  //       values[j].unpack(oss[num_players-1+i], -1);
  //     }
  //   };

  //   // 第一个 n-1 轮，规约部分数据
  //   int send_idx = P.my_num();  // 发送第几个block
  //   int receive_idx = (send_idx - 1 + num_players) % num_players; // 接收第几个block
  //   for (int i = 0; i < num_players-1; i++)
  //   { // num_players-1轮
  //     if(P.my_num()%2==0){
  //       // **************** 发送 ****************
  //       my_send(send_idx);
  //       // cout << "send finished\n";
  //       // **************** 接收 ****************
  //       my_receive1(receive_idx, i);
  //       // cout << "receive finished\n";
  //     }
  //     else{
  //       // **************** 接收 ****************
  //       my_send(send_idx);
  //       my_receive1(receive_idx, i);
  //       // cout << "receive finished\n";
  //       // **************** 发送 ****************
  //       // my_send(send_idx);
  //       // cout << "send finished\n";
  //     }

  //     // 更新idx
  //     receive_idx = (receive_idx - 1 + num_players) % num_players;
  //     send_idx = (send_idx -1 + num_players) % num_players;
  //   }

  //   // 另外n-1轮, 传递部分数据
  //   send_idx = (P.my_num()+1) % num_players;  // 发送第几个block
  //   receive_idx = P.my_num(); // 接收第几个block
  //   for (int i = 0; i < num_players - 1; ++i){
  //     if(P.my_num()%2==0){
  //       my_send(send_idx);
  //       // cout << "send finished\n";
  //       my_receive2(receive_idx, i);
  //       // cout << "receive finished\n";
  //     }
  //     else{
  //       my_send(send_idx);
  //       my_receive2(receive_idx, i);
  //       // cout << "receive finished\n";
  //       // my_send(send_idx);
  //       // cout << "send finished\n";
  //     }

  //     // 更新idx
  //     send_idx = receive_idx;
  //     receive_idx = (receive_idx - 1 + num_players) % num_players;
  //   }

  //   AddToValues(values);

  //   end = clock();
  //   std::cout<<"RING = "<<double(end-st)/CLOCKS_PER_SEC<<"s"<<" size:"<<values_size<<"\n";

  // }



  //  调整后的 ring 算法 -> 接收的缓冲区大小减半
  //  当电路比较宽，可以使用 ring or rotated-star 算法
  //  opening_sum 是奇数 -> ring
  if ( opening_sum % 2 ) {

    // // std::cout << opening_sum << std::endl;
    // // ************************ 分割线 ************************
    // // *** ring ***
    // st = clock();
    // int block_size = values_size / num_players; // 把数据分为多个block
    // auto indexes = [values_size, num_players, block_size](int index) -> pair<int, int>
    // {
    //   // 根据总的数据数和当前index求需要传输数据的长度
    //   auto start = index * block_size;
    //   auto end = start + block_size - 1;
    //   if (index == num_players - 1)
    //   {
    //     // 最后一个block
    //     end = values_size - 1;
    //   }
    //   // 返回start_index 和 end_index

    //   return {start, end};
    // };
    // int prev = (P.my_num() - 1 + num_players) % num_players;
    // int next = (P.my_num() + 1) % num_players;
    // auto &MC = *this;
    // vector<octetStream> &oss = MC.oss;
    // oss.resize((num_players-1));  // 一共要传输2(n-1)轮
    // for (size_t i = 0; i < oss.size(); ++i){
    //   oss[i].reset_read_head();
    // }

    // auto my_send = [&](int send_idx)
    // {
    //   os.reset_write_head();  // 清空发送缓冲区
    //   auto se = indexes(send_idx);
    //   for (int j = se.first; j <= se.second; ++j)
    //   { // 打包信息
    //     values[j].pack(os, -1);
    //   }
    //   os.append(0);
    //   P.send_to(next, os);
    // };

    // auto my_receive1 = [&](int receive_idx, int i)
    // {
    //   P.receive_player(prev, oss[i]);
    //   auto se = indexes(receive_idx);
    //   for (int j = se.first; j <= se.second; ++j)
    //   {
    //     values[j].add(oss[i], -1);
    //   }
    // };

    // auto my_receive2 = [&](int receive_idx, int i)
    // {
    //   P.receive_player(prev, oss[i]);
    //   auto se = indexes(receive_idx);
    //   for (int j = se.first; j <= se.second; ++j)
    //   {
    //     values[j].unpack(oss[i], -1);
    //   }
    // };

    // // 第一个 n-1 轮，规约部分数据
    // int send_idx = P.my_num();  // 发送第几个block
    // int receive_idx = (send_idx - 1 + num_players) % num_players; // 接收第几个block
    // for (int i = 0; i < num_players-1; i++){
    //   // num_players-1轮
    //   // send
    //   my_send(send_idx);
    //   //  receive
    //   my_receive1(receive_idx, i);
      

    //   // 更新idx
    //   receive_idx = (receive_idx - 1 + num_players) % num_players;
    //   send_idx = (send_idx -1 + num_players) % num_players;
    // }

    // // 另外n-1轮, 传递部分数据
    // send_idx = (P.my_num()+1) % num_players;  // 发送第几个block
    // receive_idx = P.my_num(); // 接收第几个block
    // for (int i = 0; i < num_players-1; i++){
    //     // num_players-1轮
    //     // send
    //     my_send(send_idx);
    //     //  receive
    //     my_receive2(receive_idx, i);
      

    //   // 更新idx
    //   receive_idx = (receive_idx - 1 + num_players) % num_players;
    //   send_idx = (send_idx -1 + num_players) % num_players;
    // }

    // AddToValues(values);

    // end = clock();
    // std::cout<<"RING = "<<double(end-st)/CLOCKS_PER_SEC<<"s"<<" size:"<<values_size<<"\n";






    // std::cout << opening_sum << std::endl;
    // ************************ 分割线 ************************
    // *** ring ***
    st = clock();
    int block_size = values_size / num_players; // 把数据分为多个block
    auto indexes = [values_size, num_players, block_size](int index) -> pair<int, int>
    {
      // 根据总的数据数和当前index求需要传输数据的长度
      auto start = index * block_size;
      auto end = start + block_size - 1;
      if (index == num_players - 1)
      {
        // 最后一个block
        end = values_size - 1;
      }
      // 返回start_index 和 end_index

      return {start, end};
    };
    int prev = (P.my_num() - 1 + num_players) % num_players;
    int next = (P.my_num() + 1) % num_players;
    auto &MC = *this;
    vector<octetStream> &oss = MC.oss;
    oss.resize(2*(num_players-1));  // 一共要传输2(n-1)轮
    for (size_t i = 0; i < oss.size(); ++i){
      oss[i].reset_read_head();
    }

    auto my_send = [&](int send_idx)
    {
      os.reset_write_head();  // 清空发送缓冲区
      auto se = indexes(send_idx);
      for (int j = se.first; j <= se.second; ++j)
      { // 打包信息
        values[j].pack(os, -1);
      }
      os.append(0);
      P.send_to(next, os);
    };
    auto my_receive1 = [&](int receive_idx, int i)
    {
      P.receive_player(prev, oss[num_players-1+i]);
      auto se = indexes(receive_idx);
      for (int j = se.first; j <= se.second; ++j)
      {
        values[j].add(oss[num_players-1+i], -1);
      }
    };
    auto my_receive2 = [&](int receive_idx, int i)
    {
      P.receive_player(prev, oss[num_players-1+i]);
      auto se = indexes(receive_idx);
      for (int j = se.first; j <= se.second; ++j)
      {
        values[j].unpack(oss[num_players-1+i], -1);
      }
    };

    // 第一个 n-1 轮，规约部分数据
    int send_idx = P.my_num();  // 发送第几个block
    int receive_idx = (send_idx - 1 + num_players) % num_players; // 接收第几个block
    for (int i = 0; i < num_players-1; i++)
    { // num_players-1轮
    if(P.my_num()%2==0){
      // **************** 发送 ****************
      my_send(send_idx);
      // cout << "send finished\n";
      // **************** 接收 ****************
      my_receive1(receive_idx, i);
      // cout << "receive finished\n";
    }
    else{
      // **************** 接收 ****************
      // my_send(send_idx);
      my_receive1(receive_idx, i);
      // cout << "receive finished\n";
      // **************** 发送 ****************
      my_send(send_idx);
      // cout << "send finished\n";
    }

      // 更新idx
      receive_idx = (receive_idx - 1 + num_players) % num_players;
      send_idx = (send_idx -1 + num_players) % num_players;
    }

    // 另外n-1轮, 传递部分数据
    send_idx = (P.my_num()+1) % num_players;  // 发送第几个block
    receive_idx = P.my_num(); // 接收第几个block
    for (int i = 0; i < num_players - 1; ++i){
      if(P.my_num()%2==0){
        my_send(send_idx);
        // cout << "send finished\n";
        my_receive2(receive_idx, i);
        // cout << "receive finished\n";
      }
      else{
        // my_send(send_idx);
        my_receive2(receive_idx, i);
        // cout << "receive finished\n";
        my_send(send_idx);
        // cout << "send finished\n";
      }

      // 更新idx
      send_idx = receive_idx;
      receive_idx = (receive_idx - 1 + num_players) % num_players;
    }

    AddToValues(values);

    end = clock();
    // std::cout<<"RING = "<<double(end-st)/CLOCKS_PER_SEC<<"s"<<" size:"<<values_size<<"\n";

    std::cout << "RING with opening_sum(" << opening_sum << ") = " << double(end - st) / CLOCKS_PER_SEC << "s"  << " size:" << int(values.size()) << "\n";

  }



  // opening_sum < value_size
  // 且 opening_sum 是偶数 -> rotated-star
  else{

    // ************************ 分割线 ************************
    // *** rotated-star ***
    st = clock();
    int block_size = values_size / num_players; // 把数据分为多个block

    //  该函数获取对应的 index 相应的 block 起始和结束位置
    //  index 应该是 0 ~ num_players-1， 用来指定第几个block
    auto indexes = [values_size, num_players, block_size](int index) -> pair<int, int>
    {
      // 根据总的数据数和当前index求需要传输数据的长度
      auto start = index * block_size;
      auto end = start + block_size - 1;
      if (index == num_players - 1)
      {
        // 最后一个block
        end = values_size - 1;
      }
      // 返回start_index 和 end_index

      return {start, end};
    };

    // int prev = (P.my_num() - 1 + num_players) % num_players;
    // int next = (P.my_num() + 1) % num_players;
    auto &MC = *this;
    vector<octetStream> &oss = MC.oss;
    oss.resize((num_players-1));  // 一共要传输(n-1)个缓冲区
    for (size_t i = 0; i < oss.size(); ++i){
      oss[i].reset_read_head();
    }




    // my_send函数只需要确定给 "谁" 发送 "第几块" 数据即可
    auto my_send = [&](int reveiver_num, int block_index)
    {
      os.reset_write_head();  // 清空发送缓冲区
      auto se = indexes(block_index);
      for (int j = se.first; j <= se.second; ++j)
      { // 打包信息
        values[j].pack(os, -1);
      }
      os.append(0);
      P.send_to(reveiver_num, os);
    };

  
    // my_receive1函数只需要确定从 "谁" 接收 "第几块" 数据即可 (并加和)
    auto my_receive1 = [&](int sender_num, int block_index, int round_idx)
    {
      P.receive_player(sender_num, oss[round_idx]);
      auto se = indexes(block_index);
      for (int j = se.first; j <= se.second; ++j)
      {
        values[j].add(oss[round_idx], -1);
      }
    };

    // my_receive2函数只需要确定从 "谁" 接收 "第几块" 数据即可 (并解包/替换)
    auto my_receive2 = [&](int sender_num, int block_index, int round_idx)
    {
      P.receive_player(sender_num, oss[round_idx]);
      auto se = indexes(block_index);
      for (int j = se.first; j <= se.second; ++j)
      {
        values[j].unpack(oss[round_idx], -1);
      }
    };


    //  第一个 n-1 轮，规约部分数据
    //  第 j 轮, Pi 给 P_{i-j-1} 发送自己的第 i-j-1 个 block
    //  第 j 轮, Pi 从 P_{i+j+1} 接收第 i 个 block

    //  需要调度通信, N party, 第 j‘ 轮(从1开始), 存在通信环的个数()

    auto my_gcd = [&](int a, int b) -> int {
        while (b != 0) {
          int temp = b;
          b = a % b;
          a = temp;
        }
        return a;
    };    

    for (int i = 0; i < num_players-1; i++){  // num_players - 1  rounds
      

      int roundj = i+1; //  定义为正整数
      int ring_counts = my_gcd(num_players, roundj);  //  通信结构当中环的个数
      int ring_size = num_players / ring_counts;
      //  如果有多个环，只考虑第一个环当中的归属关系

      //  记录 player_0 所在的环
      // std::vector<int> ring0_indices(num_players / ring_counts);
      // for (int j=0; j<=ring_size-1; j++){
      //   // ring0_indices[j] = (0 - roundj * j ) % num_players; 
      //   ring0_indices[j] = ( (num_players - roundj)* j ) % num_players; 
      // }

      std::map<int, int> ring0_indices;
      for (int j=0; j<ring_size; j++){
        // ring0_indices[j] = (0 - roundj * j ) % num_players; 
        // ring0_indices[j] = ( (num_players - roundj)* j ) % num_players; 
        ring0_indices.insert({j, ( (num_players - roundj)* j ) % num_players});
      }

      std::map<int, int> reverse_map0;
      for (const auto& pair : ring0_indices) {
          reverse_map0[pair.second] = pair.first;
      }
       


      //  将当前的通信关系定义为一个二分图, 分成两类, 返回 0 or 1 
      auto belongs_to_class1_first = [&](int player_idx) -> int {
        //  如果有多个 ring, 将后面的ring的index映射到第一个ring上
        //  此时有 ring_size & ring_counts
        //  每个环的大小为 ring_size， 共有 ring_counts 个环
        //  那么和 P0 等价地分在同一个组的 点一共有 ring_counts 个
        //  也就是 0,1,...,ring_counts-1
        //  那么只需要把 0,1,2,...,ring_counts 都映射到 0 即可

        //  把 0,1,2,..,num_players-1 一共分成 ring_size 组
        int equivalent_idx = player_idx / ring_counts * ring_counts;

        return reverse_map0[equivalent_idx] % 2;
      };  


      int round_index = i;
      int P_index = P.my_num();
      int receiver_num = (P_index - round_index - 1 + num_players) % num_players;
      int sender_num = (P_index + round_index + 1) % num_players;


      // std::cout << "first n-1 | round = " << roundj << "  Player.idx = " << P.my_num() << " reverse_idx =  " << reverse_map0[P.my_num() / ring_counts * ring_counts] << endl;

      if(belongs_to_class1_first(P.my_num()) == 0){
          //  send_to
          my_send(receiver_num, receiver_num);
          //  receive_from
          my_receive1(sender_num, P_index, round_index);
      }
      else{
          //  receive_from
          my_receive1(sender_num, P_index, round_index);
          //  send_to
          my_send(receiver_num, receiver_num);
      }

    }


    //  第二个 n-1 轮，广播数据
    //  第 j 轮, Pi 给 P_{i+j+1} 发送自己的第 i 个 block
    //  第 j 轮, Pi 从 P_{i-j-1} 接收其第 i-j-1 个 block
    
    for (int i = 0; i < num_players-1; i++){  // num_players - 1  rounds


      int roundj = i+1; //  定义为正整数
      int ring_counts = my_gcd(num_players, roundj);  //  通信结构当中环的个数
      int ring_size = num_players / ring_counts;
      //  如果有多个环，只考虑第一个环当中的归属关系

      //  记录 player_0 所在的环
      // std::vector<int> ring0_indices(num_players / ring_counts);
      // for (int j=0; j<=ring_size-1; j++){
      //   // ring0_indices[j] = (0 - roundj * j ) % num_players; 
      //   ring0_indices[j] = ( (num_players - roundj)* j ) % num_players; 
      // }

      std::map<int, int> ring1_indices;
      for (int j=0; j<ring_size; j++){
        // ring0_indices[j] = (0 - roundj * j ) % num_players; 
        // ring0_indices[j] = ( (num_players - roundj)* j ) % num_players; 
        ring1_indices.insert({j, ( roundj* j ) % num_players});
      }

      std::map<int, int> reverse_map1;
      for (const auto& pair : ring1_indices) {
          reverse_map1[pair.second] = pair.first;
      }
       


      //  将当前的通信关系定义为一个二分图, 分成两类, 返回 0 or 1 
      auto belongs_to_class1_second = [&](int player_idx) -> int {
        //  如果有多个 ring, 将后面的ring的index映射到第一个ring上
        //  此时有 ring_size & ring_counts
        //  每个环的大小为 ring_size， 共有 ring_counts 个环
        //  那么和 P0 等价地分在同一个组的 点一共有 ring_counts 个
        //  也就是 0,1,...,ring_counts-1
        //  那么只需要把 0,1,2,...,ring_counts 都映射到 0 即可

        //  把 0,1,2,..,num_players-1 一共分成 ring_size 组
        int equivalent_idx = player_idx / ring_counts * ring_counts;

        return reverse_map1[equivalent_idx] % 2;
      };  


      int round_index = i;
      int P_index = P.my_num();
      int receiver_num = (P_index + round_index + 1) % num_players;
      int sender_num = (P_index - round_index - 1 + num_players) % num_players;


      // std::cout << "first n-1 | round = " << roundj << "  Player.idx = " << P.my_num() << " reverse_idx =  " << reverse_map1[P.my_num() / ring_counts * ring_counts] << endl;


      if(belongs_to_class1_second(P.my_num()) == 0){
          //  send_to
          my_send(receiver_num, P_index);
          //  receive_from
          my_receive2(sender_num, sender_num, round_index);
      }
      else{
          //  receive_from
          my_receive2(sender_num, sender_num, round_index);
          //  send_to
          my_send(receiver_num, P_index);
      }
      

    }

    AddToValues(values);

    end = clock();
    // std::cout<<"ROTATEDSTAR = "<<double(end-st)/CLOCKS_PER_SEC<<"s"<<" size:"<<values_size<<"\n";

    std::cout << "ROTA with opening_sum(" << opening_sum << ") = " << double(end - st) / CLOCKS_PER_SEC << "s"  << " size:" << int(values.size()) << "\n";
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
void TreeSum<T>::add_openings(vector<T>& values, const Player& P,
    int sum_players, int last_sum_players, int send_player)
{
  // 初始化通信结构
  auto& MC = *this;
  MC.player_timers.resize(P.num_players());
  vector<octetStream>& oss = MC.oss;
  oss.resize(P.num_players());
  vector<int> senders;
  senders.reserve(P.num_players());
  bool use_lengths = values.size() == lengths.size();

  for (int relative_sender = positive_modulo(P.my_num() - send_player, P.num_players()) + sum_players;
      relative_sender < last_sum_players; relative_sender += sum_players)
    {
      int sender = positive_modulo(send_player + relative_sender, P.num_players());
      senders.push_back(sender);
    }

  for (int j = 0; j < (int)senders.size(); j++)
    // 接收信息
    P.request_receive(senders[j], oss[j]);

  for (int j = 0; j < (int)senders.size(); j++)
    {
      int sender = senders[j];
      MC.player_timers[sender].start();
      // 接收信息
      P.wait_receive(sender, oss[j]);
      MC.player_timers[sender].stop();
      MC.timers[SUM].start();
      // 把这里的add用来实现mpi op
      // debug找到这个add实现了什么？
      for (unsigned int i=0; i<values.size(); i++)
        {
          values[i].add(oss[j], use_lengths ? lengths[i] : -1);
        }
      post_add_process(values); // 这个函数是空的
      MC.timers[SUM].stop();
    }
}


// void RingSum<T>::run(vector<T>& values, const Player& P){
        
// }

template<class T>
void TreeSum<T>::start(vector<T>& values, const Player& P)
{
  //A parameter: sum at most n shares at once when using indirect communication
  // if openning_sum=2
  if (opening_sum < 2)
    opening_sum = P.num_players();

  // Maximum number of parties to send to at once
  // if max_broadcast=2
  if (max_broadcast < 2)
    max_broadcast = P.num_players();

  os.reset_write_head();
  int sum_players = P.num_players();
  // 相对数字是: (i % n + n) % n;
  int my_relative_num = positive_modulo(P.my_num() - base_player, P.num_players());
  bool use_lengths = values.size() == lengths.size();

  // ste1 向上规约
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

          for (unsigned int i=0; i<values.size(); i++)
            values[i].pack(os, use_lengths ? lengths[i] : -1);
          os.append(0);
          int receiver = positive_modulo(base_player + my_relative_num % sum_players, P.num_players());
          timers[SEND].start();
          // 发送
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

  // step2向下广播
  if (P.my_num() == base_player)
    {
      // send from the root player
      os.reset_write_head();  // 每次发送或者接收要清空缓存
      size_t n = values.size();
      for (unsigned int i=0; i<n; i++)
        values[i].pack(os, use_lengths ? lengths[i] : -1);
      os.append(0);
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
      // 从父亲节点接收
      ReceiveValues(values, P, sender);
      timers[BCAST].start();
      // 向孩子节点广播
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
  // 如果当前是叶子节点
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
  // 接收
  P.receive_player(sender, os);
  timers[RECV_SUM].stop();
  bool use_lengths = values.size() == lengths.size();
  // 从os里面unpack
  for (unsigned int i = 0; i < values.size(); i++)
    values[i].unpack(os, use_lengths ? lengths[i] : -1);
    // 后处理
  AddToValues(values);
}

#endif
