#ifndef PROTOCOLS_MAC_CHECK_HPP_
#define PROTOCOLS_MAC_CHECK_HPP_

#include "Protocols/MAC_Check.h"
#include "Tools/Subroutines.h"
#include "Tools/Exceptions.h"

#include "Tools/random.h"
#include "Tools/time-func.h"
#include "Tools/int.h"
#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"

#include <algorithm>

#include "Protocols/MAC_Check_Base.hpp"
#include "mac_key.hpp"

template<class T>
const char* TreeSum<T>::mc_timer_names[] = {
        "sending",
        "receiving and adding",
        "broadcasting",
        "receiving summed values",
        "random seed",
        "commit and open",
        "wait for summer thread",
        "receiving",
        "summing",
        "waiting for select()"
};

template<class U>
void Tree_MAC_Check<U>::setup(Player& P)
{
  assert(coordinator == 0);
  coordinator = new Coordinator(P.N, U::type_string() + to_string(U::clear::length()));
  U::prep_type::MAC_Check::coordinator = coordinator;
  U::prep_check_type::MAC_Check::coordinator = coordinator;
  U::bit_prep_type::MAC_Check::coordinator = coordinator;
  U::bit_prep_type::prep_check_type::MAC_Check::coordinator = coordinator;
  U::input_check_type::MAC_Check::coordinator = coordinator;
}

template<class U>
void Tree_MAC_Check<U>::teardown()
{
  if (coordinator)
    delete coordinator;
  coordinator = 0;
  U::prep_type::MAC_Check::coordinator = 0;
  U::prep_check_type::MAC_Check::coordinator = 0;
  U::bit_prep_type::MAC_Check::coordinator = 0;
  U::bit_prep_type::prep_check_type::MAC_Check::coordinator = 0;
  U::input_check_type::MAC_Check::coordinator = 0;
}

template<class U>
MAC_Check_<U>::MAC_Check_(const typename U::mac_key_type::Scalar& ai, int opening_sum,
    int max_broadcast, int send_player) :
    Tree_MAC_Check<U>(ai, opening_sum, max_broadcast, send_player)
{
}

template<class U>
Tree_MAC_Check<U>::Tree_MAC_Check(const typename U::mac_key_type::Scalar& ai, int opening_sum,
    int max_broadcast, int send_player) :
    TreeSum<T>(opening_sum, max_broadcast, send_player)
{
  popen_cnt=0;
  this->alphai=ai;
}

template<class T>
Tree_MAC_Check<T>::~Tree_MAC_Check()
{
#ifndef NO_SECURITY_CHECK
  if (WaitingForCheck() > 0)
    {
      cerr << endl << "SECURITY BUG: insufficient checking" << endl;
      terminate();
    }
#endif
}

template<class U>
void Tree_MAC_Check<U>::init_open(const Player&, int n)
{
  if (n > WaitingForCheck())
    {
      macs.reserve(macs.size() + n);
      vals.reserve(vals.size() + n);
    }

  this->secrets.clear();
  this->values.clear();
  this->secrets.reserve(n);
  this->values.reserve(n);
}

template<class U>
void Tree_MAC_Check<U>::prepare_open(const U& secret, int)
{
  assert(U::mac_type::invertible);
  this->values.push_back(secret.get_share());
  macs.push_back(secret.get_mac());
}

template<class U>
void Tree_MAC_Check<U>::exchange(const Player& P)
{
  this->run(this->values, P);

  this->values_opened += this->values.size();

  popen_cnt += this->values.size();

  if (OnlineOptions::singleton.has_option("always_check"))
    Check(P);
  else
    CheckIfNeeded(P);
}


template<class U>
void Tree_MAC_Check<U>::AddToValues(vector<T>& values)
{
  vals.insert(vals.end(), values.begin(), values.end());
}


template<class T>
void Tree_MAC_Check<T>::CheckIfNeeded(const Player& P)
{
  if (WaitingForCheck() >= POPEN_MAX)
    Check(P);
}


template <class U>
void Tree_MAC_Check<U>::AddToCheck(const U& share, const T& value, const Player& P)
{
  macs.push_back(share.get_mac());
  vals.push_back(value);
  popen_cnt++;
  CheckIfNeeded(P);
}



template<class U>
void mac_fail_remove(const Player& P)
{
  unlink(
      mac_filename<typename U::mac_key_type>(
          get_prep_sub_dir<U>(P.num_players()), P.my_num()).c_str());
  throw mac_fail();
}

template<class U>
void MAC_Check_<U>::Check(const Player& P)
{
  assert(U::mac_type::invertible);
  check_field_size<typename U::mac_type>();

  if (this->WaitingForCheck() == 0)
    return;

  //cerr << "In MAC Check : " << popen_cnt << endl;

  CODE_LOCATION
  auto& vals = this->vals;
  auto& macs = this->macs;
  auto& popen_cnt = this->popen_cnt;
  assert(int(macs.size()) <= popen_cnt);
  assert(this->coordinator);

  if (popen_cnt < 10)
    {
      // no random combination with few values
      vector<typename U::mac_type> deltas;
      Bundle<octetStream> bundle(P);
      for (int i = 0; i < popen_cnt; i++)
        {
          deltas.push_back(vals[i] * this->alphai - macs[i]);
          deltas.back().pack(bundle.mine);
        }
      this->timers[COMMIT].start();
      Commit_And_Open_(bundle, P, *this->coordinator);
      this->timers[COMMIT].stop();
      for (auto& delta : deltas)
        {
          for (auto& os : bundle)
            if (&os != &bundle.mine)
              delta += os.get<typename U::mac_type>();
          if (delta != 0)
            mac_fail_remove<U>(P);
        }
    }
  else
    {
      // check random combination
      octet seed[SEED_SIZE];
      this->timers[SEED].start();
      Create_Random_Seed(seed,P,SEED_SIZE);
      this->timers[SEED].stop();
      PRNG G;
      G.SetSeed(seed);

      U sj;
      typename U::mac_type a,gami,temp;
      typename U::mac_type::Scalar h;
      vector<typename U::mac_type> tau(P.num_players());
      for (int i=0; i<popen_cnt; i++)
        {
          h.almost_randomize(G);
          temp = vals[i] * h;
          a = (a + temp);

          temp = h * macs[i];
          gami = (gami + temp);
        }

      temp = this->alphai * a;
      tau[P.my_num()] = (gami - temp);

      //cerr << "\tCommit and Open" << endl;
      this->timers[COMMIT].start();
      Commit_And_Open(tau, P, *this->coordinator);
      this->timers[COMMIT].stop();

      //cerr << "\tFinal Check" << endl;

      typename U::mac_type t;
      for (int i=0; i<P.num_players(); i++)
        { t += tau[i]; }
      if (t != 0)
        mac_fail_remove<U>(P);
    }

  this->coordinator->finished();

  vals.erase(vals.begin(), vals.begin() + popen_cnt);
  macs.erase(macs.begin(), macs.begin() + popen_cnt);

  popen_cnt=0;
}

template<class T, class U, class V, class W>
MAC_Check_Z2k<T, U, V, W>::MAC_Check_Z2k(const T& ai, int opening_sum, int max_broadcast, int send_player) :
    Tree_MAC_Check<W>(ai, opening_sum, max_broadcast, send_player), prep(0)
{
}

template<class T, class U, class V, class W>
MAC_Check_Z2k<T, U, V, W>::MAC_Check_Z2k(const T& ai, Names& Nms,
        int thread_num) : MAC_Check_Z2k(ai)
{
    (void) Nms, (void) thread_num;
}

template<class T, class U, class V, class W>
void MAC_Check_Z2k<T, U, V, W>::prepare_open(const W& secret, int)
{
  prepare_open_no_mask(secret + (get_random_element() << W::clear::N_BITS));
}

template<class T, class U, class V, class W>
void MAC_Check_Z2k<T, U, V, W>::prepare_open_no_mask(const W& secret)
{
  this->values.push_back(secret.get_share());
  this->macs.push_back(secret.get_mac());
}

template<class T, class U, class V, class W>
W MAC_Check_Z2k<T, U, V, W>::get_random_element() {
  if (random_elements.size() > 0)
    {
      W res = random_elements.back();
      random_elements.pop_back();
      return res;
    }
  else
    {
      if (prep)
        return prep->get_random_for_open();
      else
      {
        insecure("random dummy");
        return {};
      }
    }
}

template<class T, class U, class V, class W>
void MAC_Check_Z2k<T, U, V, W>::set_random_element(const W& random_element) {
  random_elements.push_back(random_element);
}

template<class T, class U, class V, class W>
void MAC_Check_Z2k<T, U, V, W>::set_prep(Preprocessing<W>& prep)
{
  this->prep = &prep;
}

template<class T, class U, class V, class W>
void MAC_Check_Z2k<T, U, V, W>::Check(const Player& P)
{
  if (this->WaitingForCheck() == 0)
    return;

  CODE_LOCATION
#ifdef DEBUG_MAC
  cout << "Checking " << shares[0] << " " << this->vals[0] << " " << this->macs[0] << endl;
#endif

  octet seed[SEED_SIZE];
  Create_Random_Seed(seed,P,SEED_SIZE);
  PRNG G;
  G.SetSeed(seed);

  T y, mj;
  y.assign_zero();
  mj.assign_zero();
  for (int i = 0; i < this->popen_cnt; ++i)
  {
    U temp_chi;
    temp_chi.randomize(G);
    T xi = this->vals[i];
    y += xi * temp_chi;
    T mji = this->macs[i];
    mj += temp_chi * mji;
  }

  T zj = mj - this->alphai * y;
  vector<T> zjs(P.num_players());
  zjs[P.my_num()] = zj;

  assert(this->coordinator);
  Commit_And_Open(zjs, P, *this->coordinator);

  T zj_sum;
  zj_sum.assign_zero();
  for (int i = 0; i < P.num_players(); ++i)
    zj_sum += zjs[i];

  this->vals.erase(this->vals.begin(), this->vals.begin() + this->popen_cnt);
  this->macs.erase(this->macs.begin(), this->macs.begin() + this->popen_cnt);
  this->popen_cnt=0;
  if (!zj_sum.is_zero())
    mac_fail_remove<W>(P);

  this->coordinator->finished();
}



template<class T>
Direct_MAC_Check<T>::Direct_MAC_Check(const typename T::mac_key_type::Scalar& ai,
    Names&, int) :
    Direct_MAC_Check<T>(ai)
{
}

template<class T>
Direct_MAC_Check<T>::Direct_MAC_Check(const typename T::mac_key_type::Scalar& ai) :
    Tree_MAC_Check<T>(ai), MAC_Check_<T>(ai)
{
  open_counter = 0;
}


template<class T>
Direct_MAC_Check<T>::~Direct_MAC_Check() {
  cerr << T::type_string() << " open counter: " << open_counter << endl;
}

template<class T>
void direct_add_openings(vector<T>& values, const PlayerBase& P, vector<octetStream>& os)
{
  size_t n = P.num_players();
  size_t me = P.my_num();
  assert(os.size() == n);
  for (auto& value : values)
    for (size_t j = 0; j < n; j++)
      if (j != me)
        value += os[j].get<T>();
}

template<class T>
void Direct_MAC_Check<T>::pre_exchange(const Player& P)
{
  oss.resize(P.num_players());
  oss[P.my_num()].reset_write_head();
  oss[P.my_num()].reserve(this->values.size() * T::open_type::size());

  for (auto& x : this->values)
    x.pack(oss[P.my_num()]);
  oss[P.my_num()].append(0);
}


template<class T>
void Direct_MAC_Check<T>::exchange(const Player& P)
{
  CODE_LOCATION
  pre_exchange(P);
  P.unchecked_broadcast(oss);

  open_counter++;

  direct_add_openings<open_type>(this->values, P, oss);

  this->AddToValues(this->values);

  this->popen_cnt += this->values.size();
  this->CheckIfNeeded(P);
}

template<class T>
void Direct_MAC_Check<T>::init_open(const Player& P, int n)
{
  super::init_open(P, n);
}

template<class T>
void Direct_MAC_Check<T>::prepare_open(const T& secret, int)
{
  assert(T::mac_type::invertible);
  this->values.push_back(secret.get_share());
  this->macs.push_back(secret.get_mac());
}

#endif
