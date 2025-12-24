#ifndef PROTOCOLS_FAKE_STUFF_HPP_
#define PROTOCOLS_FAKE_STUFF_HPP_

#include "Protocols/fake-stuff.h"
#include "Processor/Data_Files.h"
#include "Tools/benchmarking.h"
#include "Math/Setup.h"
#include "GC/CcdSecret.h"
#include "GC/square64.h"
#include "FHE/tools.h"

#include "Protocols/ShamirInput.hpp"

#include <fstream>

template<class T> class Share;
template<class T> class SemiShare;
template<class T> class ShamirShare;
template<class T> class MaliciousShamirShare;
template<class T, int L> class FixedVec;
template<class T, class V> class Share_;
template<class T> class SpdzWiseShare;
template<class T, int L> class MamaMac;
template<class> class MaliciousRep3Share;
template<class> class DealerShare;

namespace GC
{
template<int S> class TinySecret;
template<class T> class TinierSecret;
template<class T> class MaliciousCcdSecret;
}

template<class T, class U, class V, class W>
void make_share(Share_<T, W>* Sa,const U& a,int N,const V& key,PRNG& G)
{
  vector<T> shares(N);
  vector<W> macs(N);
  make_share(shares.data(), a, N, GC::NoValue(), G);
  make_share(macs.data(), a * key, N, GC::NoValue(), G);
  for (int i = 0; i < N; i++)
    {
      Sa[i].set_share(shares[i]);
      Sa[i].set_mac(macs[i]);
    }
}

template<class T, class U, class V>
void make_vector_share(T* Sa,const U& a,int N,const V& key,PRNG& G)
{
  int length = Sa[0].default_length;
  for (int i = 0; i < N; i++)
    Sa[i].resize_regs(length);
  for (int j = 0; j < length; j++)
    {
      vector<typename T::part_type> shares(N);
      make_share(shares, typename T::part_type::clear(a.get_bit(j)), N, key, G);
      for (int i = 0; i < N; i++)
        Sa[i].get_reg(j) = shares[i];
    }
}

template<int S, class U, class V>
void make_share(GC::TinySecret<S>* Sa, const U& a, int N, const V& key, PRNG& G)
{
  make_vector_share(Sa, a, N, key, G);
}

template<class T, class U, class V>
void make_share(GC::TinierSecret<T>* Sa, const U& a, int N, const V& key, PRNG& G)
{
  make_vector_share(Sa, a, N, key, G);
}

template<class T, class U, class V>
void make_share(SemiShare<T>* Sa,const V& a,int N,const U&,PRNG& G)
{
  T x, S = a;
  for (int i=0; i<N-1; i++)
    {
      x.randomize(G);
      Sa[i] = x;
      S -= x;
    }
  Sa[N-1]=S;
}

template<class T, class U, class V, int L>
void make_share(MamaMac<V, L>* Sa,const T& a,int N,const U&,PRNG& G)
{
  T x, S = a;
  for (int i=0; i<N-1; i++)
    {
      x.randomize(G);
      Sa[i] = x;
      S -= x;
    }
  Sa[N-1]=S;
}

template<class T, class U>
void make_share(DealerShare<T>* Sa, const T& a, int N, const U&, PRNG& G)
{
  make_share((SemiShare<T>*) Sa, a, N - 1, U(), G);
}

template<class T, class U, class V>
void make_share(FixedVec<T, 2>* Sa, const V& a, int N, const U& key, PRNG& G);

template<class T, class U>
inline void make_share(vector<T>& Sa,
    const typename T::open_type& a, int N, const U& key,
    PRNG& G)
{
  Sa.resize(N);
  make_share(Sa.data(), a, N, key, G);
}

template<class T, class U, class V>
void make_share(FixedVec<T, 2>* Sa, const V& a, int N, const U& key, PRNG& G)
{
  (void) key;
  assert(N == 3);
  FixedVec<T, 3> add_shares;
  // hack
  add_shares.randomize_to_sum(a, G);
  for (int i=0; i<N; i++)
    {
      FixedVec<T, 2> share;
      share[0] = add_shares[(i + 1) % 3];
      share[1] = add_shares[i];
      Sa[i] = share;
    }
}

template<class T, class U, class V>
void make_share(FixedVec<T, 3>* Sa, const V& a, int N, const U& key, PRNG& G)
{
  (void) key;
  assert(N == 4);
  FixedVec<T, 4> add_shares;
  add_shares.randomize_to_sum(a, G);
  for (int i=0; i<N; i++)
    {
      FixedVec<T, 3> share;
      share[0] = add_shares[(i + 0) % 4];
      share[1] = add_shares[(i + 1) % 4];
      share[2] = add_shares[(i + 2) % 4];
      Sa[i] = share;
    }
}

template<class T>
class VanderStore
{
public:
  static vector<vector<T>> vandermonde;
};

template<class T>
vector<vector<T>> VanderStore<T>::vandermonde;

template<class T, class V>
void make_share(ShamirShare<T>* Sa, const V& a, int N,
    const GC::NoValue&, PRNG& G)
{
  auto& vandermonde = VanderStore<T>::vandermonde;
  if (vandermonde.empty())
      vandermonde = ShamirInput<ShamirShare<T>>::get_vandermonde(N / 2, N);
  vector<T> randomness(N / 2);
  for (auto& x : randomness)
      x.randomize(G);
  for (int i = 0; i < N; i++)
  {
      auto& share = Sa[i];
      share = a;
      for (int j = 0; j < ShamirOptions::singleton.threshold; j++)
          share += vandermonde.at(i).at(j) * randomness[j];
  }
}

template<class T, class V>
void check_share(vector<Share<T> >& Sa,
  V& value,
  T& mac,
  int N,
  const T& key)
{
  value = (0);
  mac = (0);

  for (int i=0; i<N; i++)
    {
      value += (Sa[i].get_share());
      mac += (Sa[i].get_mac());
    }

  V res;
  res = value * key;
  if (res != mac)
    {
      cout << "Value:      " << value << endl;
      cout << "Input MAC:  " << mac << endl;
      cout << "Actual MAC: " << res << endl;
      cout << "MAC key:    " << key << endl;
      throw mac_fail();
    }
}

template<class T>
void check_share(vector<T>& Sa, typename T::clear& value,
    typename T::mac_type& mac, int N, const typename T::mac_key_type& key)
{
  assert(N == 3);
  value = 0;
  (void)key;
  (void)mac;

  for (int i = 0; i < N; i++)
    {
      auto share = Sa[i];
      value += share[0];
      auto a = share[1];
      auto b = Sa[positive_modulo(i - 1, N)][0];
      if (a != b)
      {
        cout << a << " != " << b << endl;
        for (int i = 0; i < N; i++)
          cout << Sa[i] << endl;
        throw bad_value("invalid replicated secret sharing");
      }
    }
}

template<class T>
inline string mac_filename(string directory, int playerno)
{
  if (directory.empty())
    directory = ".";
  return directory + "/Player-MAC-Keys-" + T::type_short() + "-P"
      + to_string(playerno);
}

template <>
inline void write_mac_key(const string&, int, int, GC::NoValue)
{
}

template <class U>
void write_mac_key(const string& directory, int i, int nplayers, U key)
{
  ofstream outf;
  stringstream filename;
  filename << mac_filename<U>(directory, i);
#ifdef VERBOSE
  cout << "Writing to " << filename.str().c_str() << endl;
#endif
  if (not directory.empty())
    mkdir_p(directory.c_str());
  outf.open(filename.str().c_str());
  outf << nplayers << endl;
  key.output(outf,true);
  if (outf.fail())
    throw IO_Error("cannot write to " + filename.str());
  outf.close();
}

template <class T>
void write_mac_key(const Names& N, typename T::mac_key_type key)
{
  write_mac_key(get_prep_sub_dir<T>(N.num_players()), N.my_num(),
      N.num_players(), key);
}

template <class T>
void read_mac_key(const Names& N, typename T::mac_key_type& key)
{
  read_mac_key(get_prep_sub_dir<T>(N.num_players()), N, key);
  T::set_mac_key(key);
}

template <class T>
void read_mac_key(const string& directory, const Names& N, T& key)
{
  read_mac_key(directory, N.my_num(), N.num_players(), key);
}

template <>
inline void read_mac_key(const string&, int, int, GC::NoValue&)
{
}

template <class U>
void read_mac_key(const string& directory, int player_num, int nplayers, U& key)
{
  int nn;

  string filename = mac_filename<U>(directory, player_num);
  ifstream inpf;
#ifdef VERBOSE
  cerr << "Reading MAC keys from " << filename << endl;
#endif
  inpf.open(filename);
  if (inpf.fail())
    {
#ifdef VERBOSE
      cerr << "Could not open MAC key file. Perhaps it needs to be generated?\n";
#endif
      throw mac_key_error(filename);
    }
  inpf >> nn;
  if (nn!=nplayers)
    { cerr << "KeyGen was last run with " << nn << " players." << endl;
      cerr << "  - You are running Online with " << nplayers << " players." << endl;
      throw mac_key_error(filename);
    }

  try
  {
      key.input(inpf,true);
  }
  catch(exception&)
  {
      throw mac_key_error(filename);
  }

  if (inpf.fail())
      throw mac_key_error(filename);

  inpf.close();
}

template<class T>
typename T::mac_key_type read_generate_write_mac_key(Player& P,
        string directory)
{
  if (directory == "")
    directory = get_prep_sub_dir<T>(P.num_players());
  typename T::mac_key_type res, tmp;

  try
  {
      read_mac_key(directory, P.my_num(), P.num_players(), tmp);
  }
  catch (mac_key_error&)
  {
  }

  T::read_or_generate_mac_key(directory, P, res);

  // only write if changed
  if (tmp != res)
      write_mac_key(directory, P.my_num(), P.num_players(), res);

  return res;
}

template<>
inline GC::NoValue read_generate_write_mac_key<GC::NoShare>(Player&,
        string)
{
  return {};
}

template <class U>
KeySetup<U> read_global_mac_key(const string& directory, int nparties)
{
  if (is_same<typename U::mac_share_type::open_type, GC::NoValue>())
    return {};

  KeySetup<U> res;
  res.key_shares.resize(nparties);

  auto& key = res.key;
  key.assign_zero();

  cout << U::type_string() << "keys :" << endl;
  for (int i= 0; i < nparties; i++)
    {
      typename U::mac_key_type pp;
      read_mac_key(directory, i, nparties, pp);
      cout << " Key " << i << ": " << pp << endl;
      key += pp;
      res.key_shares.at(i) = pp;
    }

  cout << "--------------\n";
  cout << "Final Key : " << key << endl;

  return res;
}

template <class U>
void read_global_mac_key(const string& directory, int nparties, U& key)
{
  key = read_global_mac_key<Share<U>>(directory, nparties).key;
}

template <>
inline void read_global_mac_key(const string&, int, GC::NoValue&)
{
}

template <class T>
T reconstruct(vector<T>& shares)
{
  return sum(shares);
}

template <class T>
T reconstruct(vector<MaliciousRep3Share<T>>& shares)
{
  T res;
  for (auto& x : shares)
    res += x[0];
  return res;
}

template <class T>
T reconstruct(vector<MaliciousShamirShare<T>>& shares)
{
  T res;
  for (size_t i = 0; i < shares.size(); i++)
    res += Shamir<ShamirShare<T>>::get_rec_factor(i, shares.size()) * shares[i];
  return res;
}

template<class T>
void make_mac_key_share(KeySetup<T>& setup, int nplayers, T, PRNG& G)
{
  setup.key.randomize(G);
  make_share(setup.key_shares.data(), setup.key, nplayers, GC::NoValue(), G);
  assert(not setup.key_shares[0].is_zero());
}

template<int K, int S>
void make_mac_key_share(KeySetup<Spdz2kShare<K, S>>& setup, int nplayers, Spdz2kShare<K, S>, PRNG& G)
{
  auto& key = setup.key;
  auto& key_shares = setup.key_shares;
  key = {};
  key_shares.resize(nplayers);
  for (int i = 0; i < nplayers; i++)
    {
      key_shares[i] = G.get<Z2<S>>();
      key += key_shares[i];
    }
  assert(not key.is_zero());
}

template<class T>
void generate_mac_keys(KeySetup<T>& key_setup,
    int nplayers, string prep_data_prefix, PRNG& G)
{
  auto& key = key_setup.key;
  auto& key_shares = key_setup.key_shares;
  key.assign_zero();
  int tmpN = 0;
  ifstream inpf;
  prep_data_prefix = get_prep_sub_dir<T>(prep_data_prefix, nplayers, true);
  bool generate = false;
  key_shares.resize(nplayers);


  cout << T::type_string() << " keys:" << endl;
  for (int i = 0; i < nplayers; i++)
    {
      auto& pp = key_shares[i];
      string filename;
      filename = mac_filename<typename T::mac_key_type>(prep_data_prefix, i);
      inpf.open(filename);
      if (inpf.fail())
        {
          inpf.close();
          cout << "No MAC key share for player " << i << ", generating a fresh ones\n";
          generate = true;
          break;
        }
      else
        {
          inpf >> tmpN; // not needed here
          pp.input(inpf,true);
          inpf.close();
          if (pp.is_zero())
            {
              generate = true;
              break;
            }
        }
      cout << " Key " << i << ": " << pp << ", ";
      octetStream os;
      pp.pack(os);
      pprint_bytes("raw", (unsigned char*) os.get_data(), os.get_length());
    }

  key = reconstruct(key_shares);

  if (generate)
    {
      make_mac_key_share(key_setup, nplayers, T(), G);

      for (int i = 0; i < nplayers; i++)
        {
          auto& pp = key_shares[i];
          string filename;
          filename = mac_filename<typename T::mac_key_type>(prep_data_prefix,
              i);
          ofstream outf(filename);
          if (outf.fail())
            throw file_error(filename);
          outf << nplayers << " " << pp << endl;
          outf.close();
          cout << "Written new MAC key share to " << filename << endl;
          cout << " Key " << i << ": " << pp << endl;
        }
    }

  cout << "--------------\n";
  cout << "Final Key: " << key << endl;
}

inline void check_files(ofstream* outf, int N)
{
  for (int i = 0; i < N; i++)
    if (outf[i].fail())
      throw runtime_error("couldn't write to file");
}

/* N      = Number players
 * ntrip  = Number triples needed
 */
template<class T>
void make_mult_triples(const KeySetup<T>& key, int N, int ntrip,
    bool zero, string prep_data_prefix, PRNG& G, int thread_num = -1)
{
  T::clear::write_setup(get_prep_sub_dir<T>(prep_data_prefix, N));
  Files<T> files(N, key, prep_data_prefix, DATA_TRIPLE, G, thread_num);

  typename T::clear a,b,c;
  /* Generate Triples */
  for (int i=0; i<ntrip; i++)
    {
      if (!zero)
        a.randomize(G);
      if (!zero)
        b.randomize(G);
      auto c = typename T::open_type(a) * b;
      files.output_shares(a);
      files.output_shares(b);
      files.output_shares(c);
    }
  check_files(files.outf, N);
}

/* N      = Number players
 * ntrip  = Number inverses needed
 */
template<class T>
void make_inverse(const KeySetup<T>& key, int N, int ntrip, bool zero,
    string prep_data_prefix, PRNG& G)
{

  Files<T> files(N, key, prep_data_prefix, DATA_INVERSE, G);
  typename T::clear a,b;
  for (int i=0; i<ntrip; i++)
    {
      if (zero)
        // ironic?
        a.assign_one();
      else
        do
          a.randomize(G);
        while (a.is_zero());
      files.output_shares(a);
      files.output_shares(a.invert());
    }
  check_files(files.outf, N);
}

template<class T, class U>
void plain_edabits(vector<T>& as,
    vector<U>& bs, int length, PRNG& G, int max_size,
    bool zero = false)
{
  as.resize(max_size);
  bs.clear();
  bs.resize(length);
  Z2<T::MAX_EDABITS> value;
  for (int j = 0; j < max_size; j++)
    {
      if (not zero)
        value.randomize_part(G, length);
      as[j] = value;
      if (max_size > 64 or length > 64)
        for (int k = 0; k < length; k++)
          bs[k] ^= BitVec(value.get_bit(k)) << j;
    }

  if (max_size <= 64 and length <= 64)
    {
      square64 square;
      for (int j = 0; j < max_size; j++)
        square.rows[j] = Z2<64>(as[j]).get_limb(0);
      square.transpose(max_size, length);
      for (int k = 0; k < length; k++)
        bs[k] = square.rows[k];
    }
}

#endif
