
#ifndef _fake_stuff
#define _fake_stuff

#include <fstream>
using namespace std;

#include "Networking/Player.h"
#include "Processor/Data_Files.h"
#include "Math/Setup.h"
#include "Tools/benchmarking.h"

template<class T>
void check_share(vector<T>& Sa, typename T::clear& value,
    typename T::mac_type& mac, int N, const typename T::mac_key_type& key);

template<class T> class Share;

template<class T, class V>
void check_share(vector<Share<T> >& Sa,
  V& value,
  T& mac,
  int N,
  const T& key);

// Generate MAC key shares
void generate_keys(const string& directory, int nplayers);

template <class T>
void write_mac_key(const string& directory, int player_num, int nplayers, T key);

template <class U>
void read_mac_key(const string& directory, int player_num, int nplayers, U& key);
template <class U>
void read_mac_key(const string& directory, const Names& N, U& key);

template <class T>
typename T::mac_key_type read_generate_write_mac_key(Player& P,
        string directory = "");

void check_files(ofstream* outf, int N);

template<class T>
class KeySetup
{
public:
    typename T::mac_share_type::open_type key;
    vector<typename T::mac_share_type> key_shares;

    typename T::mac_share_type get(size_t i) const
    {
        if (key_shares.empty())
            return {};
        else
            return key_shares.at(i);
    }
};

class FilesBase
{
public:
  virtual ~FilesBase() {}
  virtual void output_shares(word a) = 0;

  void make_AES(int n, bool zero, PRNG& G);
  void make_DES(int n, bool zero, PRNG& G);
};

template <class T>
class Files : public FilesBase
{
  void open(int i, const string& filename)
  {
    cout << "Opening " << filename << endl;
    outf[i].open(filename,ios::out | ios::binary);
    file_signature<T>(key.get(i)).output(outf[i]);
    if (outf[i].fail())
      throw file_error(filename);
  }

public:
  ofstream* outf;
  int N;
  KeySetup<T> key;
  PRNG& G;
  Files(int N, const KeySetup<T>& key, const string& prep_data_prefix,
      Dtype type, PRNG& G, int thread_num = -1) :
      Files(N, key,
          get_prep_sub_dir<T>(prep_data_prefix, N, true)
              + DataPositions::dtype_names[type] + "-" + T::type_short(),
          G, thread_num)
  {
  }
  Files(int N, const KeySetup<T>& key, const string& prefix,
      PRNG& G, int thread_num = -1) :
      N(N), key(key), G(G)
  {
    insecure_fake(false);
    outf = new ofstream[N];
    for (int i=0; i<N; i++)
      {
        stringstream filename;
        filename << prefix << "-P" << i;
        filename << PrepBase::get_suffix(thread_num);
        open(i, filename.str());
      }
  }
  Files(const KeySetup<T>& key, const vector<string>& filenames, PRNG& G) :
      N(filenames.size()), key(key), G(G)
  {
    insecure_fake(false);
    outf = new ofstream[N];
    for (int i = 0; i < N; i++)
      open(i, filenames[i]);
  }
  ~Files()
  {
    check_files(outf, N);
    delete[] outf;
  }

  void output_shares(word a)
  {
    output_shares(typename T::open_type(a));
  }
  template<class U = T>
  void output_shares(const typename U::open_type& a)
  {
    output_shares<T>(a, key.key);
  }
  template<class U, class V>
  void output_shares(const typename U::open_type& a,
      const V& key)
  {
    vector<U> Sa(N);
    make_share(Sa,a,N,key,G);
    for (int j=0; j<N; j++)
      Sa[j].output(outf[j],false);
  }
};

#endif
