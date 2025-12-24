
#include "Math/gf2n.h"
#include "Math/gfp.h"
#include "Protocols/Share.h"
#include "Math/Setup.h"
#include "Protocols/Spdz2kShare.h"
#include "Protocols/BrainShare.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/PostSacriRepRingShare.h"
#include "Protocols/PostSacriRepFieldShare.h"
#include "Protocols/SemiShare.h"
#include "Protocols/MaliciousShamirShare.h"
#include "Protocols/SpdzWiseRingShare.h"
#include "Protocols/SpdzWiseShare.h"
#include "Protocols/Rep4Share2k.h"
#include "Protocols/MamaShare.h"
#include "Protocols/fake-stuff.h"
#include "Tools/Exceptions.h"
#include "GC/MaliciousRepSecret.h"
#include "GC/SemiSecret.h"
#include "GC/TinySecret.h"
#include "GC/TinierSecret.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/Rep4Secret.h"

#include "Math/Setup.h"
#include "Processor/Data_Files.h"
#include "Tools/mkpath.h"
#include "Tools/ezOptionParser.h"
#include "Tools/benchmarking.h"

#include "Protocols/fake-stuff.hpp"
#include "Protocols/Shamir.hpp"
#include "Protocols/Share.hpp"
#include "Processor/Data_Files.hpp"
#include "Math/Z2k.hpp"
#include "Math/gfp.hpp"
#include "GC/Secret.hpp"
#include "Machines/Shamir.hpp"

#include <sstream>
#include <fstream>
using namespace std;


string prep_data_prefix;

class FakeParams
{
  int nplayers, default_num;
  int n_edabits;
  bool zero;

public:
  ez::ezOptionParser opt;
  DataPositions usage;

  template<class T>
  int generate();

  template<class T>
  void generate_field(true_type, PRNG& G);
  template<class T>
  void generate_field(false_type, PRNG&)
  {
  }

  template<int K>
  void generate_ring(PRNG& G);

  template<class T>
  void make_with_mac_key(int nplayers, int default_num, bool zero,PRNG& G,
      const KeySetup<typename T::bit_type::part_type>& bit_keys = {});
  template<class T>
  void make_basic(const KeySetup<T>& key, int nplayers, int nitems,
      bool zero, PRNG& G, const KeySetup<typename T::bit_type::part_type>& bit_keys = {});
  template<class T>
  void make_minimal(const KeySetup<T>& key, int nplayers, int nitems, bool zero, PRNG& G);

  template<class T>
  void make_mult_triples(const KeySetup<T>& key, int N, int ntrip,
      bool zero, const string& prep_data_prefix, PRNG& G, int thread_num = -1);
  template<class T>
  void make_square_tuples(const KeySetup<T>& key, int N, int ntrip,
      const string& str, bool zero, PRNG& G);
  template<class T>
  void make_bits(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G,
      int thread_num = -1);
  template<class T>
  void make_inverse(const KeySetup<T>& key, int N, int ntrip,
      bool zero, const string& prep_data_prefix, PRNG& G);

  template<class T>
  void make_inputs(const KeySetup<T>& key, int N, int ntrip, const string& str,
      bool zero, PRNG& G);

  template<class T>
  void make_dabits(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G,
      const KeySetup<typename T::bit_type::part_type>& bit_key = { });
  template<class T>
  void make_edabits(const KeySetup<T>& key, int N, PRNG& G, false_type,
      const KeySetup<typename T::bit_type::part_type>& bit_key = {});
  template<class T>
  void make_edabits(const KeySetup<T>&, int, PRNG&, true_type,
      const KeySetup<typename T::bit_type::part_type>& = {})
  {
  }

  template<class T>
  void make_matrix_triples(const KeySetup<T>& key, PRNG& G);

  template<class T>
  int get_usage(Dtype type, int def)
  {
    auto field_type = T::clear::field_type();
    if (not usage.empty())
      {
        auto res = usage.files[field_type][type] + BUFFER_SIZE;
        if (type == DATA_TRIPLE and field_type == DATA_INT)
          res -= usage.triples_for_matmul();
        return limit(res);
      }
    else
      return def;
  }

  long long limit(long long demand)
  {
    if (opt.isSet("--default") and default_num < demand)
      return default_num;
    else
      return demand;
  }
};

template<class T>
void FakeParams::make_mult_triples(const KeySetup<T>& key, int N,
    int ntrip, bool zero, const string& prep_data_prefix, PRNG& G, int thread_num)
{
  ::make_mult_triples(key, N, get_usage<T>(DATA_TRIPLE, ntrip), zero,
      prep_data_prefix, G, thread_num);
}

template<class T>
void FakeParams::make_inverse(const KeySetup<T>& key, int N,
    int ntrip, bool zero, const string& prep_data_prefix, PRNG& G)
{
  ::make_inverse(key, N, get_usage<T>(DATA_INVERSE, ntrip), zero,
      prep_data_prefix, G);
}

/* N      = Number players
 * ntrip  = Number tuples needed
 */
template<class T>
void FakeParams::make_square_tuples(const KeySetup<T>& key, int N, int ntrip,
    const string& str, bool zero, PRNG& G)
{
  (void) str;
  ntrip = get_usage<T>(DATA_SQUARE, ntrip);
  Files<T> files(N, key, prep_data_prefix, DATA_SQUARE, G);
  typename T::clear a,c;
  /* Generate Squares */
  for (int i=0; i<ntrip; i++)
    {
      if (!zero)
        a.randomize(G);
      c = a * a;
      files.output_shares(a);
      files.output_shares(c);
    }
  check_files(files.outf, N);
}

/* N      = Number players
 * ntrip  = Number bits needed
 */
template<class T>
void FakeParams::make_bits(const KeySetup<T>& key, int N, int ntrip, bool zero,
    PRNG& G, int thread_num)
{
  ntrip = get_usage<T>(DATA_BIT, ntrip);

  Files<T> files(N, key, prep_data_prefix, DATA_BIT, G, thread_num);
  typename T::clear a;
  /* Generate Bits */
  for (int i=0; i<ntrip; i++)
    { if ((G.get_uchar()&1)==0 || zero) { a.assign_zero(); }
      else                       { a.assign_one();  }
      files.output_shares(a);
    }
  check_files(files.outf, N);
}

template<class T>
void FakeParams::make_dabits(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G,
    const KeySetup<typename T::bit_type::part_type>& bit_key)
{
  ntrip = get_usage<T>(DATA_DABIT, ntrip);
  Files<T> files(N, key, prep_data_prefix, DATA_DABIT, G);
  for (int i = 0; i < ntrip; i++)
    {
      bool bit = not zero && G.get_bit();
      files.template output_shares<T>(bit);
      files.template output_shares<typename dabit<T>::bit_type>(bit, bit_key.key);
    }
}

template<class T>
void FakeParams::make_edabits(const KeySetup<T>& key, int N, PRNG& G, false_type,
    const KeySetup<typename T::bit_type::part_type>& bit_key)
{
  vector<int> lengths;
  opt.get("-e")->getInts(lengths);

  if (not usage.empty())
    {
      lengths.clear();
      for (auto& x : usage.edabits)
        lengths.push_back(x.first.second);
    }

  for (auto length : lengths)
    {
      vector<string> filenames;
      for (int i = 0; i < N; i++)
        filenames.push_back(
            PrepBase::get_edabit_filename(
                get_prep_sub_dir<T>(prep_data_prefix, N), length, i));
      Files<T> files(key, filenames, G);
      bigint value;
      int max_size = edabitvec<T>::MAX_SIZE;
      int n;

      if (usage.empty())
        n = DIV_CEIL(n_edabits, max_size);
      else
        n = limit(usage.edabits[{false, length}] +
            usage.edabits[{true, length}]);

      for (int i = 0; i < n + 1; i++)
        {
          vector<typename T::clear> as;
          vector<typename T::bit_type::part_type::clear> bs;
          plain_edabits(as, bs, length, G, max_size, zero);
          for (auto& a : as)
            files.template output_shares<T>(a);
          for (auto& b : bs)
            files.template output_shares<typename T::bit_type::part_type>(b, bit_key.key);
        }
    }
}

/* N      = Number players
 * ntrip  = Number inputs needed
 */
template<class T>
void FakeParams::make_inputs(const KeySetup<T>& key, int N, int ntrip,
    const string& str, bool zero, PRNG& G)
{
  (void) str;

  typename T::open_type a;
  vector<T> Sa(N);
  /* Generate Inputs */
  for (int player=0; player<N; player++)
    {
      if (not usage.empty())
        {
          ntrip = usage.inputs.at(player)[T::clear::field_type()];
          if (T::randoms_for_opens)
            ntrip += get_usage<T>(DATA_OPEN, 0);
          ntrip = limit(ntrip) + BUFFER_SIZE;
        }

      vector<string> filenames;
      for (int i=0; i<N; i++)
        {
          string filename = PrepBase::get_input_filename(
              get_prep_sub_dir<T>(prep_data_prefix, N), T::type_short(), player,
              i);
          filenames.push_back(filename);
        }
      Files<T> files(key, filenames, G);
      for (int i=0; i<ntrip; i++)
        {
          if (!zero)
            a.randomize(G);
          files.output_shares(a);
          a.output(files.outf[player], false);
        }
    }
}


template<class T>
void make_PreMulC(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G)
{
  stringstream ss;
  ss << get_prep_sub_dir<T>(prep_data_prefix, N) << "PreMulC-" << T::type_short();
  Files<T> files(N, key, ss.str(), G);
  typename T::clear a, b, c;
  c = 1;
  for (int i=0; i<ntrip; i++)
    {
      // close the circle
      if (i == ntrip - 1 || zero)
        a.assign_one();
      else
        do
          a.randomize(G);
        while (a.is_zero());
      files.output_shares(a);
      b = a.invert();
      files.output_shares(b);
      files.output_shares(a * c);
      c = b;
    }
}
// Code for TTP AES
unsigned char sbox[256] =
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

template<class T>
void make_AES(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G) {
  stringstream ss;
  ss << get_prep_sub_dir<T>(prep_data_prefix, N) << "Sbox-" << T::type_short();
  Files<T> files(N, key, ss.str(), G);
  files.make_AES(ntrip, zero, G);
}

void FilesBase::make_AES(int ntrip, bool zero, PRNG& G)
{
  auto& files = *this;
  gf2n_short x;

  for (int i = 0; i < ntrip; i++)
    {
      int mask = 0;
      if (!zero)
        mask = G.get_uchar();
      expand_byte(x, mask);
      files.output_shares(x.get());

      for (int j = 0; j < 256; j++)
        {
          expand_byte(x, sbox[mask ^ j]);
          files.output_shares(x.get());
        }
    }
}

// Code for TTP DES
vector<vector<unsigned char>> des_sbox = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
};


template<class T>
void make_DES(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G)
{
  stringstream ss;
  ss << get_prep_sub_dir<T>(prep_data_prefix, N) << "SboxDes-" << T::type_short();
  Files<T> files(N, key, ss.str(), G);
  files.make_DES(ntrip, zero, G);
}

void FilesBase::make_DES(int ntrip, bool zero, PRNG& G)
{
  auto& files = *this;
  gf2n_short x;

  for (int i = 0; i < ntrip; i++)
    {
      for (int r = 0; r < 8; ++r) {
        int mask = 0;
        if (!zero)
          mask = G.get_uchar();
        mask &= 63; //take only first 6 bits
        expand_byte(x, mask);
        files.output_shares(x.get());
        for (int j = 0; j < 64; j++)
          {
            files.output_shares(des_sbox[r][mask ^ j]);
          }
      }
    }
}

template<class T>
void make_Sbox(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G, T, true_type)
{
  make_AES<T>(key, N, ntrip, zero, G);
  make_DES<T>(key, N, ntrip, zero, G);
}


template<class T>
void make_Sbox(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG&, T, false_type)
{
  (void)key, (void)N, (void)ntrip, (void)zero;
}

template<class T>
void make_Sbox(const KeySetup<T>& key, int N, int ntrip, bool zero, PRNG& G)
{
  make_Sbox(key, N, ntrip, zero, G, T(), T::clear::characteristic_two);
}

template<class T>
void FakeParams::make_matrix_triples(const KeySetup<T>& key, PRNG& G)
{
    for (auto& x : usage.matmuls)
        if (x.second > 0)
        {
            auto& dim = x.first;
            Files<T> files(nplayers, key,
                    PrepBase::get_matrix_prefix(
                            get_prep_sub_dir<T>(prep_data_prefix, nplayers,
                                    true), dim), G);
            for (int i = 0; i < limit(x.second); i++)
            {
                ValueMatrix<typename T::open_type> matrices[3] = {{dim[0], dim[1]}, {dim[1],
                        dim[2]}, {dim[0], dim[2]}};
                for (auto& matrix : matrices)
                    matrix.entries.init();
                if (zero)
                {
                    for (int i = 0; i < 2; i++)
                    {
                        for (int j = 0;
                                j < min(matrices[i].n_rows, matrices[i].n_cols);
                                j++)
                        {
                            matrices[i][{j, j}] = 1;
                        }
                    }
                }
                else
                {
                    matrices[0].randomize(G);
                    matrices[1].randomize(G);
                }
                matrices[2] = matrices[0] * matrices[1];
                for (auto& matrix : matrices)
                    for (auto& value : matrix.entries)
                        files.output_shares(value);
            }
        }
}

template<class T>
void FakeParams::make_minimal(const KeySetup<T>& key, int nplayers, int nitems,
        bool zero, PRNG& G)
{
    make_mult_triples<T>(key, nplayers, nitems, zero, prep_data_prefix, G);
    make_bits<T>(key, nplayers, nitems, zero, G);
    make_inputs<T>(key, nplayers, nitems, T::type_short(), zero, G);
}

template<class T>
void FakeParams::make_basic(const KeySetup<T>& key, int nplayers,
        int nitems, bool zero, PRNG& G, const KeySetup<typename T::bit_type::part_type>& bit_key)
{
    make_minimal<T>(key, nplayers, nitems, zero, G);
    make_square_tuples<T>(key, nplayers, nitems, T::type_short(), zero, G);
    make_dabits<T>(key, nplayers, nitems, zero, G, bit_key);
    make_edabits<T>(key, nplayers, G, T::clear::characteristic_two,
        bit_key);
    if (not T::clear::characteristic_two)
        make_matrix_triples(key, G);
    if (T::clear::invertible)
    {
        make_inverse<T>(key, nplayers, nitems, zero, prep_data_prefix, G);
        if (opt.isSet("-s"))
        {
            make_PreMulC<T>(key, nplayers, nitems, zero, G);
            make_Sbox<T>(key, nplayers, nitems, zero, G);
        }
    }
}

template<class T>
void FakeParams::make_with_mac_key(int nplayers, int default_num, bool zero, PRNG& G,
        const KeySetup<typename T::bit_type::part_type>& bit_keys)
{
    KeySetup<T> keys;
    generate_mac_keys<T>(keys, nplayers, prep_data_prefix, G);
    make_basic<T>(keys, nplayers, default_num, zero, G, bit_keys);
}

template<class T>
int generate(ez::ezOptionParser& opt);

int main(int argc, const char** argv)
{
  insecure_fake();
  bigint::init_thread();

  FakeParams params;
  auto& opt = params.opt;

  opt.syntax = "./Fake-Offline.x <nplayers> [OPTIONS]\n\nOptions with 2 arguments take the form '-X <#gf2n tuples>,<#modp tuples>'";
  opt.example = "./Fake-Offline.x 2 -lgp 128 -lg2 128 --default 10000\n./Fake-Offline.x 3 -trip 50000,10000 -btrip 100000\n";

  opt.add(
        "128", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Bit length of GF(p) field (default: 128) and Z_2^k rings (default: 64)", // Help description.
        "-lgp", // Flag token.
        "--lgp" // Flag token.
  );
  opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Prime for GF(p) field (default: generated from -lgp argument)", // Help description.
          "-P", // Flag token.
          "--prime" // Flag token.
  );
  opt.add(
        to_string(gf2n::default_degree()).c_str(), // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        ("Bit length of GF(2^n) field (default: " + to_string(gf2n::default_degree()) + ")").c_str(), // Help description.
        "-lg2", // Flag token.
        "--lg2" // Flag token.
  );
  opt.add(
        "1000", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Default number of tuples to generate for ALL data types (default: 1000)", // Help description.
        "-d", // Flag token.
        "--default" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        2, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "Number of triples, for gf2n / modp types", // Help description.
        "-trip", // Flag token.
        "--ntriples" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        2, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "Number of random bits, for gf2n / modp types", // Help description.
        "-bit", // Flag token.
        "--nbits" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        2, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "Number of input tuples, for gf2n / modp types", // Help description.
        "-inp", // Flag token.
        "--ninputs" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        2, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "Number of square tuples, for gf2n / modp types", // Help description.
        "-sq", // Flag token.
        "--nsquares" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Number of inverse tuples (modp only)", // Help description.
        "-inv", // Flag token.
        "--ninverses" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Number of GF(2) triples", // Help description.
        "-btrip", // Flag token.
        "--nbittriples" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Number of GF(2) x GF(2^n) triples", // Help description.
        "-mixed", // Flag token.
        "--nbitgf2ntriples" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Number of edaBits", // Help description.
        "-eda", // Flag token.
        "--nedabits" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        0, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Set all values to zero, but not the shares", // Help description.
        "-z", // Flag token.
        "--zero" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Generate for SPDZ2k with parameter k (bit length)", // Help description.
        "-Z", // Flag token.
        "--spdz2k" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        ("SPDZ2k security parameter (default: "
          + to_string(SPDZ2K_DEFAULT_SECURITY) + ")").c_str(), // Help description.
        "-S", // Flag token.
        "--security" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        -1, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "edaBit lengths (separate by comma)", // Help description.
        "-e", // Flag token.
        "--edabits" // Flag token.
  );
  opt.add(
        "", // Default.
        0, // Required?
        0, // Number of args expected.
        ',', // Delimiter if expecting multiple args.
        "Special preprocessing", // Help description.
        "-s", // Flag token.
        "--special" // Flag token.
  );
  opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Number of corrupted parties for Shamir secret sharing "
          "(default: just below half)", // Help description.
          "-T", // Flag token.
          "--threshold" // Flag token.
  );
  opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Deactivate Montgomery representation"
          "(default: activated)", // Help description.
          "-n", // Flag token.
          "--nontgomery" // Flag token.
  );
  opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Seed to use for initializing pseudorandom number generator"
          "(default: seed from /dev/random)", // Help description.
          "-seed", // Flag token.
          "--prngseed" // Flag token.
  );
  opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Compiled program to use for preprocessing requirements",
          // Help description.
          "-p", // Flag token.
          "--program" // Flag token.
  );
  opt.parse(argc, argv);

  int lgp;
  opt.get("--lgp")->getInt(lgp);

  if (opt.isSet("-Z"))
    {
      int k, s;
      opt.get("-Z")->getInt(k);
      s = SPDZ2K_DEFAULT_SECURITY;
      if (opt.isSet("-S"))
        opt.get("-S")->getInt(s);
#define X(K, S) if (k == K and s == S) \
	  return params.generate<Spdz2kShare<K, S>>();
#ifdef RING_SIZE
      X(RING_SIZE, SPDZ2K_DEFAULT_SECURITY)
#endif
      X(32, 32) X(64, 64) X(64, 48)
#undef X

      cerr << "Not compiled for " << k << "-bit rings with " << s
          << "-bit security." << endl << "Add 'X(" << k << "," << s
          << ")' to line " << (__LINE__ - 4) << " in " << __FILE__ << endl;
      exit(1);
    }
  else
      params.generate<Share<gfpvar>>();
}

template<class T>
int FakeParams::generate()
{
  vector<string> badOptions;
  string usage;
  unsigned int i;
  if(!opt.gotRequired(badOptions))
  {
    for (i=0; i < badOptions.size(); ++i)
      cerr << "ERROR: Missing required option " << badOptions[i] << ".";
    opt.getUsage(usage);
    cout << usage;
    return 1;
  }

  if(!opt.gotExpected(badOptions))
  {
    for(i=0; i < badOptions.size(); ++i)
      cerr << "ERROR: Got unexpected number of arguments for option " << badOptions[i] << ".";
    opt.getUsage(usage);
    cout << usage;
    return 1;
  }

  if (opt.firstArgs.size() == 2)
  {
    nplayers = atoi(opt.firstArgs[1]->c_str());
  }
  else if (opt.lastArgs.size() == 1)
  {
    nplayers = atoi(opt.lastArgs[0]->c_str());
  }
  else
  {
    cerr << "ERROR: invalid number of arguments\n";
    opt.getUsage(usage);
    cout << usage;
    return 1;
  }

  if (nplayers > 2)
  {
    ShamirOptions::singleton.nparties = nplayers;
    ShamirOptions::singleton.set_threshold(opt);
  }

  if (opt.isSet("--program"))
  {
    Program program(nplayers);
    string name;
    opt.get("--program") -> getString(name);
    BaseMachine machine;
    program.parse_with_error("Programs/Bytecode/" + name + "-0.bc");
    this->usage = program.get_offline_data_used();
  }

  int ntrip2=0, ntripp=0, nbits2=0,nbitsp=0,nsqr2=0,nsqrp=0,ninp2=0,ninpp=0,ninv=0;
  vector<int> list_options;
  int lg2, lgp;

  opt.get("--lgp")->getInt(lgp);
  opt.get("--lg2")->getInt(lg2);

  opt.get("--default")->getInt(default_num);
  ntrip2 = ntripp = nbits2 = nbitsp = nsqr2 = nsqrp = ninp2 = ninpp = ninv =
      n_edabits = default_num;
  
  if (opt.isSet("--ntriples"))
  {
    opt.get("--ntriples")->getInts(list_options);
    ntrip2 = list_options[0];
    ntripp = list_options[1];
  }
  if (opt.isSet("--nbits"))
  {
    opt.get("--nbits")->getInts(list_options);
    nbits2 = list_options[0];
    nbitsp = list_options[1];
  }
  if (opt.isSet("--ninputs"))
  {
    opt.get("--ninputs")->getInts(list_options);
    ninp2 = list_options[0];
    ninpp = list_options[1];
  }
  if (opt.isSet("--nsquares"))
  {
    opt.get("--nsquares")->getInts(list_options);
    nsqr2 = list_options[0];
    nsqrp = list_options[1];
  }
  if (opt.isSet("--ninverses"))
    opt.get("--ninverses")->getInt(ninv);
  if (opt.isSet("--nedabits"))
    opt.get("--nedabits")->getInt(n_edabits);

  zero = opt.isSet("--zero");
  if (zero)
      cout << "Set all values to zero" << endl;

  // check compatibility
  gf2n::init_field(lg2);

  // Initialize PRNG
  PRNG G;
  if (opt.isSet("--prngseed")) {
    std::string seed;
    opt.get("--prngseed")->getString(seed);
    if (seed.length() != SEED_SIZE) {
      cerr << "ERROR: invalid seed length. Must be " << SEED_SIZE << " bytes";
      opt.getUsage(usage);
      cout << usage;
      return 1;
    }
    unsigned char *val = new unsigned char[seed.length()+1];
    strcpy((char *)val, seed.c_str());
    G.SetSeed(val);
    delete [] val;
  } else {
    G.ReSeed();
  }

  prep_data_prefix = PREP_DIR;
  // Set up the fields
  if (opt.isSet("--prime"))
  {
    string p;
    opt.get("--prime")->getString(p);
    T::clear::init_field(p, not opt.isSet("--nontgomery"));
  }
  else
  {
    T::clear::init_default(lgp, not opt.isSet("--nontgomery"));
  }

  T::clear::template write_setup<T>(nplayers);

  /* Find number players and MAC keys etc*/
  typedef Share<gf2n> sgf2n;
  KeySetup<T> keyp;
  KeySetup<sgf2n> key2;

  // create PREP_DIR if not there
  if (mkdir_p(PREP_DIR) == -1)
  {
    cerr << "mkdir_p(" PREP_DIR ") failed\n";
    throw file_error(PREP_DIR);
  }

  generate_mac_keys<T>(keyp, nplayers, prep_data_prefix, G);
  generate_mac_keys<sgf2n>(key2, nplayers, prep_data_prefix, G);

  make_mult_triples<sgf2n>(key2,nplayers,ntrip2,zero,prep_data_prefix,G);
  make_mult_triples<T>(keyp,nplayers,ntripp,zero,prep_data_prefix,G);
  make_bits<Share<gf2n>>(key2,nplayers,nbits2,zero,G);
  make_bits<T>(keyp,nplayers,nbitsp,zero,G);
  make_square_tuples<sgf2n>(key2,nplayers,nsqr2,"2",zero,G);
  make_square_tuples<T>(keyp,nplayers,nsqrp,"p",zero,G);
  make_inputs<sgf2n>(key2,nplayers,ninp2,"2",zero,G);
  make_inputs<T>(keyp,nplayers,ninpp,"p",zero,G);
  make_inverse<sgf2n>(key2,nplayers,ninv,zero,prep_data_prefix,G);
  if (T::clear::invertible)
    make_inverse<T>(keyp,nplayers,ninv,zero,prep_data_prefix,G);
  make_matrix_triples<T>(keyp, G);

  if (opt.isSet("-s"))
  {
    make_PreMulC<sgf2n>(key2,nplayers,ninv,zero,G);
    if (T::clear::invertible)
      make_PreMulC<T>(keyp,nplayers,ninv,zero,G);
    make_Sbox<sgf2n>(key2,nplayers,ninv,zero,G);
  }

  // replicated secret sharing only for three parties
  if (nplayers == 3)
  {
    make_mult_triples<GC::MaliciousRepSecret>({}, nplayers, ntrip2, zero, prep_data_prefix, G);
    make_bits<GC::MaliciousRepSecret>({}, nplayers, nbits2, zero, G);
  }
  else if (nplayers == 4)
    make_basic<Rep4Share2<64>>({}, nplayers, default_num, zero, G);

  make_minimal<GC::DealerSecret>({}, nplayers, default_num, zero, G);

  make_mult_triples<GC::SemiSecret>({}, nplayers, default_num, zero, prep_data_prefix, G);
  make_bits<GC::SemiSecret>({}, nplayers, default_num, zero, G);

  gf2n_short::reset();
  gf2n_short::init_field();

  KeySetup<GC::TinySecret<DEFAULT_SECURITY>> keyt;
  generate_mac_keys<GC::TinySecret<DEFAULT_SECURITY>>(keyt, nplayers,
      prep_data_prefix, G);

  make_minimal<GC::TinySecret<DEFAULT_SECURITY>>(keyt, nplayers,
      default_num / 64, zero, G);

  KeySetup<typename T::bit_type::part_type> keytt;
  generate_mac_keys<typename T::bit_type::part_type>(keytt, nplayers, prep_data_prefix, G);
  make_minimal<typename T::bit_type::part_type>(keytt, nplayers, default_num, zero, G);

  make_dabits<T>(keyp, nplayers, default_num, zero, G, keytt);
  make_edabits<T>(keyp, nplayers, G, false_type(), keytt);

  if (T::clear::prime_field)
    {
      int n_macs = DIV_CEIL(DEFAULT_SECURITY, T::clear::length() - 1);
      n_macs = 1 << int(ceil(log2(n_macs)));
      if (n_macs > 4)
          n_macs = 10;

#define X(N) if (N == n_macs) \
  make_with_mac_key<MamaShare<typename T::clear, N>>(nplayers, \
    default_num, zero, G, keytt);

      X(1) X(2) X(4) X(10)
#undef X
    }

  if (nplayers > 2)
    {
      make_mult_triples<GC::MaliciousCcdShare<gf2n_short>>({}, nplayers,
          default_num, zero, prep_data_prefix, G);
      make_bits<GC::MaliciousCcdShare<gf2n_short>>({}, nplayers,
          default_num, zero, G);
    }

  generate_field<typename T::clear>(T::clear::prime_field, G);
  generate_field<gf2n>(true_type(), G);
  if (gf2n::degree() != gf2n_short::degree())
    generate_field<gf2n_short>(true_type(), G);

  // default
  generate_ring<64>(G);

#if defined(RING_SIZE) and RING_SIZE != 64
  generate_ring<RING_SIZE>(G);
#endif

  // reuse lgp for simplified interface
  switch (lgp)
  {
  case 64:
    break;
#define X(L) case L: generate_ring<L>(G); break;
    X(128) X(192) X(256)
  default:
    cerr << "Not compiled for " << lgp << "-bit rings." << endl << "Add 'X("
        << lgp << "') to line " << (__LINE__ - 2) << " in " << __FILE__ << endl;
    exit(1);
  }

  return 0;
}

template<class U>
void FakeParams::generate_field(true_type, PRNG& G)
{
  if (nplayers == 3)
    {
      make_basic<Rep3Share<U>>({}, nplayers, default_num, zero, G);
      make_basic<MaliciousRep3Share<U>>({}, nplayers, default_num, zero, G);
      make_basic<PostSacriRepFieldShare<U>>({}, nplayers, default_num, zero, G);
      make_with_mac_key<SpdzWiseShare<MaliciousRep3Share<U>>>(nplayers, default_num, zero, G);
    }
  else if (nplayers == 4)
    make_basic<Rep4Share<U>>({}, nplayers, default_num, zero, G);

  make_basic<SemiShare<U>>({}, nplayers, default_num, zero, G);

  if (nplayers > 2)
    {
      ShamirShare<U>::bit_type::clear::init_field();
      make_basic<ShamirShare<U>>({}, nplayers, default_num, zero, G);
      make_basic<MaliciousShamirShare<U>>({}, nplayers, default_num, zero, G);
      make_with_mac_key<SpdzWiseShare<MaliciousShamirShare<U>>>(nplayers,
          default_num, zero, G);
      make_basic<DealerShare<U>>({}, nplayers, default_num, zero, G);
    }
}

template<int K>
inline void FakeParams::generate_ring(PRNG& G)
{
  if (nplayers == 3)
    {
      make_bits<Rep3Share2<K>>({}, nplayers, default_num, zero, G);
      make_basic<MalRepRingShare<K, DEFAULT_SECURITY>>({}, nplayers,
          default_num, zero, G);
      make_basic<BrainShare<K, DEFAULT_SECURITY>>({}, nplayers, default_num,
          zero, G);
      make_basic<PostSacriRepRingShare<K, DEFAULT_SECURITY>>({}, nplayers,
          default_num, zero, G);
      make_with_mac_key<SpdzWiseRingShare<K, DEFAULT_SECURITY>>(nplayers,
          default_num, zero, G);
    }
  else if (nplayers == 4)
    make_basic<Rep4Share2<K>>({}, nplayers, default_num, zero, G);

  make_basic<SemiShare<Z2<K>>>({}, nplayers, default_num, zero, G);

  if (nplayers > 2)
    make_basic<DealerShare<Z2<K>>>({}, nplayers, default_num, zero, G);
}
