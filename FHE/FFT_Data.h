#ifndef _FFT_Data
#define _FFT_Data

#include "Math/modp.h"
#include "Math/Zp_Data.h"
#include "Math/gfpvar.h"
#include "Math/fixint.h"
#include "FHE/Ring.h"

/* Class for holding modular arithmetic data wrt the ring 
 *
 * It also holds the ring
 */


class FFT_Data
{
  Ring    R;
  Zp_Data prData;

  vector<modp> root;     // 2m'th Root of Unity mod pr and it's inverse
  vector<modp> roots;    // precomputed powers of root

  // When twop is equal to zero, m is a power of two
  // When twop is positive it is equal to 2^e where 2^e>2*m and 2^e divides p-1
  //    - In this case we can use FFTs over the base field
  int  twop;             

  // Stuff for arithmetic when 2^e > 2*m and 2^e divides p-1  (i.e. twop positive)
  vector<modp> two_root; // twop'th Root of Unity mod pr where twop = 2^e > 2*m
                         //   - And inverse
  vector< vector<modp> >  b; 

  // Stuff for arithmetic when m is a power of 2 (in which case twop=0)
  modp iphi;    // 1/phi_m mod pr
  vector< vector<modp> > powers,powers_i;

  void compute_roots(int n);

  public:
  typedef gfp T;
  typedef bigint S;
  typedef fixint<gfpvar::N_LIMBS> poly_type;

  void init(const Ring& Rg,const Zp_Data& PrD);

  void init_field() const { gfp::init_field(prData.pr); }

  void hash(octetStream& o) const;
  void pack(octetStream& o) const;
  void unpack(octetStream& o);

  FFT_Data();
  FFT_Data(const Ring& Rg,const Zp_Data& PrD)
    { init(Rg,PrD); }

  const Zp_Data& get_prD() const        { return prData; }
  const bigint&  get_prime() const      { return prData.pr; }

  int phi_m() const                     { return R.phi_m(); }
  int m()     const                     { return R.m();   }
  int num_slots() const                 { return R.phi_m(); }

  int p(int i)      const        { return R.p(i);     }
  int p_inv(int i)  const        { return R.p_inv(i); }
  const vector<int>& Phi() const { return R.Phi();    }

  int get_twop() const           { return twop;       }
  modp get_root(int i) const     { return root[i];    }
  modp get_iphi() const          { return iphi;       }
  const vector<modp>& get_roots() const { return roots; }

  const Ring& get_R() const      { return R; }

  void write_setup(const string& dir) const { prData.write_setup(dir); }

  bool operator==(const FFT_Data& other) const { return not (*this != other); }
  bool operator!=(const FFT_Data& other) const;

  friend void BFFT(vector<modp>& ans,const vector<modp>& a,const FFT_Data& FFTD,bool forward);
};

#endif

