#ifndef _P2Data
#define _P2Data

/* This class defines all the data needed for representing
 * plaintexts modulo 2
 */

#include "FHE/Ring.h"
#include "FHE/Matrix.h"
#include "Math/gf2n.h"

class P2Data
{
  int slots;
  // Data for the forward mapping  ((slots*gf2n:deg) by phi_m)
  imatrix A;
  // Data for the backward mapping (phi_m by phi_m)
  imatrix Ai;

  public:
  typedef gf2n_short T;
  typedef int S;
  typedef fixint<0> poly_type;

  int num_slots() const { return slots; }
  int degree() const { return A.size() ? A.size() : 0; }
  int phi_m() const { return A[0].size(); }

  void check_dimensions() const;

  void forward(vector<poly_type>& ans,const vector<gf2n_short>& a) const;
  void backward(vector<gf2n_short>& ans,const vector<poly_type>& a) const;

  int get_prime() const { return 2; }
  void write_setup(const string&) const {}

  bool operator!=(const P2Data& other) const;

  // no op because we require field to be initalized first
  void init_field() const {}

  void hash(octetStream& o) const;
  void pack(octetStream& o) const;
  void unpack(octetStream& o);

  void load(const Ring& Rg);
  void store(const Ring& Rg) const;

  void load_or_generate(const Ring& Rg);


  friend void init(P2Data& P2D,const Ring& Rg);
};

#endif

