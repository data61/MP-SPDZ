
#include "FHE/P2Data.h"
#include "Math/Setup.h"
#include "Math/fixint.h"
#include "Processor/OnlineOptions.h"
#include "Tools/CodeLocations.h"
#include <fstream>


void P2Data::forward(vector<poly_type>& ans,const vector<gf2n_short>& a) const
{
  CODE_LOCATION_NO_SCOPE

  int n=gf2n_short::degree();
  
  BitVector bv(A.size());
  ans.resize(A.size());
  for (int i=0; i<slots; i++)
    { word rep=a[i].get();
      for (int j=0; j<n && rep!=0; j++)
        { if ((rep&1)==1)
	     { int jj=i*n+j;
	       bv.add(A[jj]);
             }
          rep>>=1;
        }
    }
  for (size_t i = 0; i < bv.size(); i++)
    ans[i] = bv.get_bit(i);
}


void P2Data::backward(vector<gf2n_short>& ans,const vector<poly_type>& a) const
{
  CODE_LOCATION_NO_SCOPE

  int n=gf2n_short::degree();
  BitVector bv(a.size());
  for (size_t i = 0; i < a.size(); i++)
    bv.set_bit(i, a[i].get_limb(0));
  
  ans.resize(slots);
  word y;
  for (int i=0; i<slots; i++)
    { y=0;
      for (int j=0; j<n; j++)
        { y<<=1;
          int ii = i * n + n - 1 - j;
          y ^= (Ai[ii] & bv).parity();
        }
      ans[i] = (y);
    }
}


void P2Data::check_dimensions() const
{
//  cout << "degree: " << gf2n_short::degree() << endl;
//  cout << "slots: " << slots << endl;
//  cout << "A: " << A.size() << "x" << A[0].size() << endl;
//  cout << "Ai: " << Ai.size() << "x" << Ai[0].size() << endl;
  if (A.size() != Ai.size())
    throw runtime_error("forward and backward mapping dimensions mismatch");
  if (A.size() != A.at(0).size())
    throw runtime_error("forward mapping not square");
  if (Ai.size() != Ai.at(0).size())
    throw runtime_error("backward mapping not square");
  if ((int)A.at(0).size() != slots * gf2n_short::degree())
        throw runtime_error(
                "mapping dimension incorrect: " + to_string(A.at(0).size())
                        + " != " + to_string(slots) + " * "
                        + to_string(gf2n_short::degree()));
}


bool P2Data::operator!=(const P2Data& other) const
{
  return slots != other.slots or A != other.A or Ai != other.Ai;
}

void P2Data::hash(octetStream& o) const
{
  o.store(gf2n_short::degree());
  o.store(slots);
  A.hash(o);
  Ai.hash(o);
}

void P2Data::pack(octetStream& o) const
{
  check_dimensions();
  o.store(gf2n_short::degree());
  o.store(slots);
  A.pack(o);
  Ai.pack(o);
  o.store_int(0xdeadbeef1, 8);
}

void P2Data::unpack(octetStream& o)
{
  int degree;
  o.get(degree);
  gf2n_short::init_field(degree);
  o.get(slots);
  A.unpack(o);
  Ai.unpack(o);
  if (o.get_int(8) != 0xdeadbeef1)
    throw runtime_error("P2Data serialization incorrect");
  check_dimensions();
}

string get_filename(const Ring& Rg)
{
  return (string) PREP_DIR + "P2D-" + to_string(gf2n_short::degree()) + "x"
      + to_string(Rg.phi_m() / gf2n_short::degree());
}

void P2Data::load(const Ring& Rg)
{
  string filename = get_filename(Rg);
  if (OnlineOptions::singleton.verbose)
    cerr << "Loading from " << filename << endl;
  octetStream os;
  os.input(filename);
  unpack(os);
}

void P2Data::store(const Ring& Rg) const
{
  string filename = get_filename(Rg);
  if (OnlineOptions::singleton.verbose)
    cerr << "Storing in " << filename << endl;
  ofstream s(filename);
  octetStream os;
  pack(os);
  os.output(s);
}
