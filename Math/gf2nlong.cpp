/*
 * gf2n_longlong.cpp
 *
 */

#include "gf2nlong.h"
#include "gf2n.h"

#include "Tools/intrinsics.h"
#include "Tools/Exceptions.h"

#include <stdint.h>


bool is_ge(__m128i a, __m128i b)
{
  word aa[2], bb[2];
  _mm_storeu_si128((__m128i*)aa, a);
  _mm_storeu_si128((__m128i*)bb, b);
//  cout << hex << "is_ge " << aa[1] << " " << bb[1] << " " << (aa[1] > bb[1]) << " ";
//  cout << aa[0] << " " << bb[0] << " " << (aa[0] >= bb[0]) << endl;
  return aa[1] == bb[1] ? aa[0] >= bb[0] : aa[1] > bb[1];
}


ostream& operator<<(ostream& s, const int128& a)
{
  word* tmp = (word*)&a.a;
  s << hex;
  s << noshowbase;
  s.width(16);
  s.fill('0');
  s << tmp[1];
  s.width(16);
  s << tmp[0] << dec;
  return s;
}

istream& operator>>(istream& s, int128& a)
{
  bigint tmp;
  s >> hex >> tmp;
  a = 0;
  auto size = tmp.get_mpz_t()->_mp_size;
  assert(size >= 0);
  assert(size <= 2);
  mpn_copyi((mp_limb_t*) &a.a, tmp.get_mpz_t()->_mp_d, size);
  s >> dec;
  return s;
}

void int128::pack(octetStream& os) const
{
  os.store(get_lower());
  os.store(get_upper());
}

void int128::unpack(octetStream& os)
{
  word lower = os.get<word>();
  *this = {os.get<word>(), lower};
}
