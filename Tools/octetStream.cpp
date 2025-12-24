
#include <fcntl.h>
#include <sodium.h>

#include "octetStream.h"
#include <string.h>
#include "Networking/sockets.h"
#include "Networking/ssl_sockets.h"
#include "Tools/Exceptions.h"
#include "Networking/data.h"
#include "Networking/Player.h"
#include "Networking/Exchanger.h"
#include "Math/bigint.h"
#include "Tools/time-func.h"
#include "Tools/FlexBuffer.h"


void octetStream::reset()
{
    data = 0;
    data_end = 0;
    ptr = 0;
    end = 0;
}

void octetStream::clear()
{
    if (data)
        delete[] data;
    reset();
}

void octetStream::assign(const octetStream& os)
{
  auto read = os.get_ptr();
  if (os.get_length() >= get_max_length())
    {
      if (data)
        delete[] data;
      data=new octet[os.get_max_length()];
      set_max_length(os.get_max_length());
    }
  set_length(os.get_length());
  memcpy(data,os.data,get_length()*sizeof(octet));
  ptr = data + read;
  bits = os.bits;
}


octetStream::octetStream(size_t maxlen)
{
  data=new octet[maxlen];
  ptr=data;
  set_length(0);
  set_max_length(maxlen);
}

octetStream::octetStream(size_t len, const octet* source) :
    octetStream(len)
{
  append(source, len);
}

octetStream::octetStream(const string& other) :
    octetStream(other.size(), (const octet*)other.data())
{
}

octetStream::octetStream(const octetStream& os)
{
  data=new octet[os.get_max_length()];
  set_length(os.get_length());
  set_max_length(os.get_max_length());
  memcpy(data,os.data,get_length()*sizeof(octet));
  ptr = data + os.get_ptr();
  bits = os.bits;
}

octetStream::octetStream(FlexBuffer& buffer)
{
  data = (octet*)buffer.data();
  set_length(buffer.size());
  set_max_length(buffer.capacity());
  ptr = (octet*)buffer.ptr;
  buffer.reset();
}


string octetStream::str() const
{
  return string((char*) get_data(), get_length());
}


void octetStream::hash(octetStream& output) const
{
  output.resize(crypto_generichash_BYTES_MIN);
  crypto_generichash(output.data, crypto_generichash_BYTES_MIN, data,
      get_length(), NULL, 0);
  output.set_length(crypto_generichash_BYTES_MIN);
}


octetStream octetStream::hash() const
{
  octetStream h(crypto_generichash_BYTES_MIN);
  hash(h);
  return h;
}


bigint octetStream::check_sum(int req_bytes) const
{
  auto hash = new unsigned char[req_bytes];
  crypto_generichash(hash, req_bytes, data, get_length(), NULL, 0);

  bigint ans;
  bigintFromBytes(ans,hash,req_bytes);
  // cout << ans << "\n";
  delete[] hash;
  return ans;
}


bool octetStream::equals(const octetStream& a) const
{
  if (get_length()!=a.get_length()) { return false; }
  return memcmp(data, a.data, get_length()) == 0;
}


void octetStream::flush_bits()
{
  bits[0].n = 0;
  store_int<1>(bits[0].buffer);
  bits[0].buffer = 0;
}


void octetStream::append_random(size_t num)
{
  randombytes_buf(append(num), num);
}


void octetStream::concat(const octetStream& os)
{
  memcpy(append(os.get_length()), os.data, os.get_length()*sizeof(octet));
}


void octetStream::store_bytes(octet* x, const size_t l)
{
  encode_length(append(4), l, 4);
  memcpy(append(l), x, l*sizeof(octet));
}

void octetStream::get_bytes(octet* ans, size_t& length)
{
  auto rec_length = get_int(4);
  if (rec_length != length)
    throw runtime_error("unexpected length");
  memcpy(ans, consume(length), length * sizeof(octet));
}

void octetStream::store(int l)
{
  encode_length(append(4), l, 4);
}


void octetStream::get(int& l)
{
  l = get_int(4);
}


void octetStream::store(const bigint& x, long num)
{
  *append(1) = x < 0;

  if (num <= 0)
    {
      num = numBytes(x);
      encode_length(append(4), num, 4);
    }

  bytesFromBigint(append(num), x, num);
}


void octetStream::get(bigint& ans, long length)
{
  int sign = *consume(1);
  if (sign!=0 && sign!=1) { throw bad_value(); }

  if (length <= 0)
    length = get_int(4);

  if (length!=0)
    {
      bigintFromBytes(ans, consume(length), length);
      if (sign)
        mpz_neg(ans.get_mpz_t(), ans.get_mpz_t());
    }
  else
    ans=0;
}


void octetStream::store(const string& str)
{
  store(str.length());
  append((const octet*) str.data(), str.length());
}


void octetStream::get(string& str)
{
  size_t size;
  get(size);
  str.assign((const char*) consume(size), size);
}


template<class T>
void octetStream::exchange(T send_socket, T receive_socket, octetStream& receive_stream) const
{
  Exchanger<T> exchanger(send_socket, *this, receive_socket, receive_stream);
  while (exchanger.round())
    ;
}



void octetStream::input(const string& filename)
{
  ifstream s(filename);
  if (not s.good())
    throw file_error("cannot read from " + filename);
  input(s);
}

void octetStream::input(istream& s)
{
  size_t size;
  s.read((char*)&size, sizeof(size));
  if (not s.good())
    throw IO_Error("not enough data");
  resize_min(size);
  s.read((char*)data, size);
  set_length(size);
  if (not s.good())
    throw IO_Error("not enough data");
  reset_read_head();
}

void octetStream::output(ostream& s) const
{
  auto len = get_length();
  s.write((char*)&len, sizeof(len));
  s.write((char*)data, len);
}

ostream& operator<<(ostream& s,const octetStream& o)
{
  for (size_t i=0; i<o.get_length(); i++)
    { int t0=o.data[i]&15;
      int t1=o.data[i]>>4;
      s << hex << t1 << t0 << dec;
    }
  return s;
}

octetStreams::octetStreams(const Player& P)
{
  reset(P);
}

void octetStreams::reset(const Player& P)
{
  resize(P.num_players());
  for (auto& o : *this)
    o.reset_write_head();
}

template void octetStream::exchange(int, int, octetStream&) const;
template void octetStream::exchange(ssl_socket*, ssl_socket*, octetStream&) const;
