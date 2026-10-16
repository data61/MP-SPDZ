
#include "BitVector.h"
#include "Tools/random.h"
#include "Tools/octetStream.h"
#include "Math/gf2n.h"
#include "Math/gfp.h"
#include "Math/Z2k.h"

#include <fstream>
#include <assert.h>

void BitVector::assign(const BitVectorView& K)
{
    if (nbits != K.nbits)
    {
        resize(K.nbits);
    }
    memmove(bytes, K.bytes, nbytes);
}

void BitVector::resize_zero(size_t new_nbits)
{
    size_t old_nbytes = nbytes;
    resize(new_nbits);
    if (old_nbytes < nbytes)
        avx_memzero(bytes + old_nbytes, nbytes - old_nbytes);
}

const void* BitVector::get_ptr_to_byte(size_t i, size_t block_size) const
{
    assert(i + block_size <= nbytes);
    return bytes + i * block_size;
}

const void* BitVector::get_ptr_to_bit(size_t i, size_t block_size) const
{
    assert((i * block_size) % 8 == 0);
    assert((i + 1) * block_size <= nbits);
    return bytes + block_size * i / 8;
}

BitVector BitVector::operator &(const BitVector& other) const
{
    assert(size() == other.size());
    BitVector res(size());
    for (size_t i = 0; i < size_bytes(); i++)
        res.bytes[i] = bytes[i] & other.bytes[i];
    return res;
}

bool BitVector::parity() const
{
#if (defined(__SSE4_2__) or not defined(__clang__)) and defined(__x86_64__)
    bool res = 0;
    for (size_t i = 0; i < size_bytes() / 8; i++)
        res ^= _popcnt64(((word*)bytes)[i]) & 1;
    for (size_t i = size_bytes() / 8 * 8; i < size_bytes(); i++)
        res ^= _popcnt32(bytes[i]) & 1;
    return res;
#else
    bool res = 0;
    for (size_t i = 0; i < size_bytes() / 8; i++)
    {
        word x = ((word*)bytes)[i];
        for (int i = 5; i >= 0; i--)
            x ^= (x >> (1 << i));
        res ^= (x & 1);
    }
    for (size_t i = size_bytes() / 8 * 8; i < size_bytes(); i++)
        res ^= (*this)[i];
    return res;
#endif
}

void BitVector::append(const BitVectorView& other, size_t length)
{
    if (long(length) < 0)
        length = other.size();
    assert(nbytes <= capacity);
    assert(nbits % 8 == 0);
    assert(length % 8 == 0);
    assert(length <= other.nbits);
    auto old_nbytes = nbytes;
    auto add_nbytes = length / 8;
    if (nbytes + add_nbytes > capacity)
        resize(2 * (nbits + length));
    nbytes = old_nbytes + add_nbytes;
    nbits = old_nbytes * 8 + length;
    assert(nbytes <= capacity);
    memcpy(bytes + old_nbytes, other.bytes, add_nbytes);
}

BitVectorView& BitVectorView::operator &=(const BitVectorView& other)
{
    assert(size() == other.size());
    size_t i = 0;
    for (; i + 31 < size_bytes(); i += 32)
    {
        auto j = i / 32;
        set_m256i(j, get_m256i(j) & other.get_m256i(j));
    }
    for (; i < size_bytes(); i++)
        bytes[i] &= other.bytes[i];
    return *this;
}

BitVector BitVector::operator~() const
{
    BitVector res(size());
    size_t i = 0;
    for (; i + 32 < size_bytes(); i += 32)
    {
        auto j = i / 32;
        res.set_m256i(j, ~get_m256i(j));
    }
    for (; i < size_bytes(); i++)
        res.bytes[i] = ~bytes[i];
    return res;
}

void BitVector::randomize(PRNG& G)
{
    G.get_octets(bytes, nbytes);
}

void BitVector::randomize_at(size_t a, size_t nb, PRNG& G)
{
    if (nb < 1)
        throw invalid_length();
    G.get_octets(bytes + a, nb);
}

/*
 */

void BitVector::output(ostream& s,bool human) const
{
    if (human)
    {
        s << nbits << " " << hex;
        for (unsigned int i = 0; i < nbytes; i++)
        {
            s << int(bytes[i]) << " ";
        }
        s << dec << endl;
    }
    else
    {
        int len = nbits;
        s.write((char*) &len, sizeof(int));
        s.write((char*) bytes, nbytes);
    }
}


void BitVector::input(istream& s,bool human)
{
    if (s.peek() == EOF)
    {
        if (s.tellg() == 0)
        {
            cout << "IO problem. Empty file?" << endl;
            throw file_error("BitVector input");
        }
      throw end_of_file();
    }
    int len;
    if (human)
    {
        s >> len >> hex;
        resize(len);
        for (size_t i = 0; i < nbytes; i++)
        {
            s >> bytes[i];
        }
        s >> dec;
    }
    else
    {
        s.read((char*) &len, sizeof(int));
        resize(len);
        s.read((char*) bytes, nbytes);
    }
}


void BitVectorView::pack(octetStream& o) const
{
    o.store_int(nbits, 8);
    o.append((octet*)bytes, nbytes);
}

void BitVector::unpack(octetStream& o)
{
    resize(o.get_int(8));
    o.consume((octet*)bytes, nbytes);
}

BitVector::BitVector(const vector<Bit>& other) : BitVector(other.size())
{
    auto x = other.begin();
    for (size_t i = 0; i < size(); i += 8)
    {
        char tmp = 0;
        for (int j = 0; j < 8; j++)
        {
            tmp ^= *x++ << j;
        }
        bytes[i / 8] = tmp;
    }
}

BitVector& BitVector::operator =(const octetStream other)
{
    resize(other.get_length() * 8);
    memcpy(bytes, other.get_data(), nbytes);
    return *this;
}

ostream& operator <<(ostream& o, const BitVectorView& x)
{
    for (size_t i = 0; i < x.size(); i++)
        o << int(x.get_bit(i));
    return o;
}
