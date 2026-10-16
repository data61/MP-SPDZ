#ifndef _BITVECTOR
#define _BITVECTOR

/* Vector of bits */

#include <iostream>
#include <vector>
using namespace std;
#include <stdlib.h>
#include <assert.h>

#include "Tools/Exceptions.h"
#include "Networking/data.h"
// just for util functions
#include "Math/gf2nlong.h"
#include "Math/FixedVec.h"
#include "Math/Bit.h"
#include "Tools/intrinsics.h"

class PRNG;
class octetStream;

template <int K>
class Z2;
template <class U, class V>
class Rectangle;

class BitVectorView
{
    friend class BitVector;

protected:
    octet* bytes;

    size_t nbytes;
    size_t nbits;

public:
    BitVectorView(octet* bytes = 0, size_t size = 0) :
            bytes(bytes), nbytes(DIV_CEIL(size, 8)), nbits(size)
    {
    }

    size_t size() const { return nbits; }
    size_t size_bytes() const { return nbytes; }

    template<class T>
    size_t size_chunks() const
    {
        unsigned chunk_size = sizeof(T);
        assert(nbytes % chunk_size == 0);
        return nbytes / chunk_size;
    }

    void assign_zero()
    {
        memset(bytes, 0, nbytes);
    }

    void assign(const BitVectorView& other)
    {
        assert(size() == other.size());
        memmove(bytes, other.bytes, nbytes);
    }

    octet get_byte(size_t i) const
    {
#ifdef CHECK_SIZE
        assert(size_t(i) < nbytes);
#endif
        return bytes[i];
    }

    bool get_bit(size_t i) const
      {
#ifdef CHECK_SIZE
        if (i >= (size_t)nbits)
          throw out_of_range("BitVector access: " + to_string(i) + "/" + to_string(nbits));
#endif
        return (bytes[i/8] >> (i % 8)) & 1;
      }

    bool operator[](size_t i) const { return get_bit(i); }

    int128 get_int128(size_t i) const { return _mm_loadu_si128((__m128i*)bytes + i); }
    void set_int128(size_t i, int128 a) { *((__m128i*)bytes + i) = a.a; }

    __m256i get_m256i(size_t i) const { return _mm256_loadu_si256((__m256i*)bytes + i); }
    void set_m256i(size_t i, __m256i a) { _mm256_storeu_si256((__m256i*)bytes + i, a); }

    void add(const BitVectorView& A)
    {
        if (nbits != A.nbits)
          { throw invalid_length(); }
        size_t nwords = nbytes / 8;
        for (size_t i = 0; i < nwords; i++)
            ((word*)bytes)[i] ^= ((word*)A.bytes)[i];
        for (size_t i = nwords * 8; i < nbytes; i++)
        {
            bytes[i] ^= A.bytes[i];
        }
    }

    BitVector operator^(const BitVectorView& other) const;

    BitVectorView& operator^=(const BitVectorView& other)
    {
        add(other);
        return *this;
    }

    BitVectorView& operator&=(const BitVectorView& other);

    BitVectorView part(size_t begin, size_t size) const;

    array<Bit, 8> eight_from(size_t i) const
    {
#ifdef CHECK_SIZE
        assert(i < nbits);
#endif
        auto tmp = get_byte(i / 8);
        array<Bit, 8> res;
        for (int j = 0; j < 8; j++)
            res[j] = (tmp >> j) & 1;
        return res;
    }

    void increment()
    {
        bytes += nbytes;
    }

    // Pack and unpack in native format
    //   i.e. Dont care about conversion to human readable form
    void pack(octetStream& o) const;
};

class BitVector : public BitVectorView
{
    size_t capacity;

    public:

    void assign(const BitVectorView& K);
    void assign_bytes(char* new_bytes, size_t len)
    {
        resize(len*8);
        memcpy(bytes, new_bytes, len);
    }
    // only grows, never destroys
    void resize(size_t new_nbits)
    {
    if (nbits != new_nbits)
        {
            size_t new_nbytes = DIV_CEIL(new_nbits,8);

            if (new_nbytes > capacity)
                resize_exact(new_nbits);

            nbits = new_nbits;
            nbytes = new_nbytes;
            /*
            // use realloc to preserve original contents
            if (new_nbits < nbits)
            {
                memcpy(tmp, bytes, new_nbytes);
            }
            else
            {
                memset(tmp, 0, new_nbytes);
                memcpy(tmp, bytes, nbytes);   
            }*/

            // realloc may fail on size 0
            /*if (new_nbits == 0)
            {
                free(bytes);
                bytes = (octet*) malloc(0);//new octet[0];
                //free(bytes);
                return;
            }
            bytes = (octet*)realloc(bytes, nbytes);
            if (bytes == NULL)
            {
                cerr << "realloc failed\n";
                exit(1);
            }*/
            /*delete[] bytes;
            nbits = new_nbits;
            nbytes = DIV_CEIL(nbits, 8);
            bytes = new octet[nbytes];*/
        }
    }

    void resize_exact(size_t new_nbits)
    {
        size_t new_nbytes = DIV_CEIL(new_nbits, 8);
#ifdef VERBOSE_BITVECTOR_RESIZE
        if (new_nbytes > 1000)
            fprintf(stderr, "resizing bit vector to use %zu bytes\n", new_nbytes);
#endif
        octet* tmp = new octet[new_nbytes];
        memcpy(tmp, bytes, min(new_nbytes, nbytes));
        delete[] bytes;
        bytes = tmp;
        capacity = new_nbytes;
        nbits = new_nbits;
        nbytes = new_nbytes;
    }

    void resize_zero(size_t new_nbits);

    octet* get_ptr() { return bytes; }
    const octet* get_ptr() const { return bytes; }
    const void* get_ptr_to_byte(size_t i, size_t block_size) const;
    const void* get_ptr_to_bit(size_t i, size_t block_size) const;

    BitVector(size_t n=0)
    {
        nbits = n;
        nbytes = DIV_CEIL(nbits, 8);
        capacity = nbytes;
        bytes = new octet[nbytes];
        assign_zero();
    }
    BitVector(const BitVector& K) : BitVectorView()
    {
        bytes = new octet[K.nbytes];
        nbytes = K.nbytes;
        capacity = K.nbytes;
        nbits = K.nbits;
        assign(K);
    }
    BitVector(const BitVectorView& K) : BitVector()
    {
        assign(K);
    }
    BitVector(const void* other, size_t bitsize) : BitVector()
    {
        resize(bitsize);
        avx_memcpy(bytes, other, nbytes);
    }
    BitVector(const vector<Bit>& other);
    ~BitVector() {
        //cout << "Destroy, size = " << nbytes << endl;
        delete[] bytes;
    }
    BitVector& operator=(const BitVector& K)
    {
        if (this!=&K) { assign(K); }
        return *this;
    }
    BitVector& operator=(const BitVectorView& K)
    {
        assign(K);
        return *this;
    }

    BitVector& operator=(const octetStream other);

    void swap(BitVector& other)
    {
        std::swap(nbits, other.nbits);
        std::swap(nbytes, other.nbytes);
        std::swap(bytes, other.bytes);
        std::swap(capacity, other.capacity);
    }

    class Access
    {
        BitVector& v;
        size_t i;

    public:
        Access(BitVector& v, size_t i) : v(v), i(i) {}
        bool get() const { return v.get_bit(i); }
        void operator=(bool b) { v.set_bit(i, b); }
        void operator=(Bit b) { *this = b.get(); }
        void operator=(const Access& other) { *this = other.get(); }
        void operator^=(const Access& other) { *this = get() ^ other.get(); }
        bool operator==(const Access& other) const { return get() == other.get(); }
        operator bool() const { return get(); }
    };

    bool operator[](size_t i) const { return get_bit(i); }
    Access operator[](size_t i) { return {*this, i}; }

    void set_byte(size_t i, octet b) { bytes[i] = b; }

    void set_int32(size_t i, int32_t w)
    {
        size_t offset = i * sizeof(int32_t);
        memcpy(bytes + offset, (octet*)&w, sizeof(int32_t));
    }

    // get the i-th 64-bit word
    word get_word(size_t i) const { return *(word*)(bytes + i*8); }

    void set_word(size_t i, word w)
    {
        size_t offset = i * sizeof(word);
        memcpy(bytes + offset, (octet*)&w, sizeof(word));
    }

    template <class T>
    T get_portion(size_t i) const;
    template <class T>
    void set_portion(size_t i, const T& a);

    template <class T>
    void set(const T& a);
    template <class T, int L>
    void set(const FixedVec<T, L>& a);
    void set_bit(size_t i,unsigned int a)
    {
        if ((size_t)i >= nbits)
            throw overflow("BitVector", i, nbits);
        size_t j = i/8, k = i&7;
        if (a==1)
          { bytes[j] |= (octet)(1UL<<k); }
        else
  	     { bytes[j] &= (octet)~(1UL<<k); }
    }

    void add(const BitVectorView& A, const BitVectorView& B)
    {
        if (A.nbits != B.nbits)
          { throw invalid_length(); }
        resize(A.nbits);
        for (size_t i=0; i < nbytes; i++)
  	    {
            bytes[i] = A.bytes[i] ^ B.bytes[i];
        }
    }

    BitVector operator^(const BitVector& other) const
    {
        BitVector res(size());
        res.add(*this, other);
        return res;
    }

    BitVector operator&(const BitVector& other) const;
    bool parity() const;

    bool equals(const BitVector& K) const
    {
        if (nbits != K.nbits)
          { return false; }
        for (size_t i = 0; i < nbytes; i++)
          { if (bytes[i] != K.bytes[i]) { return false; } }
        return true;
    }

    bool operator==(const BitVector& other) const
    {
        return equals(other);
    }

    bool operator!=(const BitVector& other) const
    {
        return not equals(other);
    }

    BitVector operator~() const;

    void append(const BitVectorView& other, size_t length = -1);
    void set_part(size_t begin, const BitVectorView& part);

    void increment() = delete;

    void randomize(PRNG& G);
    template <class T>
    void randomize_blocks(PRNG& G);
    // randomize bytes a, ..., a+nb-1
    void randomize_at(size_t a, size_t nb, PRNG& G);

    void output(ostream& s,bool human) const;
    void input(istream& s,bool human);

    void unpack(octetStream& o);

    string str(size_t end = SIZE_MAX) const
    {
        stringstream ss;
        ss << hex;
        for(size_t i(0);i < min(nbytes, end);++i)
            ss << (int)bytes[i] << " ";
        return ss.str();
    }
};

ostream& operator<<(ostream& o, const BitVectorView& x);

template <class T>
T inline BitVector::get_portion(size_t i) const
{
    if (T::size_in_bits() == 1)
        return get_bit(i);
    else
    {
        T res;
        res.assign(&bytes[T::size() * i]);
        return res;
    }
}

template <class T>
void inline BitVector::set_portion(size_t i, const T& a)
{
    memcpy(bytes + a.size() * i, a.get_ptr(), a.size());
}

template <class T, int L>
void BitVector::set(const FixedVec<T, L>& a)
{
    resize(8 * a.size());
    size_t base = 0;
    for (int i = 0; i < L; i++)
    {
        memcpy(bytes + base, a[i].get_ptr(), a[i].size());
        base += a[i].size();
    }
}

template <class T>
void inline BitVector::set(const T& a)
{
    resize(8 * a.size());
    memcpy(bytes, a.get_ptr(), a.size());
}

inline BitVectorView BitVectorView::part(size_t begin, size_t size) const
{
    assert(begin % 8 == 0);
    assert(size % 8 == 0);
#ifdef CHECK_SIZE
    assert(begin + size <= nbits);
#endif
    BitVectorView res(bytes + begin / 8, size);
    return res;
}

inline void BitVector::set_part(size_t begin, const BitVectorView& part)
{
    assert(begin % 8 == 0);
    assert(part.size() % 8 == 0);
    assert(part.size() + begin <= size());
    memcpy(bytes + begin / 8, part.bytes, part.size() / 8);
}

template<class T>
inline void BitVector::randomize_blocks(PRNG& G)
{
    if (T::size_in_bits() == 1)
    {
        G.get_octets(bytes, nbytes);
    }
    else
    {
        T tmp;
        for (size_t i = 0; i < (nbytes / T::size()); i++)
        {
            tmp.randomize(G);
            memcpy(bytes + i * T::size(), tmp.get_ptr(), T::size());
        }
    }
}

inline BitVector BitVectorView::operator^(const BitVectorView& other) const
{
    BitVector res(size());
    res.add(*this, other);
    return res;
}

#endif
