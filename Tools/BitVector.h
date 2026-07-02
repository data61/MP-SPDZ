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
#include "Tools/intrinsics.h"

class PRNG;
class octetStream;

template <int K>
class Z2;
template <class U, class V>
class Rectangle;

class BitVector
{
    octet* bytes;

    size_t nbytes;
    size_t nbits;

    public:

    void assign(const BitVector& K);
    void assign_bytes(char* new_bytes, int len)
    {
        resize(len*8);
        memcpy(bytes, new_bytes, len);
    }
    void assign_zero()
    {
        memset(bytes, 0, nbytes);
    }
    // only grows, never destroys
    void resize(size_t new_nbits)
    {
    if (nbits != new_nbits)
        {
            int new_nbytes = DIV_CEIL(new_nbits,8);

            if (nbits < new_nbits)
            {
                octet* tmp = new octet[new_nbytes];
                memcpy(tmp, bytes, nbytes);
                delete[] bytes;
                bytes = tmp;
            }

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
    void resize_zero(size_t new_nbits);

    unsigned int size() const { return nbits; }
    unsigned int size_bytes() const { return nbytes; }
    octet* get_ptr() { return bytes; }
    const octet* get_ptr() const { return bytes; }
    const void* get_ptr_to_byte(size_t i, size_t block_size) const;
    const void* get_ptr_to_bit(size_t i, size_t block_size) const;

    BitVector(size_t n=0)
    {
        nbits = n;
        nbytes = DIV_CEIL(nbits, 8);
        bytes = new octet[nbytes];
        assign_zero();
    }
    BitVector(const BitVector& K)
    {
        bytes = new octet[K.nbytes];
        nbytes = K.nbytes;
        nbits = K.nbits;
        assign(K);
    }
    BitVector(const void* other, size_t bitsize) : BitVector()
    {
        resize(bitsize);
        avx_memcpy(bytes, other, nbytes);
    }
    ~BitVector() {
        //cout << "Destroy, size = " << nbytes << endl;
        delete[] bytes;
    }
    BitVector& operator=(const BitVector& K)
    {
        if (this!=&K) { assign(K); }
        return *this;
    }

    BitVector& operator=(const octetStream other);

    void swap(BitVector& other)
    {
        std::swap(nbits, other.nbits);
        std::swap(nbytes, other.nbytes);
        std::swap(bytes, other.bytes);
    }

    class Access
    {
        BitVector& v;
        int i;

    public:
        Access(BitVector& v, int i) : v(v), i(i) {}
        bool get() const { return v.get_bit(i); }
        void operator=(bool b) { v.set_bit(i, b); }
        void operator=(const Access& other) { *this = other.get(); }
        void operator^=(const Access& other) { *this = get() ^ other.get(); }
        bool operator==(const Access& other) const { return get() == other.get(); }
        operator bool() const { return get(); }
    };

    bool operator[](int i) const { return get_bit(i); }
    Access operator[](int i) { return {*this, i}; }

    octet get_byte(int i) const { return bytes[i]; }

    void set_byte(int i, octet b) { bytes[i] = b; }

    // get the i-th 64-bit word
    word get_word(int i) const { return *(word*)(bytes + i*8); }

    void set_word(int i, word w)
    {
        int offset = i * sizeof(word);
        memcpy(bytes + offset, (octet*)&w, sizeof(word));
    }

    int128 get_int128(int i) const { return _mm_loadu_si128((__m128i*)bytes + i); }
    void set_int128(int i, int128 a) { *((__m128i*)bytes + i) = a.a; }

    template <class T>
    T get_portion(int i) const;
    template <class T>
    void set_portion(int i, const T& a);

    template <class T>
    void set(const T& a);
    template <class T, int L>
    void set(const FixedVec<T, L>& a);
    bool get_bit(int i) const
      {
#ifdef CHECK_SIZE
        if (i >= (int)nbits)
          throw out_of_range("BitVector access: " + to_string(i) + "/" + to_string(nbits));
#endif
        return (bytes[i/8] >> (i % 8)) & 1;
      }
    void set_bit(int i,unsigned int a)
    {
        if ((size_t)i >= nbits)
            throw overflow("BitVector", i, nbits);
        int j = i/8, k = i&7;
        if (a==1)
          { bytes[j] |= (octet)(1UL<<k); }
        else
  	     { bytes[j] &= (octet)~(1UL<<k); }
    }

    void add(const BitVector& A, const BitVector& B)
    {
        if (A.nbits != B.nbits)
          { throw invalid_length(); }
        resize(A.nbits);
        for (unsigned int i=0; i < nbytes; i++)
  	    {
            bytes[i] = A.bytes[i] ^ B.bytes[i];
        }
    }

    void add(const BitVector& A)
    {
        if (nbits != A.nbits)
          { throw invalid_length(); }
        int nwords = nbytes / 8;
        for (int i = 0; i < nwords; i++)
            ((word*)bytes)[i] ^= ((word*)A.bytes)[i];
        for (unsigned int i = nwords * 8; i < nbytes; i++)
  	    {
            bytes[i] ^= A.bytes[i];
        }
    }
    
    BitVector operator&(const BitVector& other) const;
    bool parity() const;

    bool equals(const BitVector& K) const
    {
        if (nbits != K.nbits)
          { return false; }
        for (unsigned int i = 0; i < nbytes; i++)
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

    void append(const BitVector& other, size_t length);

    void randomize(PRNG& G);
    template <class T>
    void randomize_blocks(PRNG& G);
    // randomize bytes a, ..., a+nb-1
    void randomize_at(int a, int nb, PRNG& G);

    void output(ostream& s,bool human) const;
    void input(istream& s,bool human);

    // Pack and unpack in native format
    //   i.e. Dont care about conversion to human readable form
    void pack(octetStream& o) const;
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

template <class T>
T inline BitVector::get_portion(int i) const
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
void inline BitVector::set_portion(int i, const T& a)
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

#endif
