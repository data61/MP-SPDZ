/*
 * BitMatrix.h
 *
 */

#ifndef OT_BITMATRIX_H_
#define OT_BITMATRIX_H_

#include "Tools/intrinsics.h"
#include "Tools/Exceptions.h"
#include "Math/gf2nlong.h"

#include <vector>
#include <iostream>

using namespace std;

class BitVector;
class gf2n_long;
class PRNG;
class octetStream;

typedef unsigned char octet;

union square128 {
    typedef gf2n_long RowType;

    const static int N_ROWS = 128;

    static int n_rows() { return 128; }
    static int n_rows_allocated() { return 128; }
    static int n_columns() { return 128; }
    static int n_row_bytes() { return 128 / 8; }

    static size_t size() { return N_ROWS * sizeof(__m128i); }

#ifdef __AVX2__
    __m256i doublerows[64];
#endif
    __m128i rows[128];
    octet bytes[128][16];
    int16_t doublebytes[128][8];
    int32_t words[128][4];

    square128() {}

    bool get_bit(int x, int y)
    { return (bytes[x][y/8] >> (y % 8)) & 1; }

    void set_zero();

    square128& operator^=(square128& other);
    square128& operator^=(const __m128i* other);
    square128& operator^=(BitVector& other);
    bool operator==(square128& other);

    square128& add(square128& other);
    square128& sub(square128& other);
    square128& rsub(square128& other);
    square128& sub(const __m128i* other);
    square128& sub(const void* other) { return sub((__m128i*)other); }

    void bit_sub(const BitVector&, int) { throw not_implemented(); }

    void randomize(PRNG& G);
    void randomize(int row, PRNG& G);
    void conditional_add(BitVector& conditions, square128& other, int offset);
    void transpose(int n_rows = 128, int n_cols = 128);
    template <class T>
    void to(T& result);

    void check_transpose(square128& dual, int i, int k);
    void check_transpose(square128& dual);
    void print(int i, int k);
    void print();
    void print_octets();
    void print_doublerows();

    // Pack and unpack in native format
    //   i.e. Dont care about conversion to human readable form
    void pack(octetStream& o) const;
    void unpack(octetStream& o);
};

// allocator to counter GCC bug
template <typename _Tp, int ALIGN>
class aligned_allocator : public std::allocator<_Tp>
{
public:
    typedef size_t     size_type;
    typedef ptrdiff_t  difference_type;
    typedef _Tp*       pointer;
    typedef const _Tp* const_pointer;
    typedef _Tp&       reference;
    typedef const _Tp& const_reference;
    typedef _Tp        value_type;

    template<typename _Tp1>
    struct rebind
    { typedef aligned_allocator<_Tp1, ALIGN> other; };

    _Tp*
    allocate(size_t __n, const void* = 0)
    {
        _Tp* res = 0;
        int err = posix_memalign((void**)&res, ALIGN, __n * sizeof(_Tp));
        if (err != 0 or res == 0)
            std::__throw_bad_alloc();
        return res;
    }

    void
    deallocate(pointer __p, size_type)
    {
        free(__p);
    }
};

template <class U>
class Slice;

template <class U>
class Matrix
{
public:
    typedef U PartType;

    vector< U, aligned_allocator<U, 32> > squares;

    typename U::RowType& operator[](int i)
    { return squares[i / U::n_rows()].rows[i % U::n_rows()]; }

    size_t vertical_size() const;

    void resize_vertical(int length)
    { squares.resize(DIV_CEIL(length, U::n_rows())); }

    bool operator==(Matrix<U>& other);
    bool operator!=(Matrix<U>& other);

    void randomize(PRNG& G);
    void randomize(int row, PRNG& G);
    void print_side_by_side(Matrix<U>& other);
    void print_conditional(BitVector& conditions);

    // Pack and unpack in native format
    //   i.e. Dont care about conversion to human readable form
    void pack(octetStream& o) const;
    void unpack(octetStream& o);
};

class BitMatrix : public Matrix<square128>
{
public:
    BitMatrix() {}
    BitMatrix(int length);

    __m128i& operator[](int i) { return squares[i / 128].rows[i % 128]; }
    __m128i& at(size_t i);

    bool lsb(size_t i) { return int128((*this)[i]).get_bit(0); }
    BitVector lsbs() const;

    void resize(int length);

    void transpose();
    void check_transpose(BitMatrix& dual);

    void vertical_to(vector<BitVector>& output);
};

template <class U>
class Slice
{
    friend U;

    U& bm;
    size_t start, end;

public:
    Slice(U& bm, size_t start, size_t size);

    Slice<U>& rsub(Slice<U>& other);
    Slice<U>& sub(BitVector& other, int repeat = 1);

    void randomize(int row, PRNG& G);
    void conditional_add(BitVector& conditions, U& other, bool useOffset = false);
    void transpose();

    template <class T>
    void print();

    // Pack and unpack in native format
    //   i.e. Dont care about conversion to human readable form
    void pack(octetStream& o) const;
    void unpack(octetStream& o);
};

typedef Slice<BitMatrix> BitMatrixSlice;

#endif /* OT_BITMATRIX_H_ */
