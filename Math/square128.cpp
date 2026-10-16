/*
 * BitMatrix.cpp
 *
 */

#include <gmpxx.h>

#include "OT/BitMatrix.h"
#include "Tools/random.h"
#include "Tools/BitVector.h"
#include "Tools/intrinsics.h"
#include "Math/Square.h"

#include "OT/BitMatrix.hpp"

union matrix16x8
{
    __m128i whole;
    octet rows[16];

    matrix16x8() : whole(_mm_setzero_si128()) {}
    matrix16x8(__m128i x) { whole = x; }

    bool get_bit(int x, int y)
    { return (rows[x] >> y) & 1; }

    void input(square128& input, int x, int y);
    void transpose(square128& output, int x, int y);
};

class square16
{
public:
    // 16x16 in two halves, 128 bits each
    matrix16x8 halves[2];

    bool get_bit(int x, int y)
    { return halves[y/8].get_bit(x, y % 8); }

    void input(square128& output, int x, int y);
    void transpose(square128& output, int x, int y);

    void check_transpose(square16& dual);
    void print();
};

#ifdef __clang__
#define UNROLL_LOOPS
#else
#define UNROLL_LOOPS __attribute__((optimize("unroll-loops")))
#endif

UNROLL_LOOPS
inline void matrix16x8::input(square128& input, int x, int y)
{
    for (int l = 0; l < 16; l++)
        rows[l] = input.bytes[16*x+l][y];
}

UNROLL_LOOPS
inline void square16::input(square128& input, int x, int y)
{
    for (int i = 0; i < 2; i++)
        halves[i].input(input, x, 2 * y + i);
}

UNROLL_LOOPS
inline void matrix16x8::transpose(square128& output, int x, int y)
{
    for (int j = 0; j < 8; j++)
    {
        int row = _mm_movemask_epi8(whole);
        whole = _mm_slli_epi64(whole, 1);

        // _mm_movemask_epi8 uses most significant bit, hence +7-j
        output.doublebytes[8*x+7-j][y] = row;
    }
}

UNROLL_LOOPS
inline void square16::transpose(square128& output, int x, int y)
{
    for (int i = 0; i < 2; i++)
        halves[i].transpose(output, 2 * x + i, y);
}

#ifdef __AVX2__
union matrix32x8
{
    __m256i whole;
    octet rows[32];

    matrix32x8() : whole(_mm256_setzero_si256()) {}
    matrix32x8(__m256i x) { whole = x; }

    void input(square128& input, int x, int y);
    void transpose(square128& output, int x, int y);
};

class square32
{
public:
    matrix32x8 quarters[4];

    void input(square128& input, int x, int y);
    void transpose(square128& output, int x, int y);
};

UNROLL_LOOPS
inline void matrix32x8::input(square128& input, int x, int y)
{
    for (int l = 0; l < 32; l++)
        rows[l] = input.bytes[32*x+l][y];
}

UNROLL_LOOPS
inline void square32::input(square128& input, int x, int y)
{
    for (int i = 0; i < 4; i++)
        quarters[i].input(input, x, 4 * y + i);
}

UNROLL_LOOPS
inline void matrix32x8::transpose(square128& output, int x, int y)
{
    for (int j = 0; j < 8; j++)
    {
        int row = _mm256_movemask_epi8(whole);
        whole = _mm256_slli_epi64(whole, 1);

        // _mm_movemask_epi8 uses most significant bit, hence +7-j
        output.words[8*x+7-j][y] = row;
    }
}

UNROLL_LOOPS
inline void square32::transpose(square128& output, int x, int y)
{
    for (int i = 0; i < 4; i++)
        quarters[i].transpose(output, 4 * x + i, y);
}
#endif

#ifdef __AVX2__
typedef square32 subsquare;
#define N_SUBSQUARES 4
#else
typedef square16 subsquare;
#define N_SUBSQUARES 8
#endif

// hypercube permutation
#ifndef __AVX2__
const int perm[] = { 0, 8, 4, 0xc, 2, 0xa, 6, 0xe, 1, 9, 5, 0xd, 3, 0xb, 7, 0xf };
#else
const int perm2[] = { 0, 4, 2, 6, 1, 5, 3, 7, 8, 0xc, 0xa, 0xe, 9, 0xd, 0xb, 0xf };
#endif

UNROLL_LOOPS
void square128::transpose(int n_rows, int n_cols)
{
    assert(n_rows <= 128);
    assert(n_cols <= 128);
#ifdef USE_SUBSQUARES
    for (int j = 0; j < N_SUBSQUARES; j++)
        for (int k = 0; k < j; k++)
        {
            subsquare a, b;
            a.input(*this, k, j);
            b.input(*this, j, k);
            a.transpose(*this, j, k);
            b.transpose(*this, k, j);
        }

    for (int j = 0; j < N_SUBSQUARES; j++)
    {
        subsquare a;
        a.input(*this, j, j);
        a.transpose(*this, j, j);
    }
#else
#define EIGHTTOSIXTYFOUR X(8) X(16) X(32) X(64)
#define X(I) { \
        const int J = I / 4; \
        for (int i = 0; i < 16 / J; i++) \
        { \
            for (int j = 0; j < J / 2; j++) \
            { \
                int a = base + J * i + j; \
                int b = a + J/2; \
                __m128i tmp = _mm_unpacklo_epi##I(rows[a], rows[b]); \
                rows[b] = _mm_unpackhi_epi##I(rows[a], rows[b]); \
                rows[a] = tmp; \
            } \
        } \
    }
#ifdef __AVX2__
#define Z(I) { \
        const int J = I / 8; \
        for (int i = 0; i < 16 / J; i++) \
        { \
            for (int j = 0; j < J / 2; j++) \
            { \
                int a = base + J * i + j; \
                int b = a + J/2; \
                __m256i tmp = _mm256_unpacklo_epi##I(doublerows[a], doublerows[b]); \
                doublerows[b] = _mm256_unpackhi_epi##I(doublerows[a], doublerows[b]); \
                doublerows[a] = tmp; \
            } \
        } \
    }

    square128 tmp;
    for (int k = 0; k < DIV_CEIL(n_rows, 32); k++)
    {
        int base = k * 16 * 2;
        X(8)
        base += 16;
        X(8)
        base = k * 16;
        Z(16) Z(32) Z(64)
        for (int i = 0; i < 8; i++)
        {
            int a = base + i;
            int b = a + 8;
            __m128i tmp = rows[2 * b];
            rows[2 * b] = rows[2 * a + 1];
            rows[2 * a + 1] = tmp;
        }
        for (int i = 0; i < 16; i++)
        {
            int j = perm2[i];
            tmp.doublerows[base + i] = doublerows[base + j];
        }
    }

    for (int i = 0; i < DIV_CEIL(n_cols, 8); i++)
    {
        for (int k = 0; k < 4; k++)
            matrix32x8(tmp.doublerows[k * 16 + i]).transpose(*this, i, k);
    }
#else // __AVX2__
    square128 tmp;
    for (int k = 0; k < 8; k++)
    {
        int base = k * 16;
        EIGHTTOSIXTYFOUR
        for (int i = 0; i < 16; i++)
        {
            int j = perm[i];
            tmp.rows[base + i] = rows[base + j];
        }
    }

    for (int i = 0; i < 16; i++)
    {
        for (int k = 0; k < 8; k++)
            matrix16x8(tmp.rows[k * 16 + i]).transpose(*this, i, k);
    }
#endif // __AVX2__
#endif // __USE_SUBSQUARES__
}

void square128::randomize(PRNG& G)
{
    G.get_octets((octet*)&rows, sizeof(rows));
}

void square128::randomize(int row, PRNG& G)
{
    rows[row] = G.get_doubleword();
}


void square128::conditional_add(BitVector& conditions, square128& other, int offset)
{
    for (int i = 0; i < 128; i++)
        if (conditions.get_bit(128 * offset + i))
            rows[i] ^= other.rows[i];
}

template <>
void Square<gf2n_long>::to(gf2n_long& result, false_type)
{
    int128 high, low;
    for (int i = 0; i < gf2n_long::degree(); i++)
    {
        low ^= rows[i].get() << i;
        high ^= rows[i].get() >> (128 - i);
    }
    result.reduce(high, low);
}

void square128::check_transpose(square128& dual, int i, int k)
{
    for (int j = 0; j < 16; j++)
        for (int l = 0; l < 16; l++)
            if (get_bit(16 * i + j, 16 * k + l) != dual.get_bit(16 * k + l, 16 * i + j))
            {
                cout << "Error in 16x16 square (" << i << "," << k << ")" << endl;
                print(i, k);
                cout << "dual" << endl;
                dual.print(i, k);
                exit(1);
            }
}

void square128::check_transpose(square128& dual)
{
    for (int i = 0; i < 8; i++)
        for (int k = 0; k < 8; k++)
            check_transpose(dual, i, k);
}

void square16::print()
{
    for (int i = 0; i < 2; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            for (int k = 0; k < 2; k++)
            {
                for (int l = 0; l < 8; l++)
                    cout << halves[k].get_bit(8 * i + j, l);
                cout << " ";
            }
            cout << endl;
        }
        cout << endl;
    }
}

void square128::print(int i, int k)
{
    square16 a;
    a.input(*this, i, k);
    a.print();
}

void square128::print()
{
    for (int i = 0; i < 128; i++)
    {
        for (int j = 0; j < 128; j++)
            cout << get_bit(i, j);
        cout << endl;
    }
}

void square128::print_octets()
{
    for (int i = 0; i < 128; i++)
    {
        for (int j = 0; j < 16; j++)
            cout << hex << (int)bytes[i][j] << " ";
        cout << endl;
    }
    cout << dec;
}

void square128::print_doublerows()
{
    for (int i = 0; i < 64; i++)
    {
        for (int j = 0; j < 32; j++)
        {
            cout.width(2);
            cout << hex << (int)bytes[2*i+j/16][j%16] << " ";
        }
        cout << endl;
    }
    cout << dec;
}

void square128::set_zero()
{
    for (int i = 0; i < 128; i++)
        rows[i] = _mm_setzero_si128();
}

square128& square128::operator^=(square128& other)
{
    for (int i = 0; i < 128; i++)
        rows[i] ^= other.rows[i];
    return *this;
}

square128& square128::add(square128& other)
{
    return *this ^= other;
}

square128& square128::sub(square128& other)
{
    return *this ^= other;
}

square128& square128::rsub(square128& other)
{
    return *this ^= other;
}

square128& square128::operator^=(const __m128i* other)
{
    __m128i value = _mm_loadu_si128(other);
    for (int i = 0; i < 128; i++)
        rows[i] ^= value;
    return *this;
}

square128& square128::sub(const __m128i* other)
{
    return *this ^= other;
}

square128& square128::operator^=(BitVector& other)
{
    return *this ^= (__m128i*)other.get_ptr();
}

bool square128::operator==(square128& other)
{
    for (int i = 0; i < 128; i++)
    {
        if (int128(rows[i]) != other.rows[i])
            return false;
    }
    return true;
}

void square128::pack(octetStream& o) const
{
    o.append((octet*)this->bytes, sizeof(bytes));
}

void square128::unpack(octetStream &o)
{
    o.consume((octet*)this->bytes, sizeof(bytes));
}


BitMatrix::BitMatrix(int length)
{
    resize(length);
}

__m128i& BitMatrix::at(size_t i)
{
    assert(i < vertical_size());
    return (*this)[i];
}

void BitMatrix::resize(int length)
{
    if (length % 128 != 0)
        throw invalid_length(
                to_string(length) + " not divisible by "
                        + to_string(128));
    squares.resize(length / 128);
}

void BitMatrix::transpose()
{
    for (size_t i = 0; i < squares.size(); i++)
        squares[i].transpose();
}

void BitMatrix::check_transpose(BitMatrix& dual)
{
    for (size_t i = 0; i < squares.size(); i++)
    {
        for (int j = 0; j < 128; j++)
            for (int k = 0; k < 128; k++)
                if (squares[i].get_bit(j, k) != dual.squares[i].get_bit(k, j))
                {
                    cout << "First error in square " << i << " row " << j
                            << " column " << k << endl;
                    squares[i].print(i / 8, j / 8);
                    dual.squares[i].print(i / 8, j / 8);
                    return;
                }
    }
    cout << "No errors in transpose" << endl;
}

void BitMatrix::vertical_to(vector<BitVector>& output)
{
    int n = 128 * squares.size();
    output.resize(n);
    for (int i = 0; i < n; i++)
    {
        output[i].resize(128);
        output[i].set_int128(0, squares[i / 128].rows[i % 128]);
    }
}

BitVector BitMatrix::lsbs() const
{
    BitVector res(vertical_size());
    for (size_t i = 0; i < squares.size(); i++)
    {
        for (int k = 0; k < 2; k++)
        {
            word tmp = 0;
            for (int j = 0; j < 64; j++)
                tmp ^= word(int128(squares[i].rows[k * 64 + j]).get_bit(0)) << j;
            assert(tmp);
            res.set_word(2 * i + k, tmp);
        }
    }
    return res;
}

template <>
void Slice<BitMatrix>::transpose()
{
    for (size_t i = start; i < end; i++)
        bm.squares[i].transpose();
}
