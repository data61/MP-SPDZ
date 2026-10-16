/*
 * F2.h
 *
 */

#ifndef GC_F2VECTOR_H_
#define GC_F2VECTOR_H_

#include "Tools/BitVector.h"
#include "F3.h"

class F2VectorPlain;

class F2Vector : public BitVector
{
public:
    typedef F2VectorPlain plain_type;

    F2Vector() = default;

    F2Vector(size_t size) : BitVector(size)
    {
    }

    F2Vector(const BitVectorView& other) : BitVector(other)
    {
    }

    F2Vector(const F3VectorBitWiseView& other)
    {
        operator=(other);
    }

    F2Vector& operator=(const F3VectorBitWiseView& other)
    {
        *this = other.get_bits(0);
        resize(other.size());
        return *this;
    }

    void add_mul(Bit b, const F2Vector& other)
    {
        assert(size() == other.size());
        if (b.get())
        {
            size_t n_chunks = size_bytes() / sizeof(__m128i);
            for (size_t i = 0; i < n_chunks; i++)
                set_int128(i, get_int128(i) ^ other.get_int128(i));
            for (size_t i = n_chunks * sizeof(__m128i); i < size_bytes(); i++)
                bytes[i] ^= other.bytes[i];
        }
    }

    F2Vector operator+(const F2Vector& other) const
    {
        assert(size() == other.size());
        auto res = *this;
        return res ^= other;
    }

    F2Vector operator*(bool other) const
    {
        if (other)
            return *this;
        else
            return size();
    }
};

class F2VectorPlain : public vector<Bit>
{
public:
    F2VectorPlain(const BitVector& other)
    {
        reserve(8 * other.size_bytes());
        for (size_t i = 0; i < other.size_bytes(); i++)
        {
            auto byte = other.get_byte(i);
            for (int j = 0; j < 8; j++)
            {
                push_back(byte & 1);
                byte >>= 1;
            }
        }
        resize(other.size());
    }
};

class F2Vec128
{
    int128 a;
    size_t size_;

public:
    F2Vec128(size_t size = 128)
    {
        resize(size);
    }

    int128 get() const
    {
        return a;
    }

    size_t size() const
    {
        return size_;
    }

    void resize(size_t size)
    {
        assert(size == 128);
        size_ = size;
    }

    void add_mul(Bit b, const F2Vec128& other)
    {
        if (b.get())
            a ^= other.a;
    }

    void randomize(PRNG& G)
    {
        a = G.get_doubleword();
    }
};

#endif /* GC_F2VECTOR_H_ */
