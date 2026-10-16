/*
 * F3.h
 *
 */

#ifndef MATH_F3_H_
#define MATH_F3_H_

#include "Math/ValueInterface.h"
#include "Tools/BitVector.h"
#include "OT/BitMatrix.h"

class F3 : ValueInterface
{
    friend class F3Vector;
    friend class F3VectorBitWise;
    friend class F3VectorBitWiseView;

    char a;

public:
    static int p()
    {
        return 3;
    }

    F3() :
            a(0)
    {
    }

    F3(int a) :
            a((a + 3) % 3)
    {
    }

    char get() const
    {
        return a;
    }

    F3 operator+(const F3& other) const
    {
        return a + other.a;
    }

    F3 operator-(const F3& other) const
    {
        return a - other.a;
    }

    F3 operator*(const F3& other) const
    {
        return a * other.a;
    }

    F3& operator+=(const F3& other)
    {
        *this = a + other.a;
        return *this;
    }

    F3& operator*=(const F3& other)
    {
        *this = a * other.a;
        return *this;
    }

    bool operator==(const F3& other) const
    {
        return a == other.a;
    }

    bool get_bit(int i) const
    {
        if (i)
            return a & 2;
        else
            return a & 1;
    }

    void randomize(PRNG& G)
    {
        a = 3;
        while (a == 3)
            a = (G.get_bit() << 1) + G.get_bit();
    }

    void pack(octetStream& os) const
    {
        os.store_int(a, 1);
    }

    void unpack(octetStream& os)
    {
        a = os.get_int(1);
    }
};

inline
ostream& operator<<(ostream& o, const F3& x)
{
    o << int(x.get());
    return o;
}

class F3VectorBitWise;
class F3VectorBitWiseView;

class F3Vector : public vector<F3>, public ValueInterface
{
    typedef vector<F3> super;

    thread_local static vector<array<F3, 5>> randomness_table;

    static void build_randomness_table();
    static array<F3, 5> randomness_lookup(unsigned char);

public:
    typedef F3Vector next;
    typedef F3Vector plain_type;

    F3Vector() = default;

    F3Vector(size_t size) :
            super(size)
    {
    }

    F3Vector(const super& other) : super(other)
    {
    }

    F3Vector(const F3VectorBitWiseView& other);

    void append(const F3Vector& other)
    {
        this->insert(end(), other.begin(), other.end());
    }

    F3Vector operator+(const vector<F3>& other) const
    {
        assert(size() == other.size());
        F3Vector res;
        for (size_t i = 0; i < size(); i++)
            res.push_back((*this)[i] + other[i]);
        return res;
    }

    F3Vector& operator+=(const vector<F3>& other)
    {
        *this = *this + other;
        return *this;
    }

    F3Vector operator-(const vector<F3>& other) const
    {
        assert(size() == other.size());
        F3Vector res;
        for (size_t i = 0; i < size(); i++)
            res.push_back((*this)[i] - other[i]);
        return res;
    }

    void add_mul(F3 c, const F3Vector& other)
    {
        assert(size() == other.size());
        if (c.get() == 1)
            *this += other;
        else if (c.get() == 2)
            for (size_t i = 0; i < size(); i++)
                (*this)[i] += 2 * other[i].get();
    }

    void randomize_to_size(PRNG& G, size_t size)
    {
        clear();
        reserve(size);
        size_t i = 0;
        while (i + 5 < size)
        {
            auto r = G.get_uchar();
            if (r < 243)
            {
                auto rr = randomness_lookup(r);
                for (auto x : rr)
                    push_back(x);
                i += 5;
            }
        }

        for (; i < size; i++)
            push_back(G.get<F3>());
    }

    void randomize(PRNG& G)
    {
        randomize_to_size(G, size());
    }

    void pack(octetStream& os, int = -1) const
    {
        for (auto& x : *this)
            x.pack(os);
    }

    void unpack(octetStream& os, int = -1)
    {
        for (auto& x : *this)
            x.unpack(os);
    }

    BitVector to_bitvector() const;
};

template<class T>
T andnot(T a, T b)
{
    return ~a & b;
}

ostream& operator<<(ostream& o, const F3VectorBitWiseView& v);

class F3VectorBitWiseView
{
    friend class F3VectorBitWise;

    size_t size_;
    array<BitVectorView, 2> bits;

    F3VectorBitWiseView(size_t size = 0) : size_(size)
    {
    }

public:
    typedef F3VectorBitWise owner_type;

    size_t storage_size() const
    {
        return multiple_minimum(size_, 8 * sizeof(__m256i));
    }

    size_t size() const
    {
        return this->size_;
    }

    void assign(const F3VectorBitWiseView& other)
    {
        assert(size() == other.size());
        for (int k = 0; k < 2; k++)
        {
            bits[k].assign(other.bits[k]);
        }
    }

    F3 operator[](size_t i) const
    {
        return bits[0].get_bit(i) + (bits[1].get_bit(i) << 1);
    }

    const BitVectorView& get_bits(int k) const
    {
        return bits[k];
    }

    array<F3, 8> eight_from(size_t i) const
    {
        char bytes[32];
        memset(bytes, 0, sizeof(bytes));
        for (int k = 0; k < 2; k++)
            bytes[k] = bits[k].get_byte(i / 8);
        __m256i whole = _mm256_loadu_si256((__m256i*) bytes);
        array<F3, 8> res;
        for (int j = 0; j < 8; j++)
        {
            res[7 - j].a = _mm256_movemask_epi8(whole);
            whole = _mm256_slli_epi64(whole, 1);
        }
        return res;
    }

    F3VectorBitWiseView& operator+=(const F3VectorBitWiseView& other)
    {
        return add_or_sub(other, false);
    }

    F3VectorBitWiseView& operator-=(const F3VectorBitWiseView& other)
    {
        return add_or_sub(other, true);
    }

    F3VectorBitWiseView& add_or_sub(const F3VectorBitWiseView& other, bool swap)
    {
        assert(size() == other.size());
        auto n_chunks = bits[0].size_chunks<__m256i>();
        for (size_t i = 0; i < n_chunks; i++)
        {
            typedef __m256i T;
            T a[2] = {bits[0].get_m256i(i), bits[1].get_m256i(i)};
            T b[2] = {other.bits[swap].get_m256i(i),
                    other.bits[swap ^ 1].get_m256i(i)};
            auto t = a[1] ^ a[0];
            auto s1 = andnot(b[0] ^ a[0], t ^ b[1]);
            auto s0 = andnot(a[1] ^ b[1], t ^ b[0]);
            bits[0].set_m256i(i, s0);
            bits[1].set_m256i(i, s1);
        }
        return *this;
    }

    F3VectorBitWiseView operator-() const
    {
        F3VectorBitWiseView res = *this;
        swap(res.bits[0], res.bits[1]);
        return res;
    }

    F3VectorBitWise operator-(const F3VectorBitWiseView& other);

    F3VectorBitWise schur(const BitVector& other) const;
    void ischur(const BitVector& other);

    void increment()
    {
        for (auto& x : bits)
            x.increment();
    }

    BitVector to_bitvector() const
    {
        BitVector res = get_bits(0).part(0, size());
        assert(res.size());
        res.append(get_bits(1).part(0, size()), res.size());
        assert(res.size());
        return res;
    }

    void pack(octetStream& os) const
    {
        for (auto& x : bits)
            x.pack(os);
    }
};

namespace GC
{
template<class T> class RowMatrix;
}

class F3VectorBitWise : public F3VectorBitWiseView
{
    typedef F3VectorBitWiseView super;

    friend class F3Vector;
    friend super;

    union matrix32x8
    {
        __m256i whole;
        octet rows[32];
    };

    static void build_randomness_table();

    thread_local static vector<array<word, 2>> randomness_table;

    array<BitVector, 2> bits;

public:
    typedef F3Vector plain_type;
    typedef F3VectorBitWiseView view_type;

    static GC::RowMatrix<F3VectorBitWise> transpose(
            const GC::RowMatrix<F3VectorBitWise>& matrix);

    static F3VectorBitWise zero(size_t size)
    {
        F3VectorBitWise res(size);
        for (auto& x : res.bits)
            x.assign_zero();
        return res;
    }

    F3VectorBitWise(size_t size = 0)
    {
        resize(size);
    }

    F3VectorBitWise(const F3VectorBitWise& other) : F3VectorBitWiseView()
    {
        operator=(other);
    }

    F3VectorBitWise(const F3VectorBitWiseView& other)
    {
        operator=(other);
    }

    F3VectorBitWise(const F3Vector& other)
    {
        operator=(other);
    }

    F3VectorBitWise& operator=(const F3VectorBitWise& other)
    {
        operator=(F3VectorBitWiseView(other));
        return *this;
    }

    F3VectorBitWise& operator=(const F3VectorBitWiseView& other)
    {
        resize(other.size());
        for (int k = 0; k < 2; k++)
            bits[k] = other.bits[k];
        return *this;
    }

    F3VectorBitWise& operator=(const F3Vector& x)
    {
        resize(x.size());
        auto& other = x;
        size_t i;
        for (i = 0; i + 31 < size(); i += 32)
        {
            matrix32x8 tmp;
            for (size_t j = 0; j < 32; j++)
            {
                tmp.rows[j] = other[i + j].get();
            }
            auto whole = tmp.whole;
            whole = _mm256_slli_epi64(whole, 6);
            bits[1].set_int32(i / 32, _mm256_movemask_epi8(whole));
            whole = _mm256_slli_epi64(whole, 1);
            bits[0].set_int32(i / 32, _mm256_movemask_epi8(whole));
        }
        for (; i < size(); i++)
        {
            for (int k = 0; k < 2; k++)
                bits[k].set_bit(i, x[i].get_bit(k));
        }
#ifdef AVOID_UNSET_MEMORY
        auto rounded_size = multiple_minimum(size(), 8);
        for (auto& bit : bits)
            bit.part(rounded_size, storage_size() - rounded_size).assign_zero();
#endif
        return *this;
    }

    void resize(size_t size)
    {
        this->size_ = size;
        for (auto& bit: bits)
            bit.resize(storage_size());
        for (int k = 0; k < 2; k++)
            super::bits[k] = bits[k];
    }

    F3 at(size_t i) const
    {
        assert(i < bits[0].size());
        return (*this)[i];
    }

    F3VectorBitWiseView part(size_t begin, size_t size) const
    {
        F3VectorBitWiseView res(size);
        for (int k = 0; k < 2; k++)
            res.bits[k] = bits[k].part(begin, res.storage_size());
        return res;
    }

    void set_part(size_t begin, const F3VectorBitWiseView& part)
    {
        assert(begin + part.size() <= size());
        for (int k = 0; k < 2; k++)
            bits[k].set_part(begin,
                    part.bits[k].part(0, multiple_minimum(part.size(), 8)));
    }

    void append(const F3VectorBitWiseView& other)
    {
        assert(size() % 8 == 0);
        auto old_size = size();
        size_ += other.size();
        for (int k = 0; k < 2; k++)
        {
            bits[k].resize(old_size);
            bits[k].append(other.bits[k], other.size());
            bits[k].resize(storage_size());
            super::bits[k] = bits[k];
        }
    }

    F3VectorBitWise operator+(const F3VectorBitWiseView& other)
    {
        auto res = *this;
        return res += other;
    }

    void add_mul(F3 c, const F3VectorBitWiseView& other)
    {
        if (c.get() == 1)
            *this += other;
        if (c.get() == 2)
            *this -= other;
    }

    BitVector select(const array<bool, 3>& options) const
    {
        assert(options[0] + options[1] + options[2] == 1);
        BitVector res;
        const BitVector& lower = bits[0], higher = bits[1];
        if (options[0])
            res = ~lower & ~higher;
        else if (options[1])
            res = lower & ~higher;
        else if (options[2])
            res = higher;
        res.resize(size());
        return res;
    }

    BitVector select(const array<BitVector, 3>& options)
    {
        BitVector res;
        const BitVector& lower = bits[0], higher = bits[1];
        res = options[0] & (~lower & ~higher);
        res ^= options[1] & (lower & ~higher);
        res ^= options[2] & higher;
        res.resize(size());
        return res;
    }

    void randomize(PRNG& G);

    void unpack(octetStream& os)
    {
        for (auto& x : bits)
        {
            x.unpack(os);
            assert(x.size() == storage_size());
        }
    }

    bool operator!=(const F3VectorBitWise& other) const
    {
        if (size() != other.size())
            return true;
        if (bits != other.bits)
            return true;
        return false;
    }
};

ostream& operator<<(ostream& o, const F3Vector& v);

inline
F3Vector::F3Vector(const F3VectorBitWiseView& other)
{
    reserve(multiple_minimum(other.size(), 8));
    for (size_t i = 0; i < other.size(); i += 8)
    {
        auto tmp = other.eight_from(i);
        insert(end(), tmp.begin(), tmp.end());
    }
    resize(other.size());
}

inline
BitVector F3Vector::to_bitvector() const
{
    return F3VectorBitWise(*this).to_bitvector();
}

inline
F3VectorBitWiseView operator-(const F3Vector& a, const F3VectorBitWiseView& b)
{
    return F3VectorBitWise(a) - b;
}

inline
F3VectorBitWise F3VectorBitWiseView::operator-(
        const F3VectorBitWiseView& other)
{
    F3VectorBitWise res = *this;
    auto tmp = -other;
    res += tmp;
    return res;

}

inline
F3VectorBitWise F3VectorBitWiseView::schur(const BitVector& other) const
{
    F3VectorBitWise res;
    res.ischur(other);
    return res;
}

inline
void F3VectorBitWiseView::ischur(const BitVector& other)
{
    for (auto& x : bits)
        x.part(0, size()) &= other.part(0, size());
}

inline
ostream& operator<<(ostream& o, const F3Vector& v)
{
    for (auto& x : v)
        o << x;
    return o;
}

inline
ostream& operator<<(ostream& o, const F3VectorBitWiseView& v)
{
    o << F3Vector(v);
    return o;
}

inline
array<F3, 5> F3Vector::randomness_lookup(unsigned char r)
{
    if (randomness_table.empty())
    {
        build_randomness_table();
    }

    assert(r < 243);
    return randomness_table[r];
}

#endif /* MATH_F3_H_ */
