/*
 * SemiSecureShuffle.h
 *
 */

#ifndef GC_SEMISECURESHUFFLE_H_
#define GC_SEMISECURESHUFFLE_H_

#include "Processor.h"
#include "SemiSecret.h"

#include "Protocols/SecureShuffle.h"
#include "F3.h"
#include "F3Code.h"

class PlayerCoSocket;
class F3;
class F3Vector;
class F3VectorBitWise;
class F2Vector;
class F2Vec128;

namespace GC
{

class BitBuffer
{
    friend class SemiSecureShuffle;

    vector<pair<int128, size_t>> values;

public:
    BitBuffer()
    {
    }

    template<class T>
    BitBuffer(const T& other, size_t n);

    bool has_enough(size_t n_bits);

    SemiSecret get(size_t index, size_t n_bits);

    void resize(size_t size);
    void add(size_t index, const BitVector& value);
    void add(size_t index, const F2Vec128& value);
};

class SemiSecurePerm
{
public:
    mutable BitBuffer A, B, C;
    vector<unsigned> pi;

    SemiSecurePerm()
    {
    }

    SemiSecurePerm(const SemiSecurePerm& other)
    {
        *this = other;
    }

    SemiSecurePerm& operator=(const SemiSecurePerm& other)
    {
        pi = other.pi;
        A = other.A;
        B = other.B;
        C = other.C;
        other.A = {};
        other.B = {};
        other.C = {};
        return *this;
    }
};

template<class T> class RowMatrix;

template<class T>
class Matrix : public vector<vector<T>>
{
public:
    Matrix(size_t n = 0, size_t m = 0)
    {
        this->resize(n);
        for (auto& x : *this)
            x.resize(m);
    }

    template<class U>
    Matrix(const RowMatrix<U>& other);

    vector<T> dot(const vector<T> other) const
    {
        vector<T> res;
        for (auto& row : *this)
        {
            long item = 0;
            assert(row.size() == other.size());
            for (size_t i = 0; i < row.size(); i++)
                item += row[i].get() * other[i].get();
            res.push_back(item % T::p());
        }
        return res;
    }

    vector<T> dot(const BitVector& other) const
    {
        vector<T> tmp;
        for (size_t i = 0; i < other.size(); i++)
            tmp.push_back(other.get_bit(i));
        return dot(tmp);
    }

    void randomize(PRNG& G)
    {
        for (auto& x : *this)
            for (auto& y : x)
                y.randomize(G);
    }
};
template<class T>
class ColMatrix : vector<T>
{
    template<class U> friend class Matrix;
    template<class U> friend class RowMatrix;

public:
    ColMatrix(size_t n = 0, size_t m = 0)
    {
        resize(n, m);
    }

    template<class U>
    ColMatrix(const ColMatrix<U>& other)
    {
        this->reserve(other.size());
        for (size_t i = 0; i < this->size(); i++)
            this->push_back(other.row(i));
    }

    void resize(size_t n, size_t m)
    {
        vector<T>::resize(m);
        for (auto& x : *this)
            x.resize(n);
    }

    bool empty()
    {
        return vector<T>::empty();
    }

    size_t n_rows()
    {
        return this->size();
    }

    T& row(size_t i)
    {
        return this->at(i);
    }

    template<class U>
    T dot(const U& other) const
    {
        assert(other.size() == this->size());
        T res(this->at(0).size());
        auto v = this->begin();
        size_t i = 0;
        for (; i + 7 < this->size(); i += 8)
        {
            auto c = other.eight_from(i);
            for (int j = 0; j < 8; j++)
                res.add_mul(c[j], *v++);
        }
        for (; i < this->size(); i++)
            res.add_mul(other[i], *v++);
        return res;
    }

    void randomize(PRNG& G)
    {
        for (auto& x : *this)
            x.randomize(G);
    }
};

template<class T>
class RowMatrix : T
{
    template<class U> friend class Matrix;
    template<class U> friend class RowMatrix;

    size_t row_storage_size;
    size_t n;

    class ColIterator
    {
        typename T::view_type part;

    public:
        ColIterator(const RowMatrix<T>& whole) : part(whole.col(0))
        {
        }

        void operator++(int)
        {
            part.increment();
        }

        const typename T::view_type& operator*() const
        {
            return part;
        }
    };

public:
    RowMatrix(size_t n = 0, size_t m = 0)
    {
        resize(n, m);
    }

    template<class U>
    RowMatrix(const RowMatrix<U>& other)
    {
        *this = other;
    }

    RowMatrix(const vector<T>& other)
    {
        resize(other.at(0).size(), other.size());
        for (size_t i = 0; i < n_cols(); i++)
            set_col(i, other[i]);
    }

    template<class U>
    RowMatrix(const Matrix<U>& other)
    {
        vector<T> rows;
        rows.reserve(other.size());
        for (auto& row : other)
            rows.push_back(typename T::plain_type(row));
        *this = rows;
        *this = transpose();
    }

    void resize(size_t n, size_t m)
    {
        this->n = n;
        row_storage_size = T(n).storage_size();
        T::resize(row_storage_size * m);
    }

    bool empty()
    {
        return not this->size();
    }

    size_t n_rows() const
    {
        return n;
    }

    size_t n_cols() const
    {
        if (row_storage_size)
            return this->size() / row_storage_size;
        else
            return 0;
    }

    auto col(size_t i) const
    {
        return this->part(i * row_storage_size, n_rows());
    }

    void set_col(size_t i, const typename T::view_type& col)
    {
        assert(col.size() == n_rows());
        this->set_part(i * row_storage_size, col);
    }

    ColIterator begin() const
    {
        return *this;
    }

    template<class U>
    T dot(const U& other) const
    {
        assert(other.size() == n_cols());
        auto res = T::owner_type::zero(n_rows());
        size_t i = 0;
        auto n_cols = this->n_cols();
        auto v = begin();
        for (; i + 7 < n_cols; i += 8)
        {
            auto c = other.eight_from(i);
            for (int j = 0; j < 8; j++)
            {
                res.add_mul(c[j], *v);
                v++;
            }
        }
        for (; i < n_cols; i++)
        {
            res.add_mul(other[i], *v);
            v++;
        }
        return res;
    }

    void randomize(PRNG& G)
    {
        T::randomize(G);
    }

    RowMatrix transpose() const
    {
        return T::transpose(*this);
    }

    T concat() const
    {
        T res;
        res.resize(n_cols());
        res.resize(0);
        for (size_t i = 0; i < n_cols(); i++)
        {
            res.append(col(i));
        }
        return res;
    }
};

template<class T>
template<class U>
Matrix<T>::Matrix(const RowMatrix<U>& other)
{
    this->reserve(other.col(0).size());
    auto tmp = other.transpose();
    assert(tmp.n_cols() == other.col(0).size());
    assert(other.n_cols() == tmp.col(0).size());
    for (size_t i = 0; i < tmp.n_cols(); i++)
    {
        this->push_back(typename U::plain_type(tmp.col(i)));
    }
    assert(this->size() == other.col(0).size());
    assert(this->at(0).size() == other.n_cols());
}

template<class T>
ostream& operator<<(ostream& o, const Matrix<T>& A)
{
    o << "[";
    for (size_t i = 0; i < A.size(); i++)
    {
        for (auto& x : A[i])
            o << x;
        if (i != A.size() - 1)
            o << ",";
    }
    o << "]";
    return o;
}

class SemiSecureShuffleState;
class SemiSecureTripleState;

class SemiSecureShuffle
{
    typedef vector<Bit> bit_vector_type;

    SemiSecureShuffleState* state;
    OTExtensionWithMatrix* rot_ext;

    F3Code A;
    ColMatrix<F2Vec128> B;

    F2Vec128 apply_prf(const BitVector& key, const F3VectorBitWiseView& x);
    vector<F2Vec128> apply_prf(const BitVector& key,
            const RowMatrix<F3VectorBitWise>& x);

public:
    typedef SemiSecurePerm shuffle_type;
    typedef ShuffleStore<shuffle_type> store_type;
    typedef const vector<shuffle_type*> shuffle_gen_type;

    SemiSecureShuffle();
    ~SemiSecureShuffle();

    void generate(size_t n, shuffle_gen_type& perms, bool full = false);
    void full_generate(size_t n, shuffle_gen_type& perms);
    void generate_from_ot(size_t n, shuffle_gen_type& perms, Player& P);

    void apply(StackedVector<SemiSecret>& S, shuffle_type& shuffle,
            const BaseInstruction& instruction);
    void apply_role(StackedVector<SemiSecret>& S,
            ShuffleTuple<shuffle_type>& shuffle, Player& P, int role);
};

} /* namespace GC */

#endif /* GC_SEMISECURESHUFFLE_H_ */
