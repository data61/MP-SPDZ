/*
 * ShareMatrix.h
 *
 */

#ifndef PROTOCOLS_SHAREMATRIX_H_
#define PROTOCOLS_SHAREMATRIX_H_

#include <vector>
using namespace std;

#include "Share.h"
#include "FHE/AddableVector.h"

template<class T> class MatrixMC;

template<class T>
class NonInitVector
{
    template<class U> friend class NonInitVector;

    size_t size_;
public:
    AddableVector<T> v;

    NonInitVector(size_t size) :
            size_(size)
    {
        v.reserve(size);
    }

    template<class U>
    NonInitVector(const NonInitVector<U>& other) :
            size_(other.size()), v(other.v)
    {
    }

    size_t size() const
    {
        return size_;
    }

    void init()
    {
        v.resize(size_);
    }

    void check() const
    {
#ifdef DEBUG_MATRIX
        assert(not v.empty());
#endif
    }

    typename vector<T>::iterator begin()
    {
        check();
        return v.begin();
    }

    typename vector<T>::iterator end()
    {
        check();
        return v.end();
    }

    T& at(size_t index)
    {
        check();
        return v.at(index);
    }

    const T& at(size_t index) const
    {
#ifdef DEBUG_MATRIX
        assert(index < size());
#endif
        return (*this)[index];
    }

    T& operator[](size_t index)
    {
        check();
        return v[index];
    }

    const T& operator[](size_t index) const
    {
        check();
        return v[index];
    }

    NonInitVector operator-(const NonInitVector& other) const
    {
        assert(size() == other.size());
        NonInitVector res(size());
        if (other.v.empty())
            return *this;
        else if (v.empty())
        {
            res.init();
            res.v = res.v - other.v;
        }
        else
            res.v = v - other.v;
        return res;
    }

    NonInitVector& operator+=(const NonInitVector& other)
    {
        assert(size() == other.size());
        if (not other.v.empty())
        {
            if (v.empty())
                *this = other;
            else
                v += other.v;
        }
        return *this;
    }

    bool operator!=(const NonInitVector& other) const
    {
        return v != other.v;
    }

    void randomize(PRNG& G)
    {
        v.clear();
        for (size_t i = 0; i < size(); i++)
            v.push_back(G.get<T>());
    }
};

template<class T>
class ValueMatrix : public ValueInterface
{
    typedef ValueMatrix This;

public:
    int n_rows, n_cols;
    NonInitVector<T> entries;

    static DataFieldType field_type()
    {
        return T::field_type();
    }

    ValueMatrix(int n_rows = 0, int n_cols = 0) :
            n_rows(n_rows), n_cols(n_cols), entries(n_rows * n_cols)
    {
        check();
    }

    template<class U>
    ValueMatrix(const ValueMatrix<U>& other) :
            n_rows(other.n_rows), n_cols(other.n_cols), entries(other.entries)
    {
        check();
    }

    void check() const
    {
        assert(entries.size() == size_t(n_rows * n_cols));
    }

    T& operator[](const pair<int, int>& indices)
    {
#ifdef DEBUG_MATRIX
        assert(indices.first < n_rows);
        assert(indices.second < n_cols);
#endif
        return entries.at(indices.first * n_cols + indices.second);
    }

    const T& operator[](const pair<int, int>& indices) const
    {
#ifdef DEBUG_MATRIX
        assert(indices.first < n_rows);
        assert(indices.second < n_cols);
#endif
        return entries.at(indices.first * n_cols + indices.second);
    }

    This& operator+=(const This& other)
    {
        entries += other.entries;
        check();
        return *this;
    }

    This operator-(const This& other) const
    {
        assert(entries.size() == other.entries.size());
        This res(n_rows, n_cols);
        res.entries = entries - other.entries;
        res.check();
        return res;
    }

    This operator*(const This& other) const
    {
        This res;
        res.mul(*this, other);
        return res;
    }

    template<class U, class V>
    void mul(const ValueMatrix<U>& a, const ValueMatrix<V>& b)
    {
        assert(a.n_cols == b.n_rows);
        auto& res = *this;
        res = {a.n_rows, b.n_cols};
        if (a.entries.v.empty() or b.entries.v.empty())
            return;
        res.entries.init();
        for (int i = 0; i < a.n_rows; i++)
        {
            for (int j = 0; j < b.n_cols; j++)
                for (int k = 0; k < a.n_cols; k++)
                    res[{i, j}] += a[{i, k}] * b[{k, j}];
        }
        res.check();
    }

    bool operator!=(const This& other) const
    {
        if (n_rows != other.n_rows or n_cols != other.n_cols)
            return true;
        return entries != other.entries;
    }

    void randomize(PRNG& G)
    {
        entries.randomize(G);
    }

    ValueMatrix transpose() const
    {
        ValueMatrix res(this->n_cols, this->n_rows);
        for (int j = 0; j < this->n_cols; j++)
            for (int i = 0; i < this->n_rows; i++)
                res.entries.v.push_back((*this)[{i, j}]);
        return res;
    }

    void input(istream& is)
    {
        entries.init();
        for (auto& x: entries)
            x.input(is, false);
    }

    friend ostream& operator<<(ostream& o, const This&)
    {
        return o;
    }
};

template<class T>
class ShareMatrix : public ValueMatrix<T>, public ShareInterface
{
    typedef ShareMatrix This;
    typedef ValueMatrix<T> super;

public:
    typedef MatrixMC<T> MAC_Check;
    typedef Beaver<ShareMatrix> Protocol;
    typedef ::Input<This> Input;
    typedef DummyLivePrep<T> LivePrep;

    typedef ValueMatrix<typename T::clear> clear;
    typedef ValueMatrix<typename T::open_type> open_type;
    typedef typename T::mac_key_type mac_key_type;

    static string type_string()
    {
        return "matrix";
    }

    static This constant(const clear& other, int my_num, mac_key_type key)
    {
        This res(other.n_rows, other.n_cols);
        if (not other.entries.v.empty())
        {
            other.check();
            for (size_t i = 0; i < other.entries.size(); i++)
                res.entries.v.push_back(T::constant(other.entries[i], my_num, key));
            res.check();
        }
        return res;
    }

    ShareMatrix(int n_rows = 0, int n_cols = 0) :
            ValueMatrix<T>(n_rows, n_cols)
    {
    }

    template<class U>
    ShareMatrix(const U& other) :
        super(other)
    {
    }

    ShareMatrix from_row(int start, int size) const
    {
        ShareMatrix res(min(size, this->n_rows - start), this->n_cols);
        for (int i = 0; i < res.n_rows; i++)
            for (int j = 0; j < res.n_cols; j++)
                res[{i, j}] = (*this)[{start + i, j}];
        return res;
    }

    ShareMatrix from_col(int start, int size) const
    {
        ShareMatrix res(this->n_rows, min(size, this->n_cols - start));
        res.entries.clear();
        for (int i = 0; i < res.n_rows; i++)
            for (int j = 0; j < res.n_cols; j++)
                res.entries.v.push_back((*this)[{i, start + j}]);
        return res;
    }

    ShareMatrix from(int start_row, int start_col, int* sizes, bool for_real =
            true) const
    {
        ShareMatrix res(min(sizes[0], this->n_rows - start_row),
                min(sizes[1], this->n_cols - start_col));
        if (not for_real)
            return res;
        for (int i = 0; i < res.n_rows; i++)
            for (int j = 0; j < res.n_cols; j++)
                res.entries.v.push_back((*this)[{start_row + i, start_col + j}]);
        return res;
    }

    void add_from_col(int start, const ShareMatrix& other)
    {
        this->entries.init();
        for (int i = 0; i < this->n_rows; i++)
            for (int j = 0; j < other.n_cols; j++)
                (*this)[{i, start + j}] += other[{i, j}];
    }
};

template<class T>
ShareMatrix<T> operator*(const typename ShareMatrix<T>::open_type& a,
        const ShareMatrix<T>& b)
{
    ShareMatrix<T> res;
    res.mul(a, b);
    return res;
}

template<class T>
ShareMatrix<T> operator*(const ShareMatrix<T>& b,
        const ValueMatrix<typename T::clear>& a)
{
    ShareMatrix<T> res;
    res.mul(b, a);
    return res;
}

template<class T>
class MatrixMC : public MAC_Check_Base<ShareMatrix<T>>
{
    friend class Hemi<T>;

    typename T::MAC_Check& inner;

public:
    MatrixMC(typename T::MAC_Check& inner) :
            MAC_Check_Base<ShareMatrix<T>>(inner.get_alphai()), inner(inner)
    {
    }

    ~MatrixMC()
    {
    }

    void exchange(const Player& P)
    {
        inner.init_open(P);
        for (auto& share : this->secrets)
        {
            share.check();
            for (auto& entry : share.entries)
                inner.prepare_open(entry);
        }
        inner.exchange(P);
        for (auto& share : this->secrets)
        {
            this->values.push_back({share.n_rows, share.n_cols});
            if (share.entries.v.empty())
                for (size_t i = 0; i < share.entries.size(); i++)
                    inner.finalize_open();
            else
            {
                auto range = inner.finalize_several(share.entries.size());
                auto& v = this->values.back().entries.v;
                v.insert(v.begin(), range[0], range[1]);
            }
        }
    }
};

#endif /* PROTOCOLS_SHAREMATRIX_H_ */
