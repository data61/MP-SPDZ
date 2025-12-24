/*
 * TruncPrTuple.h
 *
 */

#ifndef PROCESSOR_TRUNCPRTUPLE_H_
#define PROCESSOR_TRUNCPRTUPLE_H_

#include <vector>
#include <assert.h>
using namespace std;

#include "OnlineOptions.h"
#include "BaseMachine.h"
#include "GC/ArgTuples.h"

template<class T> class StackedVector;

void trunc_pr_check(int k, int m, int n_bits);

template<class T>
class Range
{
    typename T::iterator begin_, end_;

public:
    Range(T& whole, size_t start, size_t length)
    {
        begin_ = whole.begin() + start;
        end_ = begin_ + length;
        assert(end_ <= whole.end());
    }

    typename T::iterator begin()
    {
        return begin_;
    }

    typename T::iterator end()
    {
        return end_;
    }
};

template<class T>
class TruncPrTuple
{
public:
    const static int n = 4;

    int dest_base;
    int source_base;
    int k;
    int m;
    int n_shift;

    TruncPrTuple(const vector<int>& regs, size_t base) :
            TruncPrTuple(regs.begin() + base)
    {
    }

    TruncPrTuple(vector<int>::const_iterator it)
    {
        dest_base = *it++;
        source_base = *it++;
        k = *it++;
        m = *it++;
        n_shift = T::N_BITS - 1 - k;
        trunc_pr_check(k, m, T::n_bits());
        assert(m < k);
        assert(0 < k);
        assert(m < T::n_bits());
    }

    T upper(T mask)
    {
        return (mask.cheap_lshift(n_shift + 1)) >> (n_shift + m + 1);
    }

    T msb(T mask)
    {
        return (mask.cheap_lshift(n_shift)) >> (T::N_BITS - 1);
    }

    T add_before()
    {
        return T(1).cheap_lshift(k - 1);
    }

    T subtract_after()
    {
        return T(1).cheap_lshift(k - m - 1);
    }
};

template<class T>
class TruncPrTupleWithGap : public TruncPrTuple<T>
{
    bool big_gap_;

public:
    TruncPrTupleWithGap(const vector<int>& regs, size_t base) :
            TruncPrTupleWithGap<T>(regs.begin() + base)
    {
    }

    TruncPrTupleWithGap(vector<int>::const_iterator it) :
            TruncPrTuple<T>(it)
    {
        int min_size = this->k + OnlineOptions::singleton.trunc_error;
        big_gap_ = min_size <= T::n_bits();
        if (T::prime_field and small_gap())
            throw runtime_error("domain too small for chosen truncation error");
        if (small_gap() and BaseMachine::has_singleton())
            BaseMachine::s().gap_warning(min_size);
    }

    T upper(T mask)
    {
        if (big_gap())
            return mask.signed_rshift(this->m);
        else
            return TruncPrTuple<T>::upper(mask);
    }

    T msb(T mask)
    {
        assert(not big_gap());
        return TruncPrTuple<T>::msb(mask);
    }

    bool big_gap()
    {
        return big_gap_;
    }

    bool small_gap()
    {
        return not big_gap();
    }
};

template<class T>
class TruncPrTupleWithRange : public TruncPrTupleWithGap<typename T::open_type>
{
    typedef TruncPrTupleWithGap<typename T::open_type> super;

public:
    Range<StackedVector<T>> source_range, dest_range;

    TruncPrTupleWithRange(super info, StackedVector<T>& S, size_t size) :
            super(info), source_range(S, info.source_base, size),
            dest_range(S, info.dest_base, size)
    {
    }

    template<class U>
    U correction_shift(U bit)
    {
        return bit.cheap_lshift(T::open_type::N_BITS - this->m);
    }
};

template<class T>
class TruncPrTupleList : public vector<TruncPrTupleWithRange<T>>
{
    typedef TruncPrTupleWithGap<T> part_type;
    typedef TruncPrTupleList This;

public:
    TruncPrTupleList(const vector<int>& args, StackedVector<T>& S, size_t size)
    {
        ArgList<TruncPrTupleWithGap<typename T::open_type>> tmp(args);
        for (auto x : tmp)
            this->push_back(TruncPrTupleWithRange<T>(x, S, size));
    }

    TruncPrTupleList()
    {
    }

    bool have_big_gap()
    {
        for (auto info : *this)
            if (info.big_gap())
                return true;
        return false;
    }

    bool have_small_gap()
    {
        for (auto info : *this)
            if (info.small_gap())
                return true;
        return false;
    }

    This get_big_gap()
    {
        This res;
        for (auto info : *this)
            if (info.big_gap())
                res.push_back(info);
        return res;
    }

    This get_small_gap()
    {
        This res;
        for (auto info : *this)
            if (info.small_gap())
                res.push_back(info);
        return res;
    }
};

#endif /* PROCESSOR_TRUNCPRTUPLE_H_ */
