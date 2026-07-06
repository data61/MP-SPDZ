/*
 * ArgTuples.h
 *
 */

#ifndef GC_ARGTUPLES_H_
#define GC_ARGTUPLES_H_

#include <vector>
using namespace std;

#include "Processor/Instruction.h"

template <class T>
class ArgIter
{
    ArgVector::const_iterator it;
    ArgVector::const_iterator end;

public:
    ArgIter(const ArgVector::const_iterator it,
            const ArgVector::const_iterator end) :
                it(it), end(end)
    {
    }

    T operator*()
    {
        return it;
    }

    ArgIter<T> operator++()
    {
        auto res = it;
        it += T(res).n;
        if (it > end)
            throw runtime_error("wrong number of args");
        return {res, end};
    }

    bool operator!=(const ArgIter<T>& other)
    {
        return it != other.it;
    }
};

template <class T>
class ArgList
{
    const ArgVector& args;

public:
    ArgList(const ArgVector& args) :
            args(args)
    {
    }

    ArgIter<T> begin()
    {
        return {args.begin(), args.end()};
    }

    ArgIter<T> end()
    {
        return {args.end(), args.end()};
    }
};

class InputArgs
{
public:
    static const int n = 4;

    int from;
    ArgVector::value_type& n_bits;
    ArgVector::value_type& n_shift;
    ArgVector::value_type params[2];
    ArgVector::value_type dest;

    InputArgs(ArgVector::const_iterator it) : n_bits(params[0]), n_shift(params[1])
    {
        from = *it++;
        n_bits = *it++;
        n_shift = *it++;
        dest = *it++;
    }
};

template<class T>
class InputArgListBase : public ArgList<T>
{
public:
    InputArgListBase(const ArgVector& args) :
            ArgList<T>(args)
    {
    }

    int n_inputs_from(int from)
    {
        int res = 0;
        for (auto x : *this)
            res += x.from == from;
        return res;
    }

    int n_input_bits()
    {
        int res = 0;
        for (auto x : *this)
            res += x.n_bits;
        return res;
    }

    int n_interactive_inputs_from_me(int my_num);
};

class InputArgList : public InputArgListBase<InputArgs>
{
public:
    InputArgList(const ArgVector& args) :
            InputArgListBase<InputArgs>(args)
    {
    }
};

class InputVecArgs
{
public:
    int from;
    int n;
    ArgVector::value_type& n_bits;
    ArgVector::value_type& n_shift;
    ArgVector::value_type params[2];
    ArgVector dest;

    InputVecArgs(ArgVector::const_iterator it) : n_bits(params[0]), n_shift(params[1])
    {
        n = *it++;
        n_bits = n - 3;
        n_shift = *it++;
        from = *it++;
        dest.resize(n);
        for (size_t i = 0; i < n_bits; i++)
            dest[i] = *it++;
    }
};

class InputVecArgList : public InputArgListBase<InputVecArgs>
{
public:
    InputVecArgList(const ArgVector& args) :
            InputArgListBase<InputVecArgs>(args)
    {
    }
};

#endif /* GC_ARGTUPLES_H_ */
