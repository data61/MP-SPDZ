/*
 * CheckVector.h
 *
 */

#ifndef TOOLS_CHECKVECTOR_H_
#define TOOLS_CHECKVECTOR_H_

#include <vector>
#include <span>
using namespace std;

#include "Math/Integer.h"
#include "Processor/Instruction.h"
#include "Processor/OnlineOptions.h"

template <class T>
class CheckVector : public vector<T>
{
public:
    CheckVector() : vector<T>() {}
    CheckVector(size_t size) : vector<T>(size) {}
    CheckVector(size_t size, const T& def) : vector<T>(size, def) {}
#ifndef NO_CHECK_SIZE
    T& operator[](size_t i) { return this->at(i); }
    const T& operator[](size_t i) const { return this->at(i); }
#else
    T& at(size_t i) { return (*this)[i]; }
    const T& at(size_t i) const { return (*this)[i]; }
#endif
};

template <class T>
class StackedVector : CheckVector<T>
{
    vector<size_t> stack;
    CheckVector<T>& full;
    size_t start, finish;

public:
    typedef typename CheckVector<T>::iterator iterator;

    StackedVector() :
            StackedVector<T>(0)
    {
    }
    StackedVector(size_t size) :
            StackedVector<T>(size, {})
    {
    }
    StackedVector(size_t size, const T& def) :
            CheckVector<T>(size, def), full(*this), start(0), finish(size)
    {
    }

    size_t size() const { return finish - start; }

    void resize(size_t new_size)
    {
        try
        {
            if (OnlineOptions::singleton.has_option("verbose_registers"))
                fprintf(stderr, "adding %zu %s registers to %zu\n", new_size,
                        T::type_string().c_str(), start);
            if (start + new_size > full.size())
                full.resize(start + new_size);
            finish = start + new_size;
        }
        catch (bad_alloc&)
        {
            throw runtime_error(
                    "not enough RAM for " + to_string(start + new_size)
                            + " registers");
        }
    }

    void reserve(size_t new_size) { full.reserve(start + new_size); }

    auto begin() { return full.begin() + start; }
    auto end() { return full.begin() + finish; }
    auto begin() const { return full.begin() + start; }
    auto end() const { return full.begin() + finish; }

    T& operator[](size_t i) { return full[start + i]; }
    const T& operator[](size_t i) const { return full[start + i]; }
    T& at(size_t i) { return full[start + i]; }
    const T& at(size_t i) const { return full[start + i]; }

    void push_back(const T& x)
    {
        if (end() < full.end())
            *end() = x;
        else
            full.push_back(x);
        finish++;
    }

    iterator iterator_for_size(size_t i, size_t size)
    {
        auto res = begin() + i;
        if (res + size > end())
            throw runtime_error("vector too small");
        return res;
    }

    span<T> span_for_size(size_t start, size_t size)
    {
        assert(start + size <= this->size());
        return {begin() + start, begin() + start + size};
    }

    void push_stack()
    {
        stack.push_back(start);
        start = finish;
        finish = start;
    }

    void push_args(const ArgVector& args, RegType type)
    {
        for (auto it = args.begin(); it < args.end(); it += 5)
            if (it[1] == type and not it[0])
            {
                auto dest = begin() + it[3];
                auto source = full.begin() + stack.back() + it[4];
                if (dest + it[2] > end())
                    resize(start + it[1]);
                assert(dest + it[2] <= full.end());
                assert(source + it[2] <= full.begin() + start);
                copy(source, source + it[2], dest);
            }
    }

    void pop_stack(const ArgVector& results, RegType type)
    {
        assert(not stack.empty());

        for (auto it = results.begin(); it < results.end(); it += 5)
            if (it[1] == type and it[0])
            {
                auto source = begin() + it[4];
                auto dest = full.begin() + stack.back() + it[3];
                assert(source + it[2] <= full.end());
                assert(dest + it[2] <= full.begin() + start);
                copy(source, source + it[2], dest);
            }

        finish = start;
        start = stack.back();
        stack.pop_back();
    }

    void check_index(Integer index) const
    {
        assert(size_t(index.get()) < size());
    }
};

#endif /* TOOLS_CHECKVECTOR_H_ */
