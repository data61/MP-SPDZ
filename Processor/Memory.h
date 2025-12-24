#ifndef _Memory
#define _Memory

/* Class to hold global memory of our system */

#include <iostream>
#include <set>
using namespace std;

// Forward declaration as apparently this is needed for friends in templates
template<class T> class Memory;
template<class T> ostream& operator<<(ostream& s,const Memory<T>& M);
template<class T> istream& operator>>(istream& s,Memory<T>& M);

#include "Processor/Program.h"
#include "Tools/CheckVector.h"
#include "Tools/DiskVector.h"

template<class T>
class MemoryPart
{
public:
  virtual ~MemoryPart() {}

  virtual size_t size() const = 0;
  virtual void resize(size_t) = 0;

  virtual T* data() = 0;
  virtual const T* data() const = 0;

  void check_index(size_t i) const
    {
      (void) i;
#ifndef NO_CHECK_INDEX
      if (i >= this->size())
        throw overflow(T::type_string() + " memory", i, this->size());
#endif
    }

  const T* begin() const
    {
      return data();
    }

  const T* end() const
    {
      return data() + size();
    }

  virtual T& operator[](size_t i) = 0;
  virtual const T& operator[](size_t i) const = 0;

  virtual T& at(size_t i) = 0;
  virtual const T& at(size_t i) const = 0;

  template<class U>
  void indirect_read(const Instruction& inst, StackedVector<T>& regs,
      const U& indices);
  template<class U>
  void indirect_write(const Instruction& inst, StackedVector<T>& regs,
      const U& indices);

  void minimum_size(size_t size);
};

template<class T, template<class> class V>
class MemoryPartImpl : public MemoryPart<T>, public V<T>
{
public:
  size_t size() const
    {
      return V<T>::size();
    }

  void resize(size_t size)
    {
      V<T>::resize(size);
    }

  T* data()
    {
      return V<T>::data();
    }

  const T* data() const
    {
      return V<T>::data();
    }

  T& operator[](size_t i)
    {
      this->check_index(i);
      return V<T>::operator[](i);
    }

  const T& operator[](size_t i) const
    {
      this->check_index(i);
      return V<T>::operator[](i);
    }

  T& at(size_t i)
    {
      return V<T>::at(i);
    }

  const T& at(size_t i) const
    {
      return V<T>::at(i);
    }
};

template<class T> 
class Memory
{
  public:

  MemoryPart<T>& MS;
  MemoryPartImpl<typename T::clear, CheckVector> MC;

  Memory();
  ~Memory();

  void resize_s(size_t sz)
    { MS.resize(sz); }
  void resize_c(size_t sz)
    { MC.resize(sz); }

  size_t size_s()
    { return MS.size(); }
  size_t size_c()
    { return MC.size(); }

  const typename T::clear& read_C(size_t i) const
    {
      return MC[i];
    }
  const T& read_S(size_t i) const
    {
      return MS[i];
    }

  void write_C(size_t i,const typename T::clear& x)
    {
      MC[i]=x;
    }
  void write_S(size_t i,const T& x)
    {
      MS[i]=x;
    }

  void minimum_size(RegType secret_type, RegType clear_type,
      const Program& program, const string& threadname);

  friend ostream& operator<< <>(ostream& s,const Memory<T>& M);
  friend istream& operator>> <>(istream& s,Memory<T>& M);
};

#endif

