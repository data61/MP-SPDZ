/*
 * EvalSecret.h
 *
 */

#ifndef GC_SECRET_H_
#define GC_SECRET_H_

#include "GC/config.h"
#include "BMR/config.h"
#include "BMR/common.h"

#include "GC/Clear.h"
#include "GC/Memory.h"
#include "GC/Access.h"
#include "GC/ArgTuples.h"

#include "Math/gf2nlong.h"

#include "Processor/DummyProtocol.h"
#include "Processor/Instruction.h"

#include "Tools/FixedVector.h"

#include <fstream>

class ProcessorBase;
template<class T> class NoProtocol;

namespace GC
{

template<class T>
class Secret;

template <class T>
inline void XOR(T& res, const T& left, const T& right)
{
    res.XOR(left, right);
}

template<class T> class Processor;
template<class T> class Machine;

template <class T>
class Secret
{
#ifdef FIXED_REGISTERS
    typedef FixedVector<T, FIXED_REGISTERS> RegVector;
#else
    typedef CheckVector<T> RegVector;
#endif

    RegVector registers;

    T& get_new_reg();

public:
    typedef T part_type;

    typedef typename T::DynamicMemory DynamicMemory;

    typedef NoShare bit_type;

    typedef typename T::Input Input;

    typedef typename T::out_type out_type;

    typedef int MAC_Check;
    typedef int mac_key_type;
    typedef void DefaultMC;
    typedef void MC;
    typedef NoProtocol<Secret> Protocol;

    static string type_string() { return "evaluation secret"; }
    static string phase_name() { return T::name(); }

    static int default_length;

    static const bool needs_ot = false;

    static const bool is_real = true;

    static const bool actual_inputs = T::actual_inputs;

    static const bool symmetric = true;

    static const bool garbled = T::garbled;

    static false_type is_clear;

    static bool real_shares(const Player&) { return true; }

    static int threshold(int nplayers) { return T::threshold(nplayers); }

    static Secret<T> input(party_id_t from, const int128& input, int n_bits = -1);
    static Secret<T> input(Processor<Secret<T>>& processor, const InputArgs& args);
    void random(int n_bits, int128 share);
    void random_bit();
    template <class U>
    static void store_clear_in_dynamic(U& mem, const vector<ClearWriteAccess>& accesses)
    { T::store_clear_in_dynamic(mem, accesses); }

    template<class U, class V>
    static void load(vector< ReadAccess<V> >& accesses, const U& mem);
    template<class U, class V>
    static void store(U& mem, vector< WriteAccess<V> >& accesses);

    template<class U>
    static void andrs(Processor<U>& processor, const ArgVector& args)
    { T::andrs(processor, args); }
    template<class U>
    static void ands(Processor<U>& processor, const ArgVector& args)
    { T::ands(processor, args); }
    template<class U>
    static void andrsvec(Processor<U>& processor, const ArgVector& args)
    { T::andrsvec(processor, args); }
    template<class U>
    static void xors(Processor<U>& processor, const ArgVector& args)
    { T::xors(processor, args); }
    template<class U>
    static void inputb(Processor<U>& processor, const ArgVector& args)
    { T::inputb(processor, args); }
    template<class U>
    static void inputb(Processor<U>& processor, ProcessorBase& input_proc,
            const ArgVector& args)
    { T::inputb(processor, input_proc, args); }
    template<class U>
    static void inputbvec(Processor<U>& processor, ProcessorBase& input_proc,
            const ArgVector& args)
    { T::inputbvec(processor, input_proc, args); }
    template<class U>
    static void reveal_inst(Processor<U>& processor, const ArgVector& args)
    { T::reveal_inst(processor, args); }

    template<class U>
    static void trans(Processor<U>& processor, int n_inputs, const ArgVector& args);

    template<class U>
    static void convcbit(Integer& dest, const Clear& source,
            Processor<U>& proc)
    { T::convcbit(dest, source, proc); }

    template<class U>
    static void convcbit2s(Processor<U>& processor, const BaseInstruction& instruction)
    { T::convcbit2s(processor, instruction); }
    template<class U>
    static void andm(Processor<U>& processor, const BaseInstruction& instruction)
    { T::andm(processor, instruction); }

    static void run_tapes(const ArgVector& args) { T::run_tapes(args); }

    template<class U>
    static string proto_fake_opts() { return U::fake_opts(); }

    Secret();
    Secret(const Integer& x) { *this = x; }

    void load_clear(int n, const Integer& x);
    void operator=(const Integer& x) { load_clear(default_length, x); }

    Secret<T> operator<<(int i) const;
    Secret<T> operator>>(int i) const;

    template<class U>
    void bitcom(StackedVector<U>& S, const ArgVector& regs);
    template<class U>
    void bitdec(StackedVector<U>& S, const ArgVector& regs) const;

    Secret<T> operator+(const Secret<T>& x) const;
    Secret<T>& operator+=(const Secret<T>& x) { *this = *this + x; return *this; }

    void xor_(int n, const Secret<T>& x, const Secret<T>& y)
    {
        resize_regs(n);
        for (int i = 0; i < n; i++)
            XOR<T>(registers[i], x.get_reg(i), y.get_reg(i));
    }
    void invert(int n, const Secret<T>& x);
    void and_(int n, const Secret<T>& x, const Secret<T>& y, bool repeat);

    template <class U>
    void reveal(size_t n_bits, U& x);

    template <class U>
    void my_input(U& inputter, BitVec value, int n_bits);
    template <class U>
    void other_input(U& inputter, int from, int n_bits);
    template <class U>
    void finalize_input(U& inputter, int from, int n_bits);

    int size() const { return registers.size(); }
    size_t maximum_size() const { return registers.size(); }
    RegVector& get_regs() { return registers; }
    const RegVector& get_regs() const { return registers; }

    const T& get_reg(int i) const { return registers.at(i); }
    T& get_reg(int i) { return registers.at(i); }
    void resize_regs(size_t n);
};

template <class T>
int Secret<T>::default_length = 64;

template <class T>
false_type Secret<T>::is_clear;

template <class T>
inline ostream& operator<<(ostream& o, const Secret<T>& secret)
{
	o << "(";
	for (int i = 0; i < secret.size(); i++)
	{
	    o << secret.get_reg(i);
	    if (i != secret.size() - 1)
	        o << ", ";
	}
	o << ")";
	return o;
}

} /* namespace GC */

#endif /* GC_SECRET_H_ */
