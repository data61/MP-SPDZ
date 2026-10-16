/*
 * Processor.cpp
 *
 */

#ifndef GC_PROCESSOR_HPP_
#define GC_PROCESSOR_HPP_

#include <GC/Processor.h>

#include <iostream>
#include <iomanip>
using namespace std;

#include "GC/Program.h"
#include "Access.h"
#include "Processor/FixInput.h"
#include "Math/BitVec.h"

#include "GC/Machine.hpp"
#include "GC/ShareSecret.hpp"
#include "Processor/Processor.hpp"
#include "Processor/IntInput.hpp"
#include "Math/bigint.hpp"

namespace GC
{

template <class T>
Processor<T>::Processor(Machine<T>& machine) :
		Processor<T>(machine, &machine)
{
}

template <class T>
Processor<T>::Processor(Memories<T>& memories, Machine<T>* machine) :
		machine(machine), memories(memories), PC(0), last_PC(0), time(0),
		complexity(0)
{
}

template<class T>
Processor<T>::~Processor()
{
#ifdef VERBOSE
    if (xor_timer.elapsed() > 0)
        cerr << "XOR time: " << xor_timer.elapsed() << endl;
    if (time > 0)
        cerr << "Finished after " << time << " instructions" << endl;
#endif
}

template <class T>
template <class U>
void Processor<T>::reset(const U& program, int arg)
{
    S.resize(program.num_reg(SBIT));
    C.resize(program.num_reg(CBIT));
    I.resize(program.num_reg(INT));
    set_arg(arg);
    PC = 0;
}

template <class T>
template <class U>
void Processor<T>::reset(const U& program)
{
    reset(program, 0);
    if (machine)
        machine->reset(program);
    memories.reset(program);
}

template<class T>
inline long long GC::Processor<T>::get_input(const ArgVector::value_type* params, bool interactive)
{
    assert(params[0] <= 64);
    return get_long_input<Integer>(params, *this, interactive).get();
}

template<class T>
template<class U>
U GC::Processor<T>::get_long_input(const ArgVector::value_type* params,
        ProcessorBase& input_proc, bool interactive)
{
    if (not T::actual_inputs)
        return {};
    U res;
    if (params[1] == 0)
        res = input_proc.get_input<IntInput<U>>(interactive, 0).items[0];
    else
        res = input_proc.get_input<FixInput_<U>>(interactive,
                &params[1]).items[0];
    check_input(res, params);
    return res;
}

template<class T>
template<class U>
void GC::Processor<T>::check_input(const U& in, const ArgVector::value_type* params)
{
	int n_bits = *params;
	auto test = in >> n_bits;
	if (n_bits == 1)
	{
		if (not (in == 0 or in == 1))
			throw runtime_error("input not a bit: " + to_string(in));
	}
	else if (not (test == 0 or test == -1))
	{
		if (params[1] == 0)
			throw runtime_error(
					"input out of range for a " + std::to_string(n_bits)
							+ "-bit (un)signed integer: " + to_string(in));
		else
			throw runtime_error(
					"input out of range for a " + to_string(n_bits)
							+ "-bit fixed-point number with "
							+ to_string(params[1]) + "-bit precision: "
							+ to_string(
									mpf_class(bigint(in)) * exp2(-params[1])));
	}
}

template <class T>
void Processor<T>::bitdecc(const ArgVector& regs, const Clear& x)
{
    for (unsigned int i = 0; i < regs.size(); i++)
        C[regs[i]] = (x >> i) & 1;
}

template <class T>
void Processor<T>::bitdecint(const ArgVector& regs, const Integer& x)
{
    for (unsigned int i = 0; i < regs.size(); i++)
        I[regs[i]] = (x >> i) & 1;
}

template<class T>
template<class U>
void Processor<T>::load_dynamic_direct(const ArgVector& args,
        U& dynamic_memory)
{
    vector< ReadAccess<T> > accesses;
    if (args.size() % 3 != 0)
        throw runtime_error("invalid number of arguments");
    for (size_t i = 0; i < args.size(); i += 3)
        accesses.push_back({S[args[i]], args[i+1], args[i+2], complexity});
    T::load(accesses, dynamic_memory);
}

template<class T>
template<class U>
void GC::Processor<T>::load_dynamic_indirect(const ArgVector& args,
        U& dynamic_memory)
{
    vector< ReadAccess<T> > accesses;
    if (args.size() % 3 != 0)
        throw runtime_error("invalid number of arguments");
    for (size_t i = 0; i < args.size(); i += 3)
        accesses.push_back({S[args[i]], C[args[i+1]], args[i+2], complexity});
    T::load(accesses, dynamic_memory);
}

template<class T>
template<class U>
void GC::Processor<T>::store_dynamic_direct(const ArgVector& args,
        U& dynamic_memory)
{
    vector< WriteAccess<T> > accesses;
    if (args.size() % 2 != 0)
        throw runtime_error("invalid number of arguments");
    for (size_t i = 0; i < args.size(); i += 2)
        accesses.push_back({args[i+1], S[args[i]]});
    T::store(dynamic_memory, accesses);
    complexity += accesses.size() / 2 * T::default_length;
}

template<class T>
template<class U>
void GC::Processor<T>::store_dynamic_indirect(const ArgVector& args,
        U& dynamic_memory)
{
    vector< WriteAccess<T> > accesses;
    if (args.size() % 2 != 0)
        throw runtime_error("invalid number of arguments");
    for (size_t i = 0; i < args.size(); i += 2)
        accesses.push_back({C[args[i+1]], S[args[i]]});
    T::store(dynamic_memory, accesses);
    complexity += accesses.size() / 2 * T::default_length;
}

template<class T>
template<class U>
void GC::Processor<T>::store_clear_in_dynamic(const ArgVector& args,
        U& dynamic_memory)
{
    vector<ClearWriteAccess> accesses;
	check_args(args, 2);
    for (size_t i = 0; i < args.size(); i += 2)
    	accesses.push_back({C[args[i+1]], C[args[i]]});
    T::store_clear_in_dynamic(dynamic_memory, accesses);
}

template<class T>
template<class U, class V>
void Processor<T>::mem_op(int n, U& dest, const V& source,
        Integer dest_address, Integer source_address)
{
    dest.check_index(dest_address + n - 1);
    source.check_index(source_address + n - 1);
    auto d = &dest[dest_address.get()];
    auto s = &source[source_address.get()];
    for (int i = 0; i < n; i++)
    {
        *d++ = *s++;
    }
}

template<class T>
template<class U, class V>
void Processor<T>::indirect_mem_load(U& dest, const V& source,
        const StackedVector<Integer>& Ci, const BaseInstruction& instruction)
{
    size_t n = instruction.get_size();
    size_t dest_address = instruction.get_r(0);
    size_t source_address = instruction.get_r(1);
    dest.check_index(dest_address + n - 1);
    Ci.check_index(source_address + n - 1);
    auto d = &dest[dest_address];
    auto s = &Ci[source_address];
    for (size_t i = 0; i < n; i++)
    {
        *d++ = source.at((*s++).get());
    }
}

template<class T>
template<class U, class V>
void Processor<T>::indirect_mem_store(U& dest, const V& source,
        const StackedVector<Integer>& Ci, const BaseInstruction& instruction)
{
    size_t n = instruction.get_size();
    size_t dest_address = instruction.get_r(1);
    size_t source_address = instruction.get_r(0);
    Ci.check_index(dest_address + n - 1);
    source.check_index(source_address + n - 1);
    auto d = &Ci[dest_address];
    auto s = &source[source_address];
    for (size_t i = 0; i < n; i++)
    {
        dest.at((*d++).get()) = *s++;
    }
}

template <class T>
void Processor<T>::xors(const ArgVector& args)
{
	xors(args, 0, args.size());
}

template <class T>
void Processor<T>::xors(const ArgVector& args, size_t start, size_t end)
{
    assert(start % 4 == 0);
    assert(end % 4 == 0);
    assert(start < end);
    assert(args.begin() + end <= args.end());
    unsigned dl = T::default_length;
    for (auto it = args.begin() + start; it < args.begin() + end; it += 4)
    {
        if (*it == 1)
            S[*(it + 1)].xor_(1, S[*(it + 2)], S[*(it + 3)]);
        else
        {
            int n_units = DIV_CEIL(*it, dl);
            for (int j = 0; j < n_units; j++)
            {
                int left = min(dl, *it - j * dl);
                S[*(it + 1) + j].xor_(left, S[*(it + 2) + j],
                        S[*(it + 3) + j]);
            }
        }
    }
}

template<class T>
void Processor<T>::xorc(const ::BaseInstruction& instruction)
{
    int total = instruction.get_n();
    for (int i = 0; i < DIV_CEIL(total, T::default_length); i++)
    {
        int n = min(T::default_length, total - i * T::default_length);
        C[instruction.get_r(0) + i] = BitVec(C[instruction.get_r(1) + i]).mask(n)
                ^ BitVec(C[instruction.get_r(2) + i]).mask(n);
    }
}

template<class T>
void Processor<T>::nots(const ::BaseInstruction& instruction)
{
    int total = instruction.get_n();
    for (int i = 0; i < DIV_CEIL(total, T::default_length); i++)
    {
        int n = min(T::default_length, total - i * T::default_length);
        S[instruction.get_r(0) + i].invert(n, S[instruction.get_r(1) + i]);
    }
}

template<class T>
void Processor<T>::notcb(const ::BaseInstruction& instruction)
{
    int total = instruction.get_n();
    int unit = Clear::N_BITS;
    for (int i = 0; i < DIV_CEIL(total, unit); i++)
    {
        int n = min(unit, total - i * unit);
        C[instruction.get_r(0) + i] =
                Clear(~C[instruction.get_r(1) + i].get()).mask(n);
    }
}

template<class T>
void Processor<T>::movsb(const ::BaseInstruction& instruction)
{
    int n_blocks;
    if (instruction.get_n() < unsigned(T::default_length))
        n_blocks = 1;
    else
        n_blocks = DIV_CEIL(instruction.get_n(), T::default_length);
    for (int i = 0; i < n_blocks; i++)
        S[instruction.get_r(0) + i] = S[instruction.get_r(1) + i];
}

template<class T>
void Processor<T>::andm(const ::BaseInstruction& instruction)
{
    for (int i = 0; i < DIV_CEIL(instruction.get_n(), T::default_length); i++)
        S[instruction.get_r(0) + i] = S[instruction.get_r(1) + i]
                & C[instruction.get_r(2) + i];
}

template <class T>
void Processor<T>::and_(const ArgVector& args, bool repeat)
{
    check_args(args, 4);
    for (size_t i = 0; i < args.size(); i += 4)
    {
        for (int j = 0; j < DIV_CEIL(args[i], T::default_length); j++)
        {
            int n = min(T::default_length,
                    int(args[i]) - j * T::default_length);
            S[args[i + 1] + j].and_(n, S[args[i + 2] + j],
                    S[args[i + 3] + (repeat ? 0 : j)], repeat);
        }
        complexity += args[i];
    }
}

template <class T>
void Processor<T>::andrsvec(const ArgVector& args)
{
    int N_BITS = T::default_length;
    auto it = args.begin();
    while (it < args.end())
    {
        int n_args = (*it++ - 3) / 2;
        int size = *it++;
        int base = *(it + n_args);
        for (int i = 0; i < size; i += 1)
        {
            if (i % N_BITS == 0)
                for (int j = 0; j < n_args; j++)
                    S.at(*(it + j) + i / N_BITS).resize_regs(
                            min(N_BITS, size - i));

            T y;
            y.get_regs().push_back(S.at(base + i / N_BITS).get_reg(i % N_BITS));
            for (int j = 0; j < n_args; j++)
            {
                T x, tmp;
                x.get_regs().push_back(
                        S.at(*(it + n_args + 1 + j) + i / N_BITS).get_reg(
                                i % N_BITS));
                tmp.and_(1, x, y, false);
                S.at(*(it + j) + i / N_BITS).get_reg(i % N_BITS) = tmp.get_reg(0);
            }
        }
        it += 2 * n_args + 1;
    }
}

template <class T>
void Processor<T>::input(const ArgVector& args)
{
    InputArgList a(args);
    for (auto x : a)
    {
        S[x.dest] = T::input(*this, x);
#ifdef DEBUG_INPUT
        cout << "input to " << args[i+2] << "/" << &S[args[i+2]] << endl;
#endif
    }
}

template <class T>
void Processor<T>::reveal(const ArgVector& args)
{
    for (size_t j = 0; j < args.size(); j += 3)
    {
        int n = args[j];
        int r0 = args[j + 1];
        int r1 = args[j + 2];
        if (n > max(T::default_length, Clear::N_BITS))
            assert(T::default_length == Clear::N_BITS);
        for (int i = 0; i < DIV_CEIL(n, T::default_length); i++)
            S[r1 + i].reveal(min(Clear::N_BITS, n - i * Clear::N_BITS),
                    C[r0 + i]);
    }
}

template <class T>
template <int>
void Processor<T>::convcbit2s(const BaseInstruction& instruction)
{
    int unit = GC::Clear::N_BITS;
    auto& share_thread = ShareThread<T>::s();
    for (int i = 0; i < DIV_CEIL(instruction.get_n(), unit); i++)
        S[instruction.get_r(0) + i] = T::constant(C[instruction.get_r(1) + i],
                share_thread.P->my_num(), share_thread.MC->get_alphai(),
                min(size_t(unit), instruction.get_n() - i * unit));
}

template<class T>
void Processor<T>::convcbitvec(const BaseInstruction& instruction,
        StackedVector<Integer>& Ci, Player* P)
{
    vector<Integer> bits;
    auto n = instruction.get_n();
    bits.reserve(n);
    for (size_t i = 0; i < instruction.get_n(); i++)
    {
        int i1 = i / GC::Clear::N_BITS;
        int i2 = i % GC::Clear::N_BITS;
        auto bit = C[instruction.get_r(1) + i1].get_bit(i2);
        bits.push_back(bit);
    }

    if (instruction.get_r(2))
        T::sync(bits, P);
    assert(bits.size() == n);

    auto dest = Ci.iterator_for_size(instruction.get_r(0), n);
    for (auto& bit : bits)
        *dest++ = bit;
}

template<class T>
void Processor<T>::convcbit(const BaseInstruction& instruction,
        StackedVector<Integer>& Ci, Player* P)
{
    vector<Integer> values;
    size_t n = instruction.get_size();
    values.reserve(n);
    auto it = C.iterator_for_size(instruction.get_r(1), n);
    for (size_t i = 0; i < n; i++)
        values.push_back(*it++);

    T::sync(values, P);
    assert(values.size() == n);

    auto dest = Ci.iterator_for_size(instruction.get_r(0), n);
    for (auto& value : values)
        *dest++ = value;
}

template<class T>
void ShareSecret<T>::sync(vector<Integer>& values, Player* P)
{
    try
    {
        auto proto = ShareThread<T>::s().protocol;
        auto P = ShareThread<T>::s().P;
        if (proto)
            proto->sync(values, *P);
        else
            throw no_singleton();
    }
    catch (no_singleton&)
    {
        if (P)
            ProtocolBase<T>::sync(values, *P);
        else if (not T::symmetric)
            ProtocolBase<T>::sync(values, *Thread<T>::s().P);
    }
}

template <class T>
void Processor<T>::print_reg(int reg, int n, int size)
{
#ifdef DEBUG_VALUES
    cout << "print_reg " << typeid(T).name() << " " << reg << " " << &C[reg] << endl;
#endif
    out << "Reg[" << reg << "] = 0x" << hex << noshowbase;
    for (int i = 0; i < size; i++)
    {
        out.fill('0');
        out.width(16);
        out << (unsigned long)C[reg + size - 1 - i].get();
    }
    out << dec << " # ";
    print_str(n);
    out << endl << flush;
}

template <class T>
template <class U>
void Processor<T>::print_reg_plain(U& value)
{
    out << hex << showbase << value << dec << flush;
}

template <class T>
void Processor<T>::print_reg_signed(unsigned n_bits, Integer reg)
{
    if (n_bits <= Clear::N_BITS)
    {
        auto value = C[reg.get()];
        unsigned n_shift = 0;
        if (n_bits > 1)
            n_shift = sizeof(value.get()) * 8 - n_bits;
        if (n_shift > 63)
            n_shift = 0;
        out << dec << (value.get() << n_shift >> n_shift) << flush;
    }
    else
    {
        bigint tmp = 0;
        for (int i = 0; i < DIV_CEIL(n_bits, Clear::N_BITS); i++)
        {
            tmp += bigint((unsigned long)C[reg + i].get()) << (i * Clear::N_BITS);
        }
        if (tmp >= bigint(1) << (n_bits - 1))
            tmp -= bigint(1) << n_bits;
        out << dec << tmp << flush;
    }
}

template <class T>
void Processor<T>::print_chr(int n)
{
    out << (char)n << flush;
}

template <class T>
void Processor<T>::print_str(int n)
{
    out << string((char*)&n,sizeof(n)) << flush;
}

template <class T>
void Processor<T>::print_float(const ArgVector& args)
{
    bigint::output_float(out,
            bigint::get_float(C[args[0]], C[args[1]], C[args[2]], C[args[3]]),
            C[args[4]]);
}

template <class T>
void Processor<T>::print_float_prec(int n)
{
    out << setprecision(n);
}

template<class T>
void Processor<T>::incint(const BaseInstruction& instruction)
{
    auto dest = &I[instruction.get_r(0)];
    auto base = I[instruction.get_r(1)];
    auto& start = instruction.get_start();
    for (int i = 0; i < instruction.get_size(); i++)
    {
        int inc = (i / start[0]) % start[1];
        *dest++ = base + inc * int(instruction.get_n());
    }
}

template<class T>
void GC::Processor<T>::push_stack()
{
    S.push_stack();
    C.push_stack();
}

template<class T>
void GC::Processor<T>::push_args(const ArgVector& args)
{
    S.push_args(args, SBIT);
    C.push_args(args, CBIT);
}

template<class T>
void GC::Processor<T>::pop_stack(const ArgVector& results)
{
    S.pop_stack(results, SBIT);
    C.pop_stack(results, CBIT);
}

template<class T>
template<class U>
void Processor<T>::call_tape(const BaseInstruction& instruction, U& dynamic_memory)
{
    if (T::garbled)
        throw runtime_error(
                "calling tapes not supported with garbled circuits, "
                        "compile with '--garbled'");

    auto new_arg = I.at(instruction.get_r(1)).get();

    PC_stack.push_back(PC);
    arg_stack.push_back(this->arg);
    push_stack();
    I.push_stack();

    auto& tape = machine->progs.at(instruction.get_r(0));
    reset(tape, new_arg);

    auto& args = instruction.get_start();
    push_args(args);
    I.push_args(args, INT);

    tape.execute(*this, dynamic_memory, PC);

    pop_stack(args);
    I.pop_stack(args, INT);

    PC = PC_stack.back();
    PC_stack.pop_back();
    this->arg = arg_stack.back();
    arg_stack.pop_back();
}

template<class T>
void GC::Processor<T>::generate_secure_shuffle(
        const BaseInstruction& instruction, StackedVector<Integer>& Ci)
{
    size_t n = instruction.get_n();
    vector<typename T::Shuffler::shuffle_type*> shuffles;
    for (int i = 0; i < instruction.get_size(); i++)
    {
        auto res = memories.shuffle_store.add(n);
        Ci[instruction.get_r(0) + i] = res;
        shuffles.push_back(&memories.shuffle_store.get(res).second);
    }
    shuffler.generate(n, shuffles, instruction.get_r(1));
}

template<class T>
void GC::Processor<T>::apply_shuffle(int handle,
        const BaseInstruction& instruction)
{
    if (shuffle_store.find(handle) == shuffle_store.end())
        shuffle_store[handle] = memories.shuffle_store.get(handle).second;
    shuffler.apply(S, shuffle_store.at(handle), instruction);
}

template<class T>
void GC::Processor<T>::delete_shuffle(int handle)
{
    memories.shuffle_store.del(handle);
}

template<class T>
void Processor<T>::concats(const BaseInstruction& instruction)
{
    auto dest = S.begin() + instruction.get_r(0);
    auto& args = instruction.get_start();
    int dl = T::default_length;
    int base = 0;
    for (auto it = args.begin(); it < args.end(); it++)
    {
        int n = *it++;
        auto source = S.begin() + *it;
        assert(source < S.end());
        for (int i = 0; i < n; i += dl)
        {
            assert(source < S.end());
            int left = min(n - i, dl);
            T tmp = source->mask(left);
            if (base % dl == 0)
            {
                assert(dest < S.end());
                *dest = T();
            }
            int free = dl - (base % dl);
            *dest ^= tmp.mask(free) << (base % dl);
            int now_left = left - free;
            base = base + left - max(0, now_left);
            if (now_left >= 0)
            {
                dest++;
            }
            if (now_left > 0)
            {
                assert(dest < S.end());
                *dest = T();
                *dest ^= tmp >> (left - now_left);
                base += now_left;
            }
            source++;
        }
    }
}

template<class T>
void Processor<T>::picks(const BaseInstruction& instruction)
{
    auto& args = instruction.get_start();
    assert(args.size() == 4);
    auto dest = S.begin() + args[0];
    auto source = S.begin() + args[1] + args[2];
    auto skip = args[3];
    size_t size = instruction.get_size();
    assert(dest + size <= S.end());
    assert(source + size * skip <= S.end());
    for (size_t i = 0; i < size; i++)
        *dest++ = *(source + i * skip);
}

template<class T>
void Processor<T>::zips(const BaseInstruction& instruction)
{
    size_t size = instruction.get_size();
    auto dest = S.begin() + instruction.get_r(0);
    for (int i = 1; i < 3; i++)
    {
        auto op = S.begin() + instruction.get_r(i);
        assert(op + size <= S.end());
        assert(op <= dest - size or op > dest + size);
    }
    auto op1 = S.begin() + instruction.get_r(1);
    auto op2 = S.begin() + instruction.get_r(2);
    assert(dest + 2 * size <= S.end());
    for (int i = 0; i < instruction.get_size(); i++)
    {
        *dest++ = *op1++;
        *dest++ = *op2++;
    }
}

template<class T>
void Processor<T>::transvec(const BaseInstruction& instruction)
{
    auto& args = instruction.get_start();
    assert(args.size() == 4);
    int n_outputs = args[0];
    int dest_base = args[1];
    int n_inputs = args[2];
    int source_base = args[3];
    int dl = T::default_length;
    auto it = S.begin() + source_base;
    int n_input_units = n_inputs * DIV_CEIL(n_outputs, dl);
    int n_output_units = n_outputs * DIV_CEIL(n_inputs, dl);
    StackedVector<T> source, dest(n_output_units);
    assert(it + n_input_units <= S.end());
    for (int i = 0; i < n_input_units; i++)
        source.push_back(*it++);
    ArgVector trans_args;
    for (int i = 0; i < n_outputs; i++)
        trans_args.push_back(i * DIV_CEIL(n_inputs, dl));
    for (int i = 0; i < n_inputs; i++)
        trans_args.push_back(i * DIV_CEIL(n_outputs, dl));
    T::trans(dest, source, n_outputs, trans_args);
    it = S.begin() + dest_base;
    assert(it + dest.size() <= S.end());
    auto dit = dest.begin();
    for (int i = 0; i < n_output_units; i++)
        *it++ = *dit++;
}

template<class T>
void Processor<T>::convcint(const StackedVector<Integer>& Ci,
        const BaseInstruction& instruction)
{
    auto dest = C.begin() + instruction.get_r(0);
    auto source = Ci.begin() + instruction.get_r(1);
    size_t size = instruction.get_size();
    assert(dest + size <= C.end());
    assert(source + size <= Ci.end());
    for (size_t i = 0; i < size; i++)
        *dest++ = *source++;
}

} /* namespace GC */

#endif
