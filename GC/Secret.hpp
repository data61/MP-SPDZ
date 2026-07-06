/*
 * EvalSecret.cpp
 *
 */

#ifndef GC_SECRET_HPP_
#define GC_SECRET_HPP_

#include "Secret.h"
#include "Secret_inline.h"

namespace GC
{

template<class T>
Secret<T> Secret<T>::input(Processor<Secret<T>>& processor, const InputArgs& args)
{
    return T::get_input(processor, args);
}

template<class T>
Secret<T> Secret<T>::input(party_id_t from, const int128& input, int n_bits)
{
    Secret<T> res;
    if (n_bits < 0)
        n_bits = default_length;
#ifdef DEBUG_INPUT
    cout << "input " << input << endl;
#endif
    for (int i = 0; i < n_bits; i++)
    {
        res.get_new_reg().input(from, input.get_bit(i));
#ifdef DEBUG_INPUT
        cout << (int)input.get_bit(i);
#endif
    }
#ifdef DEBUG_INPUT
    cout << " input" << endl;
#endif
    if ((size_t)n_bits != res.registers.size())
    {
    	cout << n_bits << " " << res.registers.size() << endl;
    	throw runtime_error("wrong bit length in input()");
    }
#ifdef DEBUG_INPUT
	for (auto& reg : res.registers)
	    cout << (int)reg.get_mask_no_check();
	cout << " mask " <<  endl;
	for (auto& reg : res.registers)
	    cout << (int)reg.get_external_no_check();
	cout << " ext " << endl;
    int128 a;
    res.reveal(a);
	cout << " input " << hex << a << "(" << res.size() << ") from " << from
			<< " (" << input << ", " << dec << n_bits << ")" << endl;
#endif
    return res;
}

template<class T>
template<class U>
void GC::Secret<T>::my_input(U& inputter, BitVec value, int n_bits)
{
    resize_regs(n_bits);
    for (int i = 0; i < n_bits; i++)
        get_reg(i).my_input(inputter, value.get_bit(i), 1);
}

template<class T>
template<class U>
void GC::Secret<T>::other_input(U& inputter, int from, int n_bits)
{
    resize_regs(n_bits);
    for (int i = 0; i < n_bits; i++)
        get_reg(i).other_input(inputter, from);
}

template<class T>
template<class U>
void GC::Secret<T>::finalize_input(U& inputter, int from, int n_bits)
{
    resize_regs(n_bits);
    for (int i = 0; i < n_bits; i++)
        get_reg(i).finalize_input(inputter, from, 1);
}

template<class T>
void Secret<T>::random(int n_bits, int128 share)
{
    (void)share;
    if (n_bits > 128)
        throw runtime_error("too many bits");
    resize_regs(n_bits);
    for (int i = 0; i < n_bits; i++)
    	get_reg(i).random();
#ifdef DEBUG_RANDOM
    int128 revealed;
    reveal(revealed);
    cout << "random " << revealed << " share " << share << endl;
#endif
    if ((size_t)n_bits != registers.size())
    {
    	cout << n_bits << " " << registers.size() << endl;
    	throw runtime_error("wrong bit length in random()");
    }
}

template <class T>
void Secret<T>::random_bit()
{
	return random(1, 0);
}

template <class T>
template <class U, class V>
void Secret<T>::store(U& mem,
        vector<WriteAccess<V> >& accesses)
{
    T::store(mem, accesses);
}

template <class T>
Secret<T>::Secret()
{

}


template<class T>
T& GC::Secret<T>::get_new_reg()
{
	registers.push_back(T());
	T& res = registers.back();
#ifdef DEBUG_REGS
	cout << "Secret: new " << typeid(T).name() << " " << res.get_id() << " at " << &res << endl;
#endif
	return res;
}

template <class T>
void Secret<T>::load_clear(int n, const Integer& x)
{
    if ((unsigned)n < 8 * sizeof(x) and (unsigned long) abs(x.get()) > (1ul << n))
        throw out_of_range("public value too long");
#ifdef DEBUG_ROUNDS2
    cout << "secret from integer " << hex << this << dec << " " << endl;
#endif
    resize_regs(n);
    for (int i = 0; i < n; i++)
    {
        get_reg(i).public_input((x.get() >> i) & 1);
    }
#ifdef DEBUG_VALUES
    cout << "input " << x << endl;
    for (int i = 0; i < n; i++)
        cout << ((x.get() >> i) & 1);
    cout << endl;
    cout << "on registers: " << endl;
    for (int i = 0; i < n; i++)
        cout << get_reg(i).get_id() << " ";
    cout << endl;
#endif
}

template <class T>
template <class U, class V>
void Secret<T>::load(vector<ReadAccess <V> >& accesses, const U& mem)
{
    for (auto&& access : accesses)
    {
        int n = access.length;
        if (n <= 0 || n > default_length)
            throw runtime_error("invalid length for dynamic loading");
        access.dest.resize_regs(n);
    }
    T::load(accesses, mem);
}

template <class T>
Secret<T> Secret<T>::operator<<(int i) const
{
    Secret<T> res;
    for (int j = 0; j < i; j++)
        res.get_new_reg().public_input(0);
    res.registers.insert(res.registers.end(), registers.begin(),
            registers.end());
    return res;
}

template <class T>
Secret<T> Secret<T>::operator>>(int i) const
{
    Secret<T> res;
    res.registers.insert(res.registers.end(), registers.begin() + i, registers.end());
    return res;
}

template <class T>
template <class U>
void Secret<T>::bitcom(StackedVector<U>& S, const ArgVector& regs)
{
    registers.clear();
    for (unsigned int i = 0; i < regs.size(); i++)
    {
    	if (S[regs[i]].registers.size() != 1)
    		throw Processor_Error("can only compose bits");
        registers.push_back(S[regs[i]].registers.at(0));
    }
}

template <class T>
template <class U>
void Secret<T>::bitdec(StackedVector<U>& S, const ArgVector& regs) const
{
    if (regs.size() > registers.size())
        throw overflow("not enough bits for bit decomposition", regs.size(),
            registers.size());
    for (unsigned int i = 0; i < regs.size(); i++)
    {
        Secret& secret = S[regs[i]];
        secret.registers.clear();
        secret.registers.push_back(registers.at(i));
    }
}

template<class T>
template<class U>
void Secret<T>::trans(Processor<U>& processor, int n_outputs,
        const ArgVector& args)
{
    int n_inputs = args.size() - n_outputs;
    int dl = U::default_length;
    for (int i = 0; i < n_outputs; i++)
    {
        for (int j = 0; j < DIV_CEIL(n_inputs, dl); j++)
            processor.S[args[i] + j].resize_regs(min(dl, n_inputs - j * dl));
        for (int j = 0; j < n_inputs; j++)
        {
            auto& source = processor.S[args[n_outputs + j] + i / dl].registers;
            auto& dest = processor.S[args[i] + j / dl].registers[j % dl];
            if (size_t(i % dl) < source.size())
                dest = source[i % dl];
            else
                dest.public_input(0);
        }
    }
}

template <class T>
template <class U>
void Secret<T>::reveal(size_t n_bits, U& x)
{
#ifdef DEBUG_OUTPUT
    cout << "revealing " << this << " with min(" << 8 * sizeof(U) << ","
            << registers.size() << ") bits" << endl;
#endif
    if (n_bits > registers.size())
        throw out_of_range(
                "not enough wires for revealing: " + to_string(n_bits) + "/"
                        + to_string(registers.size()));
    x = 0;
    for (unsigned int i = 0; i < min(8 * sizeof(U), registers.size()); i++)
    {
        get_reg(i).output();
        char out = get_reg(i).get_output();
        x ^= U(out) << i;
#ifdef DEBUG_OUTPUT
        cout << (int)out;
#endif
    }
#ifdef DEBUG_OUTPUT
    cout << " output" << endl;
    for (auto& reg : registers)
        cout << (int)reg.get_mask_no_check();
    cout << " mask" << endl;
    for (auto& reg: registers)
        cout << (int)reg.get_external_no_check();
    cout << " ext" << endl;
#endif
#ifdef DEBUG_VALUES
    cout << typeid(T).name() << " " << &x << endl;
    cout << "reveal " << registers.size() << " bits: " << hex << showbase << x << dec << endl;
    cout << "from registers:" << endl;
    for (unsigned int i = 0; i < registers.size(); i++)
        cout << registers[i].get_id() << " ";
    cout << endl;
#endif
}

} /* namespace GC */

#endif
