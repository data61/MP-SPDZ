/*
 * Register.h
 *
 */

#ifndef PROTOCOL_SRC_REGISTER_H_
#define PROTOCOL_SRC_REGISTER_H_

#include <vector>
#include <utility>
#include <stdint.h>
using namespace std;

#include "config.h"
#include "Key.h"
#include "Wire.h"
#include "GC/Clear.h"
#include "GC/Memory.h"
#include "GC/Access.h"
#include "GC/ArgTuples.h"
#include "Math/gf2n.h"
#include "Tools/FlexBuffer.h"
#include "Tools/PointerVector.h"
#include "Tools/Bundle.h"
#include "Tools/SwitchableOutput.h"
#include "Processor/Instruction.h"

//#define PAD_TO_8(n) (n+8-n%8)
#define PAD_TO_8(n) (n)

#ifdef N_PARTIES
#define MAX_N_PARTIES N_PARTIES
#endif

#ifdef MAX_N_PARTIES
class BaseKeyVector
{
    Key keys[MAX_N_PARTIES];
public:
    Key& operator[](int i) { return keys[i]; }
    const Key& operator[](int i) const { return keys[i]; }
    Key* data() { return keys; }
    const Key* data() const { return keys; }
#ifdef N_PARTIES
    BaseKeyVector(int n_parties)
    {
        for (auto& key : keys)
            key = 0;
    }
    size_t size() const { return N_PARTIES; }
    void resize(int size) { (void)size; }
#else
    BaseKeyVector(int n_parties = 0) : n_parties(n_parties)
    {
        for (auto& key : keys)
            key = 0;
    }
    size_t size() const { return n_parties; }
    void resize(int size) { n_parties = size; }
private:
    int n_parties;
#endif
};
#else
class BaseKeyVector : public CheckVector<Key>
{
    typedef CheckVector<Key> super;

public:
	BaseKeyVector(int size = 0) : super(size, Key(0)) {}
	void resize(int size) { super::resize(size, Key(0)); }
};
#endif

class KeyVector : public BaseKeyVector
{
public:
	KeyVector(int size = 0) : BaseKeyVector(size) {}
	KeyVector(const KeyVector& other) : BaseKeyVector() { *this = other; }
	size_t byte_size() const { return size() * sizeof(Key); }
	void operator=(const KeyVector& source);
    KeyVector operator^(const KeyVector& other) const;
    template <class T>
    void serialize_no_allocate(T& output) const { output.serialize_no_allocate(data(), byte_size()); }
    template <class T>
    void serialize(T& output) const { output.serialize(data(), byte_size()); }
    void unserialize(ReceivedMsg& source, int n_parties);
    friend ostream& operator<<(ostream& os, const KeyVector& kv);
};

class GarbledGate;
class CommonParty;

template <int I>
class KeyTuple {
	friend class Register;

	static long counter;

protected:
	KeyVector keys[I];

	int part_size() { return keys[0].size() * sizeof(Key); }
public:
	KeyTuple() {}
	KeyTuple(int n_parties) { init(n_parties); }
	void init(int n_parties);
	int byte_size() { return I * keys[0].byte_size(); }
	KeyVector& operator[](int i) { return keys[i]; }
	const KeyVector& operator[](int i) const { return keys[i]; }
	KeyTuple<I> operator^(const KeyTuple<I>& other) const;
	void copy_to(Key* dest);
	void unserialize(ReceivedMsg& source, int n_parties);
	void copy_from(Key* source, int n_parties, int except);
	template <class T>
	void serialize_no_allocate(T& output) const;
	template <class T>
	void serialize(T& output) const;
	template <class T>
	void serialize(T& output, party_id_t pid) const;
	void unserialize(vector<char>& output);
	template <class T>
	void unserialize(T& output);
	void randomize();
	void reset();
	void print(int wire_id) const;
	void print(int wire_id, party_id_t pid);
};

namespace GC
{
template <class T>
class Secret;
template <class T>
class Processor;
}

class Register {
protected:
	static int counter;

    KeyVector garbled_entry;
    char external;

public:
	char mask;
	KeyTuple<2> keys; /* Additional data stored per per party per wire: */
	                  /* Total of n*W*2 keys
	                   *  For every w={0,...,W}
	                   *      For every b={0,1}
	                   *          For every i={1...n}
	                   *              k^i_{w,b}
	                   *  This is helpful that the keys for specific w and b are adjacent
	                   *  for pipelining matters.
	                   */

	Register();

	void init(int n_parties);
	void init(int rfd, int n_parties);
	KeyVector& operator[](int i) { return keys[i]; }
    const Key& key(party_id_t i, int b) const { return keys[b][i-1]; }
    Key& key(party_id_t i, int b) { return keys[b][i-1]; }
    void set_eval_keys();
    void set_eval_keys(Key* keys, int n_parties, int except);
    const Key& external_key(party_id_t i) const { return garbled_entry[i-1]; }
    void set_external_key(party_id_t i, const Key& key);
    void reset_non_external_key(party_id_t i);
    void set_external(char ext);
    char get_external() const { check_external(); return external; }
    char get_external_no_check() const { return external; }
    void set_mask(char mask);
    int get_mask() const { check_mask(); return mask; }
    char get_mask_no_check() { return mask; }
    char get_output() { check_external(); check_mask(); return mask ^ external; }
    char get_output_no_check() { return mask ^ external; }
    const KeyVector& get_garbled_entry() const { return garbled_entry; }
    const Key& get_garbled_wire(party_id_t i) const { return garbled_entry[i-1]; }
    void print_input(int id);
    void print() const { keys.print(get_id()); }
    void check_external() const;
    void check_mask() const;
    void check_signal_key(int my_id, KeyVector& garbled_entry);

    void eval(const Register& left, const Register& right, GarbledGate& gate,
            party_id_t my_id, char* prf_output, int, int, int);

    void garble(const Register& left, const Register& right, Function func,
            Gate* gate, int g, vector<ReceivedMsg>& prf_outputs, SendBuffer& buffer);

    size_t get_id() const { return (size_t)this; }

    template <class T>
    void set_trace();
};

inline ostream& operator<<(ostream&, const Register&)
{
	throw runtime_error("BMR secret output not implemented");
}


// this is to fake a "cout" that does nothing
class BlackHole
{
public:
	template <typename T>
	BlackHole& operator<<(T) { return *this; }
	BlackHole& operator<<(BlackHole& (*__pf)(BlackHole&)) { (void)__pf; return *this; }
	void fill(char) {}
	void width(int) {}
	void activate(bool) {}
	void redirect_to_file(ostream&) {}
};
inline BlackHole& endl(BlackHole& b) { return b; }
inline BlackHole& flush(BlackHole& b) { return b; }

class ProcessorBase;

class Phase
{
public:
    typedef NoMemory DynamicMemory;

	typedef BlackHole out_type;

	static const bool actual_inputs = true;

	static const bool garbled = true;

	template <class T>
	static void store_clear_in_dynamic(T&, const vector<GC::ClearWriteAccess>&)
	{}

	template<class T>
	static void store(NoMemory&, const vector<GC::WriteAccess<T> >&)
	{ throw no_dynamic_memory(); }
	template<class T>
	static void load(vector<GC::ReadAccess<T> >&, const NoMemory&)
	{ throw no_dynamic_memory(); }

	template <class T>
	static void andrs(T& processor, const ArgVector& args) { processor.andrs(args); }
	template <class T>
	static void ands(T& processor, const ArgVector& args) { processor.ands(args); }
	template <class T>
	static void andrsvec(T& processor, const ArgVector& args)
	{ processor.andrsvec(args); }
	template <class T>
	static void xors(T& processor, const ArgVector& args) { processor.xors(args); }
	template <class T>
	static void inputb(T& processor, const ArgVector& args) { processor.input(args); }
	template <class T>
	static void inputbvec(T&, ProcessorBase&, const ArgVector&)
	{ throw not_implemented(); }
	template <class T>
	static T get_input(int from, GC::Processor<T>& processor, int n_bits)
	{ return T::input(from, processor.get_input(n_bits), n_bits); }
	template<class U>
	static void reveal_inst(GC::Processor<U>& processor, const ArgVector& args)
	{ processor.reveal(args); }

	template<class T>
	static void convcbit(Integer& dest, const GC::Clear& source, T&)
	{ (void) dest, (void) source; throw not_implemented(); }

	void input(party_id_t from, char value = -1) { (void)from; (void)value; }
	void public_input(bool value) { (void)value; }
	void random() {}
	void output() {}
};

class InputterBase
{
public:
    static bool is_me(int player, int my_num)
    {
        return player == my_num;
    }
};

class NoOpInputter : public InputterBase
{
public:
	PointerVector<char> inputs;

	void exchange()
	{
	}
};

class ProgramRegister : public Phase, public Register
{
public:
	typedef NoOpInputter Input;

	// only true for evaluation
	static const bool actual_inputs = false;

	static int threshold(int) { throw not_implemented(); }

	template<class T>
	static void store(NoMemory& dest,
			const vector<GC::WriteAccess<T> >& accesses) { (void)dest; (void)accesses; }

	template <class T>
	static void inputbvec(T& processor, ProcessorBase& input_processor,
			const ArgVector& args);

    template<class U>
    static void convcbit2s(GC::Processor<U>&, const BaseInstruction&)
    { throw runtime_error("convcbit2s not implemented"); }
    template<class U>
    static void andm(GC::Processor<U>&, const BaseInstruction&)
    { throw runtime_error("andm not implemented"); }

    static void run_tapes(const ArgVector&)
    { throw runtime_error("multi-threading not implemented"); }

	// most BMR phases don't need actual input
	template<class T>
	static T get_input(GC::Processor<T>& processor, const InputArgs& args)
	{ (void)processor; return T::input(args.from + 1, 0, args.n_bits); }

	void my_input(Input&, bool, int) {}
	void other_input(Input&, int) {}

	char get_output() { return 0; }
};

class PRFRegister : public ProgramRegister
{
public:
	static string name() { return "PRF"; }

	template<class T>
	static void load(vector<GC::ReadAccess<T> >& accesses,
			const NoMemory& source);

	void op(const PRFRegister& left, const PRFRegister& right, Function func);
	void XOR(const Register& left, const Register& right);
	void input(party_id_t from, char input = -1);
	void public_input(bool value);
	void random();
	void output();

	void finalize_input(NoOpInputter&, int from, int)
	{ input(from + 1, -1); }
};

class ProgramParty;
class EvalRegister;

class EvalInputter : public InputterBase
{
	class Tuple
	{
	public:
		EvalRegister* reg;
		int from;

		Tuple(EvalRegister* reg, int from) :
				reg(reg), from(from)
		{
		}
	};

public:
	ProgramParty& party;

	Bundle<octetStream> oss;
	vector<Tuple> tuples;

	EvalInputter();
	void add_other(int from);
	void exchange();
};

class EvalRegister : public ProgramRegister
{
public:
    static string name() { return "Evaluation"; }

    typedef EvalInputter Input;

    typedef SwitchableOutput out_type;

	static const bool actual_inputs = true;

    template<class T, class U>
    static void store(GC::Memory<U>& dest,
    		const vector<GC::WriteAccess<T> >& accesses);
    template<class T, class U>
    static void load(vector<GC::ReadAccess<T> >& accesses,
    		const GC::Memory<U>& source);

	template <class T>
	static void andrs(T& processor, const ArgVector& args);
	template <class T>
	static void inputb(T& processor, const ArgVector& args);
	template <class T>
	static void inputbvec(T& processor, ProcessorBase& input_processor,
			const ArgVector& args);

	template <class T>
	static T get_input(GC::Processor<T>& processor, const InputArgs& args)
	{
		(void)processor, (void)args;
		throw runtime_error("use EvalRegister::inputb()");
	}

	static void convcbit(Integer& dest, const GC::Clear& source,
	        GC::Processor<GC::Secret<EvalRegister>>& proc);

	void op(const ProgramRegister& left, const ProgramRegister& right, Function func);
	void XOR(const Register& left, const Register& right);

	void public_input(bool value);
	void random();
	void output();
	unsigned long long get_output() { return Register::get_output(); }

	template <class T>
	static void store_clear_in_dynamic(GC::Memory<T>& mem,
			const vector<GC::ClearWriteAccess>& accesses);
	static void check_input(long long input, int n_bits);
	void input(party_id_t from, char value = -1);
	void input_helper(char value, octetStream& os);

	void my_input(EvalInputter& inputter, bool input, int);
	void other_input(EvalInputter& inputter, int from);
	void finalize_input(EvalInputter& inputter, int from, int);
};

class GarbleRegister : public ProgramRegister
{
public:
	static string name() { return "Garbling"; }

	template<class T>
	static void load(vector<GC::ReadAccess<T> >& accesses,
			const NoMemory& source);

	void op(const Register& left, const Register& right, Function func);
	void XOR(const Register& left, const Register& right);
        void input(party_id_t from, char value = -1);
	void public_input(bool value);
	void random();
	void output() {}

	void finalize_input(NoOpInputter&, int from, int)
	{ input(from + 1, -1); }
};

class RandomRegister : public ProgramRegister
{
public:
	static string name() { return "Randomization"; }

	template<class T>
	static void store(NoMemory& dest,
			const vector<GC::WriteAccess<T> >& accesses);
	template<class T>
	static void load(vector<GC::ReadAccess<T> >& accesses,
			const NoMemory& source);

	void randomize();

	void op(const Register& left, const Register& right, Function func);
	void XOR(const Register& left, const Register& right);

	void input(party_id_t from, char value = -1);
	void public_input(bool value);
	void random();
	void output();

	void finalize_input(NoOpInputter&, int from, int)
	{ input(from + 1, -1); }
};


inline void KeyVector::operator=(const KeyVector& other)
{
	resize(other.size());
	avx_memcpy(data(), other.data(), byte_size());
}

inline void KeyVector::unserialize(ReceivedMsg& source, int n_parties)
{
	resize(n_parties);
	source.unserialize(data(), size() * sizeof(Key));
}

template <int I>
inline void KeyTuple<I>::init(int n_parties) {
	for (int i = 0; i < I; i++)
		keys[i].resize(n_parties);
}

template<int I>
inline void KeyTuple<I>::reset()
{
	for (int i = 0; i < I; i++)
		for (size_t j = 0; j < keys[i].size(); j++)
			keys[i][j] = 0;
}

template <int I>
inline void KeyTuple<I>::unserialize(ReceivedMsg& source, int n_parties) {
	for (int b = 0; b < I; b++)
		keys[b].unserialize(source, n_parties);
}

template<int I> template <class T>
void KeyTuple<I>::serialize_no_allocate(T& output) const {
	for (int i = 0; i < I; i++)
		keys[i].serialize_no_allocate(output);
}

template<int I> template <class T>
void KeyTuple<I>::serialize(T& output) const {
	for (int i = 0; i < I; i++)
		for (unsigned int j = 0; j < keys[i].size(); j++)
			keys[i][j].serialize(output);
}

template<int I> template <class T>
void KeyTuple<I>::serialize(T& output, party_id_t pid) const {
	for (int i = 0; i < I; i++)
		keys[i][pid - 1].serialize(output);
}

template<int I> template <class T>
void KeyTuple<I>::unserialize(T& output) {
	for (int i = 0; i < I; i++)
		for (unsigned int j = 0; j < keys[i].size(); j++)
			output.unserialize(keys[i][j]);
}

#endif /* PROTOCOL_SRC_REGISTER_H_ */
