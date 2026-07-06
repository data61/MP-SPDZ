/*
 * YaoWire.h
 *
 */

#ifndef YAO_YAOGARBLEWIRE_H_
#define YAO_YAOGARBLEWIRE_H_

#include "BMR/Key.h"
#include "BMR/Register.h"
#include "config.h"
#include "YaoWire.h"
#include "Processor/Instruction.h"

#include <map>

class YaoGarbler;
class YaoGarbleInput;
class ProcessorBase;

class YaoGarbleWire : public YaoWire
{
	typedef GC::Secret<YaoGarbleWire> whole_type;

public:
	typedef YaoGarbler Party;
	typedef YaoGarbleInput Input;
	typedef GC::Processor<GC::Secret<YaoGarbleWire>> Processor;
	typedef SwitchableOutput out_type;

	static string name() { return "YaoGarbleWire"; }

	static void andrs(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args)
	{
		and_(processor, args, true);
	}
	static void ands(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args)
	{
		and_(processor, args, false);
	}

	static void and_(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args, bool repeat);
	static void and_multithread(
			GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args, bool repeat);
	static void and_singlethread(
			GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args, bool repeat);
	static void and_(StackedVector<GC::Secret<YaoGarbleWire>>& S,
			const ArgVector& args, size_t start, size_t end,
			size_t total_ands, YaoGate* gate, long& counter, PRNG& prng,
			map<string, Timer>& timers, bool repeat, YaoGarbler& garbler);

	static void inputb(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
			const ArgVector& args);
	static void inputbvec(Processor& processor, ProcessorBase& input_processor,
			const ArgVector& args);

	static void convcbit(Integer& dest, const GC::Clear& source,
			GC::Processor<GC::Secret<YaoGarbleWire>>&);
	static void reveal_inst(Processor& processor, const ArgVector& args);

	static void convcbit2s(GC::Processor<whole_type>& processor,
			const BaseInstruction& instruction);

	static void run_tapes(const ArgVector& args);

	void randomize(PRNG& prng);
	void set(Key key, bool mask);

	Key full_key() const
	{
	    return key_;
	}

	void set_full_key(Key key)
	{
	    key_ = key;
	}

	Key key() const
	{
		Key res = key_;
		res.set_signal(0);
		return res;
	}

	bool mask() const
	{
		return key_.get_signal();
	}

	void random();
	void public_input(bool value);
	void op(const YaoGarbleWire& left, const YaoGarbleWire& right, Function func);
	char get_output();

	template<class T>
	void my_input(T&, bool value, int n_bits)
	{
		assert(n_bits == 1);
		public_input(value);
	}

	template<class T>
	void finalize_input(T& inputter, int from, int n_bits)
	{
		assert(n_bits == 1);
		if (from == 1)
		{
			set(inputter.garbler.prng.get_doubleword(), 0);
			assert(mask() == 0);
			inputter.garbler.receiver_input_keys.back().push_back(full_key());
		}
	}
};

inline void YaoGarbleWire::randomize(PRNG& prng)
{
    key_ = prng.get_doubleword();
#ifdef DEBUG
    //key = YaoGarbler::s().counter << 1;
#endif
}

inline void YaoGarbleWire::set(Key key, bool mask)
{
    key.set_signal(mask);
    this->key_ = key;
    assert(key.get_signal() == mask);
}

#endif /* YAO_YAOGARBLEWIRE_H_ */
