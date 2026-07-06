/*
 * YaoEvalWire.h
 *
 */

#ifndef YAO_YAOEVALWIRE_H_
#define YAO_YAOEVALWIRE_H_

#include "BMR/Key.h"
#include "BMR/Gate.h"
#include "BMR/Register.h"
#include "Processor/DummyProtocol.h"
#include "Processor/Instruction.h"
#include "config.h"
#include "YaoWire.h"

class YaoEvaluator;
class YaoEvalInput;
class ProcessorBase;

class YaoEvalWire : public YaoWire
{
	typedef GC::Secret<YaoEvalWire> whole_type;

public:
	typedef YaoEvaluator Party;
	typedef YaoEvalInput Input;
	typedef GC::Processor<GC::Secret<YaoEvalWire>> Processor;

	static string name() { return "YaoEvalWire"; }

	typedef SwitchableOutput out_type;

	static void andrs(GC::Processor<GC::Secret<YaoEvalWire>>& processor,
			const ArgVector& args)
	{
		and_<true>(processor, args);
	}
	static void ands(GC::Processor<GC::Secret<YaoEvalWire>>& processor,
			const ArgVector& args)
	{
		and_<false>(processor, args);
	}
	template<bool repeat>
	static void and_(GC::Processor<GC::Secret<YaoEvalWire>>& processor,
			const ArgVector& args);
	template<bool repeat>
	static void and_singlethread(
			GC::Processor<GC::Secret<YaoEvalWire>>& processor,
			const ArgVector& args, int total_ands);
	static void and_(StackedVector<GC::Secret<YaoEvalWire>>& S,
			const ArgVector& args, size_t start, size_t end,
			size_t total_ands, YaoGate* gate, long& counter, PRNG& prng,
			map<string, Timer>& timers, bool repeat, YaoEvaluator& garbler);

	static void inputb(GC::Processor<GC::Secret<YaoEvalWire>>& processor,
			const ArgVector& args);
	static void inputbvec(Processor& processor, ProcessorBase& input_processor,
			const ArgVector& args);

	static void convcbit(Integer& dest, const GC::Clear& source,
			GC::Processor<GC::Secret<YaoEvalWire>>&);
	static void reveal_inst(Processor& processor, const ArgVector& args);

	static void convcbit2s(GC::Processor<whole_type>& processor,
			const BaseInstruction& instruction);

	static void run_tapes(const ArgVector& args);

	void set(const Key& key);
	void set(Key key, bool external);

	const Key& key() const
	{
		return key_;
	}

	bool external() const
	{
		return key_.get_signal();
	}

	void random();
	void public_input(bool value);
	void op(const YaoEvalWire& left, const YaoEvalWire& right, Function func);
	bool get_output();

	template<class T>
	void my_input(T&, bool value, int n_bits);
	template<class T>
	void finalize_input(T& inputter, int from, int n_bits);
};

#endif /* YAO_YAOEVALWIRE_H_ */
