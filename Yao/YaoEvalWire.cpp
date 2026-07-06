/*
 * YaoEvalWire.cpp
 *
 */

#include "config.h"
#include "YaoEvalWire.h"
#include "YaoGate.h"
#include "YaoEvaluator.h"
#include "YaoEvalInput.h"
#include "BMR/prf.h"
#include "BMR/common.h"
#include "GC/ArgTuples.h"
#include "Tools/CheckVector.h"

#include "GC/Processor.hpp"
#include "GC/Secret.hpp"
#include "GC/Thread.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/ThreadMaster.hpp"
#include "YaoCommon.hpp"

void YaoEvalWire::random()
{
	set(0);
}

void YaoEvalWire::public_input(bool value)
{
	(void)value;
	set(0);
}

template<bool repeat>
void YaoEvalWire::and_(GC::Processor<GC::Secret<YaoEvalWire> >& processor,
		const ArgVector& args)
{
	YaoEvaluator& party = YaoEvaluator::s();
	int total = processor.check_args(args, 4);
	int threshold = 1024;
	if (total < threshold)
	{
		// run in single thread
		and_singlethread<repeat>(processor, args, total);
		return;
	}

	processor.complexity += total;
	int i_thread = 0, start = 0;
	for (auto& x : party.get_splits(args, threshold, total))
	{
		auto i_gate = x[0];
		auto end = x[1];
		YaoGate* gate = (YaoGate*) party.gates.consume(
				i_gate * sizeof(YaoGate));
		party.jobs[i_thread++]->dispatch(YAO_AND_JOB, processor, args, start,
				end, i_gate, gate, party.get_gate_id(), repeat);
		party.counter += i_gate;
		start = end;
	}
	party.wait(i_thread);
}

template<bool repeat>
void YaoEvalWire::and_singlethread(GC::Processor<GC::Secret<YaoEvalWire> >& processor,
		const ArgVector& args, int total_ands)
{
	if (total_ands < 10)
		return processor.and_(args, repeat);
	processor.complexity += total_ands;
	size_t n_args = args.size();
	YaoEvaluator& party = YaoEvaluator::s();
	YaoGate* gate = (YaoGate*) party.gates.consume(total_ands * sizeof(YaoGate));
	long counter = party.get_gate_id();
	map<string, Timer> timers;
	SeededPRNG prng;
	and_(processor.S, args, 0, n_args, total_ands, gate, counter,
			prng, timers, repeat, party);
	party.counter += counter - party.get_gate_id();
}

void YaoEvalWire::and_(StackedVector<GC::Secret<YaoEvalWire> >& S,
		const ArgVector& args, size_t start, size_t end, size_t,
		YaoGate* gates, long& gate_id, PRNG&, map<string, Timer>&,
		bool repeat, YaoEvaluator& evaluator)
{
	size_t dl = GC::Secret<YaoEvalWire>::default_length;
	MMO& mmo = evaluator.mmo;
	for (auto it = args.begin() + start; it < args.begin() + end; it += 4)
	{
		if (*it == 1)
		{
			Key label[YaoGate::N_EVAL_HASHES];
			Key hash[YaoGate::N_EVAL_HASHES];
			gate_id++;
			YaoGate::eval_inputs(label,
					S[*(it + 2)].get_reg(0).key(),
					S[*(it + 3)].get_reg(0).key(),
					gate_id);
			mmo.hash<YaoGate::N_EVAL_HASHES>(hash, label);
			auto& out = S[*(it + 1)];
			out.resize_regs(1);
			YaoGate& gate = *gates;
			gates++;
			gate.eval(out.get_reg(0), hash, S[*(it + 2)].get_reg(0),
					S[*(it + 3)].get_reg(0));
		}
		else
		{
			int n_units = DIV_CEIL(*it, dl);
			for (int j = 0; j < n_units; j++)
			{
				auto& left = S[*(it + 2) + j];
				auto& right = S[*(it + 3) + (repeat ? 0 : j)];
				auto& out = S[*(it + 1) + j];
				int n = min(dl, *it - j * dl);
				out.resize_regs(n);
				for (int k = 0; k < n; k++)
				{
					Key label[YaoGate::N_EVAL_HASHES];
					Key hash[YaoGate::N_EVAL_HASHES];
					auto& left_wire = left.get_reg(k);
					auto& right_key = right.get_reg(repeat ? 0 : k).key();
					gate_id++;
					YaoGate::eval_inputs(label, left_wire.key(), right_key,
							gate_id);
					mmo.hash<YaoGate::N_EVAL_HASHES>(hash, label);
					auto& right_wire = right.get_reg(repeat ? 0 : k);
					YaoGate& gate = *gates;
					gates++;
					gate.eval(out.get_reg(k), hash, left_wire, right_wire);
				}
			}
		}
	}
}

template<class T>
void YaoEvalWire::my_input(T& inputter, bool value, int n_bits)
{
	assert(n_bits == 1);
	auto& inputs = inputter.inputs;
	size_t start = inputs.size();
	inputs.resize_zero(start + 1);
	inputs.set_bit(start, value);
}

template<class T>
void YaoEvalWire::finalize_input(T& inputter, int from, int n_bits)
{
	assert(n_bits == 1);

	if (from == 1)
	{
		auto& i_bit = inputter.i_bit;
		Key key;
		inputter.os.unserialize(key);
		set(key ^ inputter.evaluator.ot_ext.receiverOutputMatrix[i_bit],
				inputter.inputs.get_bit(i_bit));
		i_bit++;
	}
	else
	{
		set(0);
	}
}

void YaoEvalWire::inputb(GC::Processor<GC::Secret<YaoEvalWire> >& processor,
        const ArgVector& args)
{
	YaoEvalInput inputter;
	processor.inputb(inputter, processor, args, inputter.evaluator.P->my_num());
	return;
}

void YaoEvalWire::inputbvec(GC::Processor<GC::Secret<YaoEvalWire> >& processor,
        ProcessorBase& input_processor, const ArgVector& args)
{
    YaoEvalInput inputter;
    processor.inputbvec(inputter, input_processor, args,
            *inputter.evaluator.P);
    return;
}

void YaoEvalWire::op(const YaoEvalWire& left, const YaoEvalWire& right,
		Function func)
{
    (void)func;
	YaoGate gate;
	YaoEvaluator::s().load_gate(gate);
	YaoEvaluator::s().counter++;
	gate.eval(*this, left, right);
}

bool YaoEvalWire::get_output()
{
	YaoEvaluator::s().taint();
	bool res = external() ^ YaoEvaluator::s().output_masks.pop_front();
#ifdef DEBUG
    cout << "output " << res << " mask " << (external() ^ res) << " external() "
            << external() << endl;
#endif
	return res;
}

void YaoEvalWire::set(const Key& key)
{
	this->key_ = key;
}

void YaoEvalWire::set(Key key, bool external)
{
	assert(key.get_signal() == external);
	set(key);
}

void YaoEvalWire::convcbit(Integer& dest, const GC::Clear& source,
		GC::Processor<GC::Secret<YaoEvalWire>>&)
{
	dest = source;
	auto &evaluator = YaoEvaluator::s();
	if (not evaluator.continuous())
	{
		evaluator.P->send_long(0, source.get());
		throw needs_cleaning();
	}
}

void YaoEvalWire::reveal_inst(Processor& processor, const ArgVector& args)
{
	processor.reveal(args);
	auto &evaluator = YaoEvaluator::s();
	if (evaluator.continuous())
	{
		octetStream buffer;
		for (size_t j = 0; j < args.size(); j += 3)
		{
			int n = args[j];
			int r0 = args[j + 1];
			for (int i = 0; i < DIV_CEIL(n, GC::Clear::N_BITS); i++)
				processor.C[r0 + i].pack(buffer);
		}
		YaoEvaluator::s().P->send_to(0, buffer);
		throw needs_cleaning();
	}
}

void YaoEvalWire::convcbit2s(GC::Processor<whole_type>& processor,
		const BaseInstruction& instruction)
{
	int unit = GC::Clear::N_BITS;
	for (int i = 0; i < DIV_CEIL(instruction.get_n(), unit); i++)
	{
		auto& dest = processor.S[instruction.get_r(0) + i];
		dest.resize_regs(min(size_t(unit), instruction.get_n() - i * unit));
		for (auto& reg : dest.get_regs())
			reg.set(0);
	}
}

void YaoEvalWire::run_tapes(const ArgVector& args)
{
	auto& party = YaoEvaluator::s();
	party.master.machine.run_tapes(args);
	if (party.continuous())
		party.untaint();
}

template void YaoEvalWire::and_<false>(
        GC::Processor<GC::Secret<YaoEvalWire> >& processor,
        const ArgVector& args);
template void YaoEvalWire::and_<true>(
        GC::Processor<GC::Secret<YaoEvalWire> >& processor,
        const ArgVector& args);
