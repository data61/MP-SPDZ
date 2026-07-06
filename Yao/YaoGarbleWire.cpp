/*
 * YaoWire.cpp
 *
 */

#include "YaoGarbleWire.h"
#include "YaoGate.h"
#include "YaoGarbler.h"
#include "YaoGarbleInput.h"
#include "GC/ArgTuples.h"
#include "Tools/pprint.h"

#include "GC/Processor.hpp"
#include "GC/Secret.hpp"
#include "GC/Thread.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/ThreadMaster.hpp"
#include "YaoCommon.hpp"

void YaoGarbleWire::random()
{
	if (YaoGarbler::s().prng.get_bit())
		key_ = YaoGarbler::s().get_delta();
	else
		key_ = 0;
}

void YaoGarbleWire::public_input(bool value)
{
	key_ = YaoGate::garble_public_input(value, YaoGarbler::s().get_delta());
}

void YaoGarbleWire::and_(GC::Processor<GC::Secret<YaoGarbleWire> >& processor,
		const ArgVector& args, bool repeat)
{
#ifdef YAO_TIMINGS
	auto& garbler = YaoGarbler::s();
	TimeScope ts(garbler.and_timer), ts2(garbler.and_proc_timer),
			ts3(garbler.and_main_thread_timer);
#endif
	and_multithread(processor, args, repeat);
}

void YaoGarbleWire::and_multithread(GC::Processor<GC::Secret<YaoGarbleWire> >& processor,
		const ArgVector& args, bool repeat)
{
	YaoGarbler& party = YaoGarbler::s();
	int total = processor.check_args(args, 4);
	if (total < party.get_threshold())
	{
		// run in single thread
		and_singlethread(processor, args, repeat);
		return;
	}

	party.and_prepare_timer.start();
	processor.complexity += total;
	SendBuffer& gates = party.gates;
	gates.allocate(total * sizeof(YaoGate));
	int i_thread = 0, start = 0;
	for (auto& x : party.get_splits(args, party.get_threshold(), total))
	{
		int i_gate = x[0];
		int end = x[1];
		YaoGate* gate = (YaoGate*)gates.end();
		gates.skip(i_gate * sizeof(YaoGate));
		party.timers["Dispatch"].start();
		party.jobs[i_thread++]->dispatch(YAO_AND_JOB, processor, args, start,
				end, i_gate, gate, party.get_gate_id(), repeat);
		party.timers["Dispatch"].stop();
		party.counter += i_gate;
		i_gate = 0;
		start = end;
	}
	party.and_prepare_timer.stop();
	party.and_wait_timer.start();
	party.wait(i_thread);
	party.and_wait_timer.stop();
}

void YaoGarbleWire::and_singlethread(GC::Processor<GC::Secret<YaoGarbleWire> >& processor,
		const ArgVector& args, bool repeat)
{
	int total_ands = processor.check_args(args, 4);
	if (total_ands < 10)
		return processor.and_(args, repeat);
	processor.complexity += total_ands;
	size_t n_args = args.size();
	auto& garbler = YaoGarbler::s();
	SendBuffer& gates = garbler.gates;
	YaoGate* gate = (YaoGate*)gates.allocate_and_skip(total_ands * sizeof(YaoGate));
	long counter = garbler.get_gate_id();
	and_(processor.S, args, 0, n_args, total_ands, gate, counter,
			garbler.prng, garbler.timers, repeat, garbler);
	garbler.counter += counter - garbler.get_gate_id();
}

void YaoGarbleWire::and_(StackedVector<GC::Secret<YaoGarbleWire> >& S,
		const ArgVector& args, size_t start, size_t end, size_t,
		YaoGate* gate, long& counter, PRNG& prng, map<string, Timer>& timers,
		bool repeat, YaoGarbler& garbler)
{
	(void)timers;
	const Key& delta = garbler.get_delta();
	size_t dl = GC::Secret<YaoGarbleWire>::default_length;
	Key left_delta = delta.doubling(1);
	Key right_delta = delta.doubling(2);
	Key labels[4];
	Key hashes[4];
	MMO& mmo = garbler.mmo;
	for (auto it = args.begin() + start; it < args.begin() + end; it += 4)
	{
		if (*it == 1)
		{
			counter++;
			YaoGate::E_inputs(labels, S[*(it + 2)].get_reg(0),
					S[*(it + 3)].get_reg(0), left_delta, right_delta,
					counter);
			mmo.hash<4>(hashes, labels);
			auto& out = S[*(it + 1)];
			out.resize_regs(1);
			YaoGate::randomize(out.get_reg(0), prng);
			(gate++)->and_garble(out.get_reg(0), hashes,
					S[*(it + 2)].get_reg(0),
					S[*(it + 3)].get_reg(0), garbler.get_delta());
		}
		else
		{
			int n_units = DIV_CEIL(*it, dl);
			for (int j = 0; j < n_units; j++)
			{
				auto& out = S[*(it + 1) + j];
				int left = min(dl, *it - j * dl);
				out.resize_regs(left);
				for (int k = 0; k < left; k++)
				{
					auto& left_wire = S[*(it + 2) + j].get_reg(k);
					auto& right_wire = S[*(it + 3) + (repeat ? 0 : j)].get_reg(
							repeat ? 0 : k);
					counter++;
					YaoGate::E_inputs(labels, left_wire,
							right_wire, left_delta, right_delta, counter);
					mmo.hash<4>(hashes, labels);
					//timers["Inner ref"].start();
					//timers["Inner ref"].stop();
					//timers["Randomizing"].start();
					out.get_reg(k).randomize(prng);
					//timers["Randomizing"].stop();
					//timers["Gate computation"].start();
					(gate++)->and_garble(out.get_reg(k), hashes,
							left_wire, right_wire,
							garbler.get_delta());
					//timers["Gate computation"].stop();
				}
			}
		}
	}
}


void YaoGarbleWire::inputb(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
        const ArgVector& args)
{
	auto& garbler = YaoGarbler::s();
	YaoGarbleInput input;
	processor.inputb(input, processor, args, garbler.P->my_num());
}

void YaoGarbleWire::inputbvec(GC::Processor<GC::Secret<YaoGarbleWire>>& processor,
        ProcessorBase& input_processor, const ArgVector& args)
{
    auto& garbler = YaoGarbler::s();
    YaoGarbleInput input;
    processor.inputbvec(input, input_processor, args, *garbler.P);
}

inline void YaoGarbler::store_gate(const YaoGate& gate)
{
	gates.serialize(gate);
}

void YaoGarbleWire::op(const YaoGarbleWire& left, const YaoGarbleWire& right,
		Function func)
{
	auto& garbler = YaoGarbler::s();
	randomize(garbler.prng);
	YaoGarbler::s().counter++;
	YaoGate gate(*this, left, right, func);
	YaoGarbler::s().store_gate(gate);
}

char YaoGarbleWire::get_output()
{
	YaoGarbler::s().taint();
	YaoGarbler::s().output_masks.push_back(mask());
	return 0;
}

void YaoGarbleWire::convcbit(Integer& dest, const GC::Clear& source,
		GC::Processor<GC::Secret<YaoGarbleWire>>&)
{
	auto &garbler = YaoGarbler::s();
	if (garbler.continuous())
		dest = source;
	else
	{
		garbler.untaint();
		dest = garbler.P->receive_long(1);
	}
}

void YaoGarbleWire::reveal_inst(Processor& processor, const ArgVector& args)
{
	auto &garbler = YaoGarbler::s();
	if (garbler.continuous())
	{
		if (garbler.is_tainted())
			processor.reveal(args);
		garbler.untaint();
		octetStream buffer;
		garbler.P->receive_player(1, buffer);
		for (size_t j = 0; j < args.size(); j += 3)
		{
			int n = args[j];
			int r0 = args[j + 1];
			for (int i = 0; i < DIV_CEIL(n, GC::Clear::N_BITS); i++)
				processor.C[r0 + i].unpack(buffer);
		}
		garbler.taint();
	}
	else
		processor.reveal(args);
}

void YaoGarbleWire::convcbit2s(GC::Processor<whole_type>& processor,
		const BaseInstruction& instruction)
{
	int unit = GC::Clear::N_BITS;
	for (int i = 0; i < DIV_CEIL(instruction.get_n(), unit); i++)
	{
		auto& dest = processor.S[instruction.get_r(0) + i];
		int n = min(size_t(unit), instruction.get_n() - i * unit);
		dest.resize_regs(n);
		for (int j = 0; j < n; j++)
			dest.get_reg(j).public_input(
					processor.C[instruction.get_r(1) + i].get_bit(j));
	}
}

void YaoGarbleWire::run_tapes(const ArgVector& args)
{
	auto& garbler = YaoGarbler::s();
	if (garbler.continuous())
		garbler.untaint();
	garbler.master.machine.run_tapes(args);
}
