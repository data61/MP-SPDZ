/*
 * YaoEvaluator.cpp
 *
 */

#include "YaoEvaluator.h"

#include "GC/Machine.hpp"
#include "GC/Program.hpp"
#include "GC/Processor.hpp"
#include "GC/Secret.hpp"
#include "GC/Thread.hpp"
#include "GC/ThreadMaster.hpp"
#include "Tools/MMO.hpp"
#include "YaoWire.hpp"

thread_local YaoEvaluator* YaoEvaluator::singleton = 0;

YaoEvaluator::YaoEvaluator(int thread_num, YaoEvalMaster& master) :
		Thread<GC::Secret<YaoEvalWire>>(thread_num, master),
		YaoCommon<YaoEvalWire>(master),
		master(master),
		player(N, 0, "thread" + to_string(thread_num)),
		ot_ext(OTExtensionWithMatrix::setup(player, {}, RECEIVER, true))
{
	set_n_program_threads(master.machine.nthreads);
	this->init(*this);
}

void YaoEvaluator::pre_run()
{
	if (master.opts.cmd_private_output_file.empty())
		processor.out.activate(not continuous());
	if (not continuous())
		receive_to_store(*P);
}

void YaoEvaluator::run(GC::Program& program)
{
	singleton = this;

	if (continuous())
		run(program, *P);
	else
	{
		run_from_store(program);
	}
}

void YaoEvaluator::run(GC::Program& program, Player& P)
{
	auto next = GC::TIME_BREAK;
	do
	{
		receive(P);
		try
		{
			next = program.execute(processor, master.memory, -1);
		}
		catch (needs_cleaning& e)
		{
		}
	}
	while(GC::DONE_BREAK != next);
}

void YaoEvaluator::run_from_store(GC::Program& program)
{
	machine.reset_timer();
	do
	{
		gates_store.pop(gates);
		output_masks_store.pop(output_masks);
	}
	while(GC::DONE_BREAK != program.execute(processor, master.memory, -1));
}

bool YaoEvaluator::receive(Player& P)
{
#ifdef DEBUG_YAO
	printf("waiting to receive at %d in thread %d\n", processor.PC, thread_num);
#endif
	if (P.receive_long(0) == YaoCommon::DONE)
		return false;
	P.receive_player(0, gates);
	P.receive_player(0, output_masks);
#ifdef DEBUG_YAO
	cout << "received " << gates.size() << " bytes for gates and "
			<< output_masks.size() << " output masks at " << processor.PC
			<< " in thread " << thread_num << endl;
#endif
	return true;
}

void YaoEvaluator::receive_to_store(Player& P)
{
	while (receive(P))
	{
		gates_store.push(gates);
		output_masks_store.push(output_masks);
	}
}

NamedCommStats YaoEvaluator::extra_comm()
{
	return player.get_comm_stats();
}
