/*
 * YaoGarbler.cpp
 *
 */

#include "YaoGarbler.h"
#include "YaoGate.h"

#include "GC/ThreadMaster.hpp"
#include "GC/Processor.hpp"
#include "GC/Program.hpp"
#include "GC/Machine.hpp"
#include "GC/Secret.hpp"
#include "GC/Thread.hpp"
#include "Tools/MMO.hpp"
#include "YaoWire.hpp"

thread_local YaoGarbler* YaoGarbler::singleton = 0;

YaoGarbler::YaoGarbler(int thread_num, YaoGarbleMaster& master) :
		GC::Thread<GC::Secret<YaoGarbleWire>>(thread_num, master),
		YaoCommon<YaoGarbleWire>(master),
		master(master),
		and_proc_timer(CLOCK_PROCESS_CPUTIME_ID),
		and_main_thread_timer(CLOCK_THREAD_CPUTIME_ID),
		player(master.N, 1, "thread" + to_string(thread_num)),
		ot_ext(OTExtensionWithMatrix::setup(player,
				master.get_delta().get<__m128i>(), SENDER, true))
{
	prng.ReSeed();
	set_n_program_threads(master.machine.nthreads);
	this->init(*this);
	if (continuous())
	    taint();
	else
	{
		processor.out.activate(false);
		if (not master.opts.cmd_private_output_file.empty())
			cerr << "Garbling party cannot output with one-shot computation"
					<< endl;
	}
}

YaoGarbler::~YaoGarbler()
{
#ifdef VERBOSE
	cerr << "Number of AND gates: " << counter << endl;
#endif
#ifdef YAO_TIMINGS
	cout << "AND time: " << and_timer.elapsed() << endl;
	cout << "AND process timer: " << and_proc_timer.elapsed() << endl;
	cout << "AND main thread timer: " << and_main_thread_timer.elapsed() << endl;
	cout << "AND prepare timer: " << and_prepare_timer.elapsed() << endl;
	cout << "AND wait timer: " << and_wait_timer.elapsed() << endl;
	for (auto& x : timers)
		cout << x.first << " time:" << x.second.elapsed() << endl;
#endif
}

void YaoGarbler::run(GC::Program& program)
{
	singleton = this;

	GC::BreakType b = GC::TIME_BREAK;
	while(GC::DONE_BREAK != b)
	{
		try
		{
			b = program.execute(processor, master.memory, -1);
		}
		catch (needs_cleaning& e)
		{
			if (not continuous())
				throw runtime_error("run-time branching impossible with garbling at once");
			processor.PC--;
		}
		send(*P);
		gates.clear();
		output_masks.clear();
		if (continuous())
			process_receiver_inputs();
	}
}

void YaoGarbler::post_run()
{
	if (not continuous())
	{
		P->send_long(1, YaoCommon::DONE);
		process_receiver_inputs();
	}
}

void YaoGarbler::send(Player& P)
{
#ifdef DEBUG_YAO
	cerr << "sending " << gates.size() << " bytes for gates and "
			<< output_masks.size() << " output masks at " << processor.PC
			<< " in thread " << thread_num << endl;
#endif
	P.send_long(1, YaoCommon::MORE);
	size_t size = gates.size();
	P.send_to(1, gates);
	gates.allocate(2 * size);
	P.send_to(1, output_masks);
}

void YaoGarbler::process_receiver_inputs()
{
	while (not receiver_input_keys.empty())
	{
		vector<Key>& inputs = receiver_input_keys.front();
		BitVector _;
		ot_ext.extend_correlated(inputs.size(), _);

		octetStream os;
		for (size_t i = 0; i < inputs.size(); i++)
			os.serialize(inputs[i] ^ ot_ext.senderOutputMatrices[0][i]);
		player.send(os);

		receiver_input_keys.pop_front();
	}
}

NamedCommStats YaoGarbler::extra_comm()
{
	return player.get_comm_stats();
}
