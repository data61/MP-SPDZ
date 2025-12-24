/*
 * YaoGarbler.h
 *
 */

#ifndef YAO_YAOGARBLER_H_
#define YAO_YAOGARBLER_H_

#include "YaoGarbleWire.h"
#include "YaoAndJob.h"
#include "YaoGarbleMaster.h"
#include "YaoCommon.h"
#include "Tools/random.h"
#include "Tools/MMO.h"
#include "GC/Secret.h"
#include "Networking/Player.h"
#include "OT/OTExtensionWithMatrix.h"

#include <thread>

class YaoGarbler: public GC::Thread<GC::Secret<YaoGarbleWire>>,
		public YaoCommon<YaoGarbleWire>
{
	friend class YaoGarbleWire;
	friend class YaoCommon<YaoGarbleWire>;

	typedef GC::Thread<GC::Secret<YaoGarbleWire>> super;

protected:
	static thread_local YaoGarbler* singleton;

	YaoGarbleMaster& master;

	SendBuffer gates;

	Timer and_timer;
	Timer and_proc_timer;
	Timer and_main_thread_timer;
	DoubleTimer and_prepare_timer;
	DoubleTimer and_wait_timer;

public:
	PRNG prng;
	SendBuffer output_masks;
	MMO mmo;

	map<string, Timer> timers;

	RealTwoPartyPlayer player;
	OTExtensionWithMatrix ot_ext;

	deque<vector<Key>> receiver_input_keys;

	static YaoGarbler& s();

	YaoGarbler(int thread_num, YaoGarbleMaster& master);
	~YaoGarbler();

	bool continuous() { return master.continuous; }

	void run(GC::Program& program);
	void run(Player& P, bool continuous);
	void post_run();
	void send(Player& P);

	void process_receiver_inputs();

	Key get_delta() { return master.get_delta(); }
	void store_gate(const YaoGate& gate);

	int get_threshold() { return master.threshold; }

	long get_gate_id() { return gate_id(thread_num); }

    NamedCommStats extra_comm();
};

inline YaoGarbler& YaoGarbler::s()
{
	if (singleton)
		return *singleton;
	else
		throw runtime_error("singleton unavailable");
}

#endif /* YAO_YAOGARBLER_H_ */
