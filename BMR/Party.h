/*
 * Party.h
 *
 */

#ifndef PROTOCOL_PARTY_H_
#define PROTOCOL_PARTY_H_

#include "Register.h"
#include "GarbledGate.h"
#include "network/Node.h"
#include "CommonParty.h"
#include "SpdzWire.h"
#include "AndJob.h"

#include "GC/Machine.h"
#include "GC/Program.h"
#include "GC/Processor.h"
#include "GC/Secret.h"
#include "GC/RuntimeBranching.h"
#include "Tools/Worker.h"

#define SERVER_ID (0)
#define INPUT_KEYS_MSG_TYPE_SIZE (16) // so memory will by aligned

#ifndef N_EVAL_THREADS
// Default Intel desktop processor has 8 half cores.
// This is beneficial if only one AES available per full core.
#define N_EVAL_THREADS (thread::hardware_concurrency())
#endif


class PartyProperties
{
protected:
    party_id_t _id;

	Timer online_timer;

	Key delta;

public:
	PartyProperties() : _id(-1) {}

	party_id_t get_id() { return _id; }
	Key get_delta() { return delta; }

};

class BaseParty : virtual public CommonFakeParty, virtual public PartyProperties
{
public:
    BaseParty();
    virtual ~BaseParty();

	/* From NodeUpdatable class */
	void NodeReady();
	void NewMessage(int from, ReceivedMsg& msg);
	void NodeAborted(struct sockaddr_in* from) { (void)from; }

	void Start();

protected:
	virtual void _compute_prfs_outputs(Key* keys) = 0;
	void _send_prfs();

	virtual void store_garbled_circuit(ReceivedMsg& msg) = 0;
	virtual void _check_evaluate() = 0;

	virtual void mask_output(ReceivedMsg& msg) = 0;
	virtual void mask_input(ReceivedMsg& msg) = 0;

	void done();

	virtual void start_online_round() = 0;

	virtual void receive_spdz_wires(ReceivedMsg& msg) = 0;
};

class ProgramParty : virtual public CommonParty, virtual public PartyProperties, public GC::RuntimeBranching
{
protected:
	friend class PRFRegister;
	friend class EvalRegister;
	friend class Register;

	vector<char> prf_output;

	deque<octetStream> spdz_wires[SPDZ_OP_N];
	size_t spdz_storage;
	size_t garbled_storage;
	vector<size_t> spdz_counters;

	Worker<AndJob>* eval_threads;
	vector<AndJob> and_jobs;

	ReceivedMsgStore output_masks_store;
	ReceivedMsgStore input_masks_store;

	GC::Machine< GC::Secret<EvalRegister> > machine;
	GC::Processor<GC::Secret<EvalRegister> > processor;
	GC::Program program;

	GC::Machine< GC::Secret<PRFRegister> > prf_machine;
	GC::Processor<GC::Secret<PRFRegister> > prf_processor;

	void store_garbled_circuit(ReceivedMsg& msg);
	void load_garbled_circuit();

	virtual void _check_evaluate() = 0;
	virtual void done() = 0;

	virtual void receive_keys(Register& reg) = 0;
	virtual void receive_all_keys(Register& reg, bool external) = 0;
	virtual void process_prf_output(PRFOutputs& prf_output,
			PRFRegister* out, const PRFRegister* left, const PRFRegister* right) = 0;

	void start_online_round();

	void mask_output(ReceivedMsg& msg) { output_masks_store.push(msg); }
	void mask_input(ReceivedMsg& msg) { input_masks_store.push(msg); }

public:
	static ProgramParty* singleton;

	LocalBuffer garbled_circuit;
	ReceivedMsgStore garbled_circuits;

	LocalBuffer output_masks;
	LocalBuffer input_masks;

	Player* P;
	Names N;

	int threshold;

	vector<Integer> convcbit;

	static ProgramParty& s();

	ProgramParty();
	virtual ~ProgramParty();

	void reset();

	void store_wire(const Register& reg);
	void load_wire(Register& reg);
};

template<class T>
class ProgramPartySpec : public ProgramParty
{
	static ProgramPartySpec* singleton;

protected:
	GC::Memory<T> dynamic_memory;

	void _check_evaluate();

public:
	typename T::MAC_Check* MC;

	static ProgramPartySpec& s();

	ProgramPartySpec();
	~ProgramPartySpec();

	void load(string progname);

	void get_spdz_wire(SpdzOp op, DualWire<T>& spdz_wire);
};

typedef ProgramPartySpec<Share<gf2n_long>> FakeProgramPartySuper;

class FakeProgramParty : virtual public BaseParty, virtual public FakeProgramPartySuper
{
    Key* keys_for_prf;

	void _compute_prfs_outputs(Key* keys);

	void store_garbled_circuit(ReceivedMsg& msg) {  ProgramParty::store_garbled_circuit(msg); }

	void _check_evaluate();

	void receive_keys(Register& reg);
	void receive_all_keys(Register& reg, bool external);
	void process_prf_output(PRFOutputs& prf_output, PRFRegister* out,
			const PRFRegister* left, const PRFRegister* right);

	void receive_spdz_wires(ReceivedMsg& msg);

	void start_online_round() { FakeProgramPartySuper::start_online_round(); }

	void mask_output(ReceivedMsg& msg) { ProgramParty::mask_output(msg); }
	void mask_input(ReceivedMsg& msg) { ProgramParty::mask_input(msg); }

	void done() { BaseParty::done(); }

public:
    FakeProgramParty(int argc, const char** argv);
    ~FakeProgramParty();
};

inline ProgramParty& ProgramParty::s()
{
	if (singleton)
		return *singleton;
	else
		throw runtime_error("no singleton");
}

template<class T>
inline ProgramPartySpec<T>& ProgramPartySpec<T>::s()
{
	if (singleton)
		return *singleton;
	else
		throw runtime_error("no singleton");
}

#endif /* PROTOCOL_PARTY_H_ */
