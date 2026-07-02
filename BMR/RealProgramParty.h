/*
 * RealProgramParty.h
 *
 */

#ifndef BMR_REALPROGRAMPARTY_H_
#define BMR_REALPROGRAMPARTY_H_

#include "Party.h"
#include "RealGarbleWire.h"

#include "GC/Machine.h"
#include "GC/RuntimeBranching.h"
#include "Processor/Processor.h"

template<class T>
class RealProgramParty : public ProgramPartySpec<T>
{
	typedef typename T::Input Inputter;

	friend class RealGarbleWire<T>;
	friend class GarbleInputter<T>;
	friend class GarbleJob<T>;

	static RealProgramParty* singleton;

	GC::Machine<GC::Secret<RealGarbleWire<T>>> garble_machine;
	GC::Processor<GC::Secret<RealGarbleWire<T>>> garble_processor;

	DataPositions usage;
	Preprocessing<T>* prep;
	SubProcessor<T>* shared_proc;

	ArithmeticProcessor dummy_proc;

	vector<T> deltas;

	Inputter* garble_inputter;
	typename T::Protocol* garble_protocol;
	vector<GarbleJob<T>> garble_jobs;

	GC::BreakType next;

	bool one_shot;

	typename T::mac_key_type mac_key;

public:
	static RealProgramParty& s();

	LocalBuffer garble_input_masks, garble_output_masks;

	RealProgramParty(int argc, const char** argv);
	~RealProgramParty();

	void garble();

	void receive_keys(Register& reg);
	void receive_all_keys(Register& reg, bool external);
	void process_prf_output(PRFOutputs& prf_output, PRFRegister* out,
			const PRFRegister* left, const PRFRegister* right);

	void push_spdz_wire(SpdzOp op, const RealGarbleWire<T>& wire);

	void done() {}

	T shared_delta(int i) { return deltas[i]; }
};

template<class T>
inline RealProgramParty<T>& RealProgramParty<T>::s()
{
	if (singleton)
		return *singleton;
	else
		throw runtime_error("no singleton");
}

#endif /* BMR_REALPROGRAMPARTY_H_ */
