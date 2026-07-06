/*
 * RealGarbleWire.h
 *
 */

#ifndef BMR_REALGARBLEWIRE_H_
#define BMR_REALGARBLEWIRE_H_

#include "Register.h"

template<class T> class RealProgramParty;
template<class T> class RealGarbleWire;

template<class T>
class GarbleInputter : public InputterBase
{
public:
	RealProgramParty<T>& party;

	Bundle<octetStream> oss;
	PointerVector<pair<RealGarbleWire<T>*, int>> tuples;

	GarbleInputter();
	void exchange();
};

template<class T>
class RealGarbleWire : public PRFRegister
{
	friend class RealProgramParty<T>;
	friend class GarbleInputter<T>;

	T mask;

public:
	typedef GarbleInputter<T> Input;

	static void store(NoMemory& dest,
			const vector<GC::WriteAccess<GC::Secret<RealGarbleWire>>>& accesses);
	static void load(vector<GC::ReadAccess<GC::Secret<RealGarbleWire>>>& accesses,
			const NoMemory& source);

	static void convcbit(Integer& dest, const GC::Clear& source,
	        GC::Processor<GC::Secret<RealGarbleWire>>& processor);

	static void inputb(GC::Processor<GC::Secret<RealGarbleWire>>& processor,
			const ArgVector& args);
	static void inputbvec(GC::Processor<GC::Secret<RealGarbleWire>>& processor,
			ProcessorBase& input_processor, const ArgVector& args);

	void garble(PRFOutputs& prf_output, const RealGarbleWire<T>& left,
			const RealGarbleWire<T>& right);

	void XOR(const RealGarbleWire& left, const RealGarbleWire& right);

	void input(party_id_t from, char input = -1);
	void public_input(bool value);
	void random();
	void output();

	void my_input(Input& Inputter, bool value, int n_bits);
	void other_input(Input& Inputter, int from);
	void finalize_input(Input&, int from, int);
};

template<class T>
class GarbleJob
{
	typedef typename T::Protocol Protocol;
	typedef typename T::Input Inputter;

	T lambda_u, lambda_v, lambda_uv, lambda_w;

public:
	GarbleJob(T lambda_u, T lambda_v, T lambda_w);
	void middle_round(RealProgramParty<T>& party, Protocol& second_protocol);
	void last_round(RealProgramParty<T>& party, Inputter& inputter,
			Protocol& second_protocol, vector<T>& wires);
};

#endif /* BMR_REALGARBLEWIRE_H_ */
