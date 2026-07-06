/*
 * AndJob.h
 *
 */

#ifndef BMR_ANDJOB_H_
#define BMR_ANDJOB_H_

#include "GC/Secret.h"
#include "Register.h"
#include "GarbledGate.h"

#include <vector>
using namespace std;

class AndJob
{
	StackedVector< GC::Secret<EvalRegister> >* S;
	const ArgVector* args;

public:
	vector<GarbledGate> gates;
	size_t start, end;
	gate_id_t gate_id;

	AndJob() : S(0), args(0), start(0), end(0), gate_id(0) {}

	void reset(StackedVector<GC::Secret<EvalRegister> >& S, const ArgVector& args,
			size_t start, gate_id_t gate_id, size_t n_gates, int n_parties)
	{
		this->S = &S;
		this->args = &args;
		this->start = start;
		this->end = start;
		this->gate_id = gate_id;
		if (gates.size() < n_gates)
			gates.resize(n_gates, {n_parties});
	}

	int run();
};

#endif /* BMR_ANDJOB_H_ */
