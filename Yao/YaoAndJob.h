/*
 * YaoAndJob.h
 *
 */

#ifndef YAO_YAOANDJOB_H_
#define YAO_YAOANDJOB_H_

#include "YaoGarbleWire.h"
#include "Tools/Worker.h"

enum YaoJobType
{
	YAO_AND_JOB,
	YAO_XOR_JOB,
	YAO_NO_JOB
};

template<class T>
class YaoAndJob
{
	GC::Processor< GC::Secret<T> >* processor;
	const ArgVector* args;
	size_t start, end, n_gates;
	YaoGate* gate;
	long counter;
	PRNG prng;
	map<string, Timer> timers;
	bool repeat;
	typename T::Party& party;
	YaoJobType type;

public:
	Worker<YaoAndJob> worker;

	YaoAndJob(typename T::Party& party) :
			processor(0), args(0), start(0), end(0), n_gates(0), gate(0),
			counter(0), repeat(0), party(party), type(YAO_NO_JOB)
	{
		prng.ReSeed();
	}

	~YaoAndJob()
	{
#ifdef VERBOSE
		for (auto& x : timers)
			cerr << x.first << " time:" << x.second.elapsed() << endl;
#endif
	}

	void dispatch(YaoJobType type,
			GC::Processor<GC::Secret<T> >& processor, const ArgVector& args,
			size_t start, size_t end, size_t n_gates,
			YaoGate* gate, long counter, bool repeat)
	{
		this->type = type;
		this->processor = &processor;
		this->args = &args;
		this->start = start;
		this->end = end;
		this->n_gates = n_gates;
		this->gate = gate;
		this->counter = counter;
		this->repeat = repeat;
		worker.request(*this);
	}

	int run()
	{
		switch(type)
		{
		case YAO_AND_JOB:
			T::and_(processor->S, *args, start, end, n_gates, gate, counter,
					prng, timers, repeat, party);
			break;
		case YAO_XOR_JOB:
			T::xors(*processor, *args, start, end);
			break;
		default:
			throw runtime_error("job not specified: " + to_string(type));
		}

		type = YAO_NO_JOB;
		return 0;
	}
};

#endif /* YAO_YAOANDJOB_H_ */
