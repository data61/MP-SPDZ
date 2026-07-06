/*
 * YaoCommon.cpp
 *
 */

#include "YaoCommon.h"

template<class T>
vector<array<size_t, 2> > YaoCommon<T>::get_splits(const ArgVector& args,
		int threshold, int total)
{
	vector<array<size_t, 2>> res;
	size_t max_gates_per_thread = max(threshold / 2,
			(total + get_n_worker_threads() - 1) / get_n_worker_threads());
	size_t i_gate = 0;
	for (auto it = args.begin(); it < args.end(); it += 4)
	{
		i_gate += *it;
		auto end = it + 4;
		if (i_gate >= max_gates_per_thread or end >= args.end())
		{
			res.push_back({{i_gate, size_t(end - args.begin())}});
			i_gate = 0;
		}
	}
	return res;
}
