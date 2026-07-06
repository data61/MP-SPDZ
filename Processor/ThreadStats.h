/*
 * ThreadStats.h
 *
 */

#ifndef PROCESSOR_THREADSTATS_H_
#define PROCESSOR_THREADSTATS_H_

#include "Networking/Player.h"
#include "Tools/ExecutionStats.h"

class ThreadStats
{
public:
    NamedCommStats comm_stats;
    ExecutionStats exe_stats;

    ThreadStats() = default;

    ThreadStats(const NamedCommStats& comm_stats,
            const ExecutionStats& exe_stats = {});

    ThreadStats& operator+=(const ThreadStats& other);

    ThreadStats operator-(const ThreadStats& other) const;
};

#endif /* PROCESSOR_THREADSTATS_H_ */
