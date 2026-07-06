/*
 * ThreadStats.cpp
 *
 */

#include "ThreadStats.h"

ThreadStats::ThreadStats(const NamedCommStats& comm_stats,
        const ExecutionStats& exe_stats) :
        comm_stats(comm_stats), exe_stats(exe_stats)
{
}

ThreadStats& ThreadStats::operator +=(const ThreadStats& other)
{
    comm_stats += other.comm_stats;
    exe_stats += other.exe_stats;
    return *this;
}

ThreadStats ThreadStats::operator -(const ThreadStats& other) const
{
    ThreadStats res;
    res.comm_stats = comm_stats - other.comm_stats;
    res.exe_stats = exe_stats - other.exe_stats;
    return res;
}
