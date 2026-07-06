/*
 * TimerWithComm.cpp
 *
 */

#include "TimerWithComm.h"

TimerWithComm::TimerWithComm(const Timer& other) :
        Timer(other), cpu_timer(CLOCK_PROCESS_CPUTIME_ID)
{
}

TimerWithComm::TimerWithComm(double time) :
        TimerWithComm(Timer(time))
{
}

void TimerWithComm::start(const ThreadStats& stats)
{
    Timer::start();
    last_stats = stats;
    cpu_timer.start();
}

void TimerWithComm::stop(const ThreadStats& stats)
{
    Timer::stop();
    total_stats += stats - last_stats;
    cpu_timer.stop();
}

size_t TimerWithComm::bytes_sent() const
{
    return total_stats.comm_stats.sent;
}

double TimerWithComm::mb_sent() const
{
    return total_stats.comm_stats.sent * 1e-6;
}

size_t TimerWithComm::rounds() const
{
    size_t res = 0;
    for (auto& x : total_stats.comm_stats)
        res += x.second.rounds;
    return res;
}

TimerWithComm TimerWithComm::operator +(const TimerWithComm& other)
{
    TimerWithComm res = *this;
    res += other;
    return res;
}

TimerWithComm TimerWithComm::operator -(const TimerWithComm& other)
{
    TimerWithComm res = *this;
    res.Timer::operator-=(other);
    res.total_stats = total_stats - other.total_stats;
    return res;
}

TimerWithComm& TimerWithComm::operator +=(const TimerWithComm& other)
{
    Timer::operator+=(other);
    total_stats += other.total_stats;
    return *this;
}

TimerWithComm& TimerWithComm::operator -=(const TimerWithComm& other)
{
    *this = *this - other;
    return *this;
}

string TimerWithComm::full()
{
    stringstream tmp;
    tmp << elapsed() << " seconds";
    if (mb_sent() > 0)
        tmp << " (" << *this << ")";
    return tmp.str();
}

const ExecutionStats& TimerWithComm::exe_stats() const
{
    return total_stats.exe_stats;
}

ostream& operator<<(ostream& os, const TimerWithComm& stats)
{
    os << stats.mb_sent() << " MB, " << stats.rounds() << " rounds, "
            << stats.cpu_timer.elapsed() << " CPU seconds";
    return os;
}
