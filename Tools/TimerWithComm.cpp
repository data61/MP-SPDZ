/*
 * TimerWithComm.cpp
 *
 */

#include "TimerWithComm.h"

TimerWithComm::TimerWithComm()
{
}

TimerWithComm::TimerWithComm(const Timer& other) :
        Timer(other)
{
}

TimerWithComm::TimerWithComm(double time) :
        Timer(time)
{
}

void TimerWithComm::start(const NamedCommStats& stats)
{
    Timer::start();
    last_stats = stats;
}

void TimerWithComm::stop(const NamedCommStats& stats)
{
    Timer::stop();
    total_stats += stats - last_stats;
}

size_t TimerWithComm::bytes_sent() const
{
    return total_stats.sent;
}

double TimerWithComm::mb_sent() const
{
    return total_stats.sent * 1e-6;
}

size_t TimerWithComm::rounds() const
{
    size_t res = 0;
    for (auto& x : total_stats)
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

ostream& operator<<(ostream& os, const TimerWithComm& stats)
{
    os << stats.mb_sent() << " MB, " << stats.rounds() << " rounds";
    return os;
}
