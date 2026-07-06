/*
 * TimerWithComm.h
 *
 */

#ifndef TOOLS_TIMERWITHCOMM_H_
#define TOOLS_TIMERWITHCOMM_H_

#include "time-func.h"
#include "Networking/Player.h"
#include "Processor/ThreadStats.h"

class TimerWithComm : public Timer
{
    ThreadStats total_stats, last_stats;
    Timer cpu_timer;

public:
    TimerWithComm(const Timer& other = {});
    TimerWithComm(double time);

    void start(const ThreadStats& stats = {});
    void stop(const ThreadStats& stats = {});

    size_t bytes_sent() const;
    double mb_sent() const;
    size_t rounds() const;

    const ExecutionStats& exe_stats() const;

    TimerWithComm operator+(const TimerWithComm& other);
    TimerWithComm operator-(const TimerWithComm& other);
    TimerWithComm& operator+=(const TimerWithComm& other);
    TimerWithComm& operator-=(const TimerWithComm& other);

    string full();

    friend ostream& operator<<(ostream& os, const TimerWithComm& stats);
};

#endif /* TOOLS_TIMERWITHCOMM_H_ */
