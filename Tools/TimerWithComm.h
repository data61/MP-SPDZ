/*
 * TimerWithComm.h
 *
 */

#ifndef TOOLS_TIMERWITHCOMM_H_
#define TOOLS_TIMERWITHCOMM_H_

#include "time-func.h"
#include "Networking/Player.h"

class TimerWithComm : public Timer
{
    NamedCommStats total_stats, last_stats;

public:
    TimerWithComm();
    TimerWithComm(const Timer& other);
    TimerWithComm(double time);

    void start(const NamedCommStats& stats = {});
    void stop(const NamedCommStats& stats = {});

    size_t bytes_sent() const;
    double mb_sent() const;
    size_t rounds() const;

    TimerWithComm operator+(const TimerWithComm& other);
    TimerWithComm operator-(const TimerWithComm& other);
    TimerWithComm& operator+=(const TimerWithComm& other);
    TimerWithComm& operator-=(const TimerWithComm& other);

    string full();

    friend ostream& operator<<(ostream& os, const TimerWithComm& stats);
};

#endif /* TOOLS_TIMERWITHCOMM_H_ */
