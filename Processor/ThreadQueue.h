/*
 * ThreadQueue.h
 *
 */

#ifndef PROCESSOR_THREADQUEUE_H_
#define PROCESSOR_THREADQUEUE_H_

#include "ThreadJob.h"
#include "Tools/NamedStats.h"

class ThreadQueue
{
    WaitQueue<ThreadJob> in, out;
    Lock lock;
    int left;
    NamedCommStats comm_stats;

public:
    static thread_local ThreadQueue* thread_queue;

    map<string, TimerWithComm> timers;
    Timer wait_timer;
    NamedStats stats;

    ThreadQueue() :
            left(0)
    {
    }

    bool available()
    {
        return left == 0;
    }

    void schedule(const ThreadJob& job);
    ThreadJob next();
    void finished(const ThreadJob& job);
    void finished(const ThreadJob& job, const NamedCommStats& comm_stats,
            const NamedStats& stats = {});
    ThreadJob result();

    void set_comm_stats(const NamedCommStats& new_comm_stats);
    NamedCommStats get_comm_stats();
};

#endif /* PROCESSOR_THREADQUEUE_H_ */
