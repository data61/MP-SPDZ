/*
 * ThreadQueues.h
 *
 */

#ifndef PROCESSOR_THREADQUEUES_H_
#define PROCESSOR_THREADQUEUES_H_

#include "Tools/WaitQueue.h"
#include "ThreadJob.h"
#include "ThreadQueue.h"

#include <barrier>

class ThreadQueues :
        public vector<ThreadQueue*>
{
    vector<int> available;

    barrier<>* sync_point;

public:
    thread_local static int counter;

    ThreadQueues();

    int find_available();
    int get_n_per_thread(int n_items, int granularity = 1);
    int get_n_threads(int n_items, int base = 0, int granularity = 1);
    // expects that the last slice is done by the caller
    int distribute(ThreadJob job, int n_items, int base = 0,
            int granularity = 1);
    int distribute_no_setup(ThreadJob job, int n_items, int base = 0,
            int granularity = 1, const vector<void*>* supplies = 0);
    int distribute_with_sync(ThreadJob job, int n_items);
    void sync();
    void wrap_up(ThreadJob job);

    TimerWithComm sum(const string& phase);

    void print_breakdown();

    ThreadStats total_stats();
    NamedCommStats max_comm();
};

#endif /* PROCESSOR_THREADQUEUES_H_ */
