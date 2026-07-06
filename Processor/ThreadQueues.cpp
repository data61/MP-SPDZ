/*
 * ThreadQueues.cpp
 *
 */

#include "ThreadQueues.h"

#include <assert.h>
#include <math.h>

thread_local int ThreadQueues::counter = 0;

ThreadQueues::ThreadQueues() :
        sync_point(0)
{
}

int ThreadQueues::distribute(ThreadJob job, int n_items, int base,
        int granularity)
{
    if (find_available() > 0)
        return distribute_no_setup(job, n_items, base, granularity, 0);
    else
        return base;
}

int ThreadQueues::distribute_with_sync(ThreadJob job, int n_items)
{
    if (find_available() == 0)
        return 0;

    auto res = get_n_per_thread(n_items) * get_n_threads(n_items);
    auto n_threads = get_n_threads(n_items) + (res != n_items);
    if (OnlineOptions::singleton.has_option("debug_sync"))
        cerr << "sync " << n_threads << ", res " << res << "/" << n_items
                << endl;
    if (n_threads > 1)
    {
        assert(not sync_point);
        sync_point = new barrier(n_threads);
    }
    return distribute_no_setup(job, n_items);
}

int ThreadQueues::find_available()
{
#ifdef VERBOSE_QUEUES
    cerr << available.size() << " threads in use" << endl;
#endif
    if (not available.empty())
        return 0;
    for (size_t i = 1; i < size(); i++)
        if (at(i)->available())
            available.push_back(i);
#ifdef VERBOSE_QUEUES
    cerr << "Using " << available.size() << " threads" << endl;
#endif
    return available.size();
}

int ThreadQueues::get_n_per_thread(int n_items, int granularity)
{
    int n_per_thread = int(ceil(n_items / (available.size() + 1.0)) / granularity)
            * granularity;
    return n_per_thread;
}

int ThreadQueues::get_n_threads(int n_items, int base, int granularity)
{
    if (n_items == 0)
        return available.size();

    size_t per_thread = get_n_per_thread(n_items, granularity);
    if (per_thread)
        return min(available.size(), (n_items - base) / per_thread);
    else
        return 0;
}

int ThreadQueues::distribute_no_setup(ThreadJob job, int n_items, int base,
        int granularity, const vector<void*>* supplies)
{
#ifdef VERBOSE_QUEUES
    cerr << "Distribute " << job.type << " among " << available.size() << endl;
#endif

    int n_per_thread = get_n_per_thread(n_items, granularity);
    size_t n_threads = get_n_threads(n_items, base, granularity);

    if (OnlineOptions::singleton.has_option("debug_sync"))
        cerr << n_per_thread << " per thread" << ", " << n_threads << " threads"
                << ", " << available.size() << " available" << endl;

    if (n_items and (n_per_thread == 0 or base + n_per_thread > n_items))
    {
        assert(n_threads == 0);
        available.clear();
        return base;
    }

    for (size_t i = 0; i < available.size(); i++)
    {
        if (base + (i + 1) * n_per_thread > size_t(n_items))
        {
            assert(i);
            available.resize(i);
            assert(n_threads == i);
            return base + i * n_per_thread;
        }
        if (supplies)
            job.supply = supplies->at(i);
        job.begin = base + i * n_per_thread;
        job.end = base + (i + 1) * n_per_thread;
        at(available[i])->schedule(job);
    }
    assert(available.size() == n_threads);
    return base + available.size() * n_per_thread;
}

void ThreadQueues::sync()
{
    bool debug = OnlineOptions::singleton.has_option("debug_sync");

    if (sync_point)
    {
        if (debug)
        {
            fprintf(stderr, "%d wait\n", counter);
            fprintf(stderr, "wait thread %lx\n", long(pthread_self()));
        }
        sync_point->arrive_and_wait();
        if (debug)
        {
            fprintf(stderr, "%d continue\n", counter++);
            fprintf(stderr, "continue thread %lx\n", long(pthread_self()));
        }
    }
    else if (debug)
        fprintf(stderr, "skip sync %lx\n", long(pthread_self()));
}

void ThreadQueues::wrap_up(ThreadJob job)
{
#ifdef VERBOSE_QUEUES
    cerr << "Wrap up " << available.size() << " threads" << endl;
#endif
    for (int i : available)
    {
        auto result = at(i)->result();
        assert(result.output == job.output);
        assert(result.type == job.type);
    }
    available.clear();

    if (sync_point)
    {
        if (OnlineOptions::singleton.has_option("debug_sync"))
            cerr << "stopping sync" << endl;
        delete sync_point;
        sync_point = 0;
    }
}

TimerWithComm ThreadQueues::sum(const string& phase)
{
    TimerWithComm res;
    for (auto& x : *this)
        res += x->timers[phase];
    return res;
}

void ThreadQueues::print_breakdown()
{
    if (size() > 0)
    {
        if (size() == 1)
        {
            cerr << "Spent " << (*this)[0]->timers["online"].full()
                    << " on the online phase and "
                    << (*this)[0]->timers["prep"].full()
                    << " on the preprocessing/offline phase." << endl;
        }
        else
        {
            cerr << size() << " threads spent a total of " << sum("online").full()
                    << " on the online phase, " << sum("prep").full()
                    << " on the preprocessing/offline phase, and "
                    << sum("wait").full() << " idling." << endl;
        }

        if (sum("random").elapsed())
            cerr << "Spent " << sum("random").full()
                    << " on correlated randomness generation." << endl;
    }
}

ThreadStats ThreadQueues::total_stats()
{
    ThreadStats res;
    for (auto& queue : *this)
      res += queue->get_stats();
    return res;
}

NamedCommStats ThreadQueues::max_comm()
{
    NamedCommStats max;
    if (size() > 2)
        for (auto& queue : *this)
            max.imax(queue->get_comm_stats());
    return max;
}
