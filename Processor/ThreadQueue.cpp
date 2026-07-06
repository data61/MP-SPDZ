/*
 * ThreadQueue.cpp
 *
 */


#include "ThreadQueue.h"

#include <chrono>

thread_local ThreadQueue* ThreadQueue::thread_queue = 0;

void ThreadQueue::schedule(const ThreadJob& job)
{
    lock.lock();
    left++;
#ifdef DEBUG_THREAD_QUEUE
        cerr << this << ": " << left << " left" << endl;
#endif
    lock.unlock();
    if (thread_queue)
        thread_queue->wait_timer.start();
    in.push(job);
    if (thread_queue)
        thread_queue->wait_timer.stop();

    if (debug)
        fprintf(stderr, "schedule for thread %lx from %lx at %f\n", long(this),
                pthread_self(), timer.elapsed());
}

ThreadJob ThreadQueue::next()
{
    if (debug)
        fprintf(stderr, "wait for next in thread %lx at %f\n", long(this),
                timer.elapsed());

    TimeScope scope(inside_wait_timer);
    auto res = in.pop();

    if (debug)
        fprintf(stderr, "done waiting in thread %lx at %f (wait time %f)\n",
                long(this), timer.elapsed(), inside_wait_timer.elapsed());

    return res;
}

void ThreadQueue::finished(const ThreadJob& job)
{
    TimeScope scope(inside_wait_timer);
    out.push(job);
}

void ThreadQueue::finished(const ThreadJob& job,
        const ThreadStats& thread_stats, const NamedStats& stats)
{
    finished(job);
    set_stats(thread_stats);
    this->stats = stats;
}

void ThreadQueue::set_stats(const ThreadStats& new_stats)
{
    lock.lock();
    thread_stats = new_stats;
    lock.unlock();
}

ThreadJob ThreadQueue::result()
{
    if (thread_queue)
        thread_queue->wait_timer.start();
    auto res = out.pop();
    if (thread_queue)
        thread_queue->wait_timer.stop();
    lock.lock();
    left--;
#ifdef DEBUG_THREAD_QUEUE
        cerr << this << ": " << left << " left" << endl;
#endif
    lock.unlock();
    return res;
}
NamedCommStats ThreadQueue::get_comm_stats()
{
    lock.lock();
    auto res = thread_stats.comm_stats;
    lock.unlock();
    return res;
}


ThreadStats ThreadQueue::get_stats()
{
    lock.lock();
    auto res = thread_stats;
    lock.unlock();
    return res;
}

void ThreadQueue::start_timer()
{
    debug = OnlineOptions::singleton.has_option("debug_timers");
    timer.start();
}

void ThreadQueue::stop_timer(Player& P)
{
    timer.stop(P.total_comm());

    timers["wait"] = inside_wait_timer + wait_timer;
    timers["online"] = online_timer - online_prep_timer;
    timers["prep"] = timer - inside_wait_timer - timers["online"];

    if (debug)
    {
        cerr << "Total thread time: " << timer.elapsed() << endl;
        cerr << "Inside wait time: " << inside_wait_timer.elapsed() << endl;
        cerr << "Other wait time: " << wait_timer.elapsed() << endl;
        cerr << "Online time: " << online_timer.elapsed() << endl;
        cerr << "Online prep time: " << online_prep_timer.elapsed() << endl;
    }
}

void ThreadQueue::start_online(Player& P, const TimerWithComm& prep_time)
{
    online_timer.start(P.total_comm());
    online_prep_timer -= prep_time;

    if (debug)
        fprintf(stderr, "start online thread %lx timer at %f\n", long(this),
                timer.elapsed());
}

void ThreadQueue::stop_online(Player& P, const TimerWithComm& prep_time)
{
    online_timer.stop(P.total_comm());
    online_prep_timer += prep_time;

    if (debug)
        fprintf(stderr, "stop online thread %lx timer at %f\n", long(this),
                timer.elapsed());
}
