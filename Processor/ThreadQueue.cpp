/*
 * ThreadQueue.cpp
 *
 */


#include "ThreadQueue.h"

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
}

ThreadJob ThreadQueue::next()
{
    TimeScope scope(inside_wait_timer);
    return in.pop();
}

void ThreadQueue::finished(const ThreadJob& job)
{
    TimeScope scope(inside_wait_timer);
    out.push(job);
}

void ThreadQueue::finished(const ThreadJob& job,
        const NamedCommStats& new_comm_stats, const NamedStats& stats)
{
    finished(job);
    set_comm_stats(new_comm_stats);
    this->stats = stats;
}

void ThreadQueue::set_comm_stats(const NamedCommStats& new_comm_stats)
{
    lock.lock();
    comm_stats = new_comm_stats;
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
    auto res = comm_stats;
    lock.unlock();
    return res;
}

void ThreadQueue::start_timer()
{
    timer.start();
}

void ThreadQueue::stop_timer(Player& P)
{
    timer.stop(P.total_comm());
    timers["wait"] = inside_wait_timer + wait_timer;
    timers["online"] = online_timer - online_prep_timer - wait_timer;
    timers["prep"] = timer - timers["wait"] - timers["online"];
}

void ThreadQueue::start_online(Player& P, const TimerWithComm& prep_time)
{
    online_timer.start(P.total_comm());
    online_prep_timer -= prep_time;
}

void ThreadQueue::stop_online(Player& P, const TimerWithComm& prep_time)
{
    online_timer.stop(P.total_comm());
    online_prep_timer += prep_time;
}
