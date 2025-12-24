#ifndef _timer
#define _timer

#include <sys/wait.h>   /* Wait for Process Termination */
#include <sys/time.h>
#include <time.h>
#include <string>

#include "Tools/Exceptions.h"

long long timeval_diff(struct timeval *start_time, struct timeval *end_time);
double timeval_diff_in_seconds(struct timeval *start_time, struct timeval *end_time);
long long timespec_diff(const struct timespec *start_time, const struct timespec *end_time);

class TimeScope;

class Timer
{
  friend class TimeScope;

  public:
  Timer(clockid_t clock_id = CLOCK_MONOTONIC) : running(false), elapsed_time(0), clock_id(clock_id)
      { clock_gettime(clock_id, &startv); }
  Timer(double time) : Timer()
      { elapsed_time = time * 1e9; }
  Timer& start();
  void stop();
  void reset();

  double elapsed() const;
  double elapsed_then_reset();
  double idle();

  bool is_running();

  Timer& operator-=(const Timer& other);
  Timer& operator+=(const Timer& other);
  Timer& operator+=(const TimeScope& other);

  Timer operator+(const Timer& other) const;

  bool operator<(const Timer& other) const;

  private:
  timespec startv;
  bool running;
  long long elapsed_time;
  clockid_t clock_id;

  long long elapsed_since_last_start() const;
};

class TimeScope
{
  friend class Timer;
  Timer& timer;

public:
  TimeScope(Timer& timer) : timer(timer) { timer.start(); }
  ~TimeScope();
};

class DoubleTimer
{
  Timer wall, thread;

public:
  DoubleTimer() : thread(CLOCK_THREAD_CPUTIME_ID) {}
  void start() { wall.start(); thread.start(); }
  void stop() { wall.stop(); thread.stop(); }
  string elapsed()
  { return to_string(thread.elapsed()) + "/" + to_string(wall.elapsed()); }
};

class RunningTimer : public Timer
{
public:
  RunningTimer() { start(); }
};

inline Timer& Timer::start()
{
  if (running)
    throw Processor_Error("Timer already running.");
  // clock() is not suitable in threaded programs so time using something else
  clock_gettime(clock_id, &startv);
  running = true;
  return *this;
}

inline void Timer::stop()
{
  if (!running)
    throw Processor_Error("Time not running.");
  elapsed_time += elapsed_since_last_start();

  running = false;
  clock_gettime(clock_id, &startv);
}

inline void Timer::reset()
{
  elapsed_time = 0;
  clock_gettime(clock_id, &startv);
}

inline long long Timer::elapsed_since_last_start() const
{
  timespec endv;
  clock_gettime(clock_id, &endv);
  return timespec_diff(&startv, &endv);
}

#endif

