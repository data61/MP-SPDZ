
#include "Tools/time-func.h"
#include "Tools/Exceptions.h"
#include "Processor/OnlineOptions.h"

#include <assert.h>

long long timeval_diff(struct timeval *start_time, struct timeval *end_time)
{ struct timeval temp_diff;
  struct timeval *difference;
  difference=&temp_diff;
  difference->tv_sec =end_time->tv_sec -start_time->tv_sec ;
  difference->tv_usec=end_time->tv_usec-start_time->tv_usec;
  while(difference->tv_usec<0)
  { difference->tv_usec+=1000000;
    difference->tv_sec -=1;
  }
  return 1000000LL*difference->tv_sec+difference->tv_usec;
}

double timeval_diff_in_seconds(struct timeval *start_time, struct timeval *end_time)
{
    return double(timeval_diff(start_time, end_time)) / 1e6;
}


long long timespec_diff(const struct timespec *start_time, const struct timespec *end_time)
{
  long long sec =end_time->tv_sec -start_time->tv_sec ;
  long long nsec=end_time->tv_nsec-start_time->tv_nsec;
  while(nsec<0)
  { nsec+=1000000000;
    sec -=1;
  }
  return 1000000000*sec+nsec;
}


double convert_ns_to_seconds(long long x)
{
  return double(x) / 1e9;
}


double Timer::elapsed() const
{
  long long res = elapsed_time;
  if (running)
    res += elapsed_since_last_start();
  return convert_ns_to_seconds(res);
}

double Timer::elapsed_then_reset()
{
  double res = elapsed();
  reset();
  return res;
}

double Timer::idle()
{
  if (running)
    throw Processor_Error("Timer running.");
  else
    return convert_ns_to_seconds(elapsed_since_last_start());
}

bool Timer::is_running()
{
  return running;
}

Timer& Timer::operator -=(const Timer& other)
{
  assert(clock_id == other.clock_id);
  assert(not running);
  assert(not other.running);
  elapsed_time -= other.elapsed_time;
  return *this;
}

Timer& Timer::operator +=(const Timer& other)
{
  assert(clock_id == other.clock_id);
  assert(not running);
  elapsed_time += other.elapsed_time
      + other.running * other.elapsed_since_last_start();
  return *this;
}

Timer& Timer::operator +=(const TimeScope& other)
{
  assert(clock_id == other.timer.clock_id);
  assert(not running);
  elapsed_time += other.timer.elapsed_since_last_start();
  return *this;
}

Timer Timer::operator +(const Timer& other) const
{
  Timer res = *this;
  res += other;
  return res;
}

bool Timer::operator <(const Timer& other) const
{
  return elapsed() < other.elapsed();
}

TimeScope::~TimeScope()
{
  if (OnlineOptions::singleton.has_option("verbose_comm_time"))
    fprintf(stderr, "took %f seconds\n",
	convert_ns_to_seconds(timer.elapsed_since_last_start()));
  timer.stop();
}
