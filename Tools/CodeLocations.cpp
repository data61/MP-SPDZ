/*
 * CodeLocations.cpp
 *
 */

#include "CodeLocations.h"
#include "Processor/OnlineOptions.h"

CodeLocations CodeLocations::singleton;

void CodeLocations::maybe_output(const char* file, int line,
        const char* function)
{
    if (OnlineOptions::singleton.code_locations)
        singleton.output(file, line, function);
}

void CodeLocations::output(const char* file, int line,
        const char* function)
{
    location_type location({file, line, function});
    lock.lock();
    bool always = OnlineOptions::singleton.has_option("all_locations");
    if (always or done.find(location) == done.end())
    {
        if (not always)
            cerr << "first ";
        cerr << "call to " << file << ":" << line << ", " << function
                << endl;
    }
    done.insert(location);
    lock.unlock();
}

LocationScope::LocationScope(const char* file, int line, const char* function) :
        file(file), function(function), line(line)
{
    output_scope = OnlineOptions::singleton.has_option("location_scope");
    time_scope = OnlineOptions::singleton.has_option("location_time");
    if (output_scope)
        cerr << "call to " << file << ":" << line << ", " << function
                << endl;
    else
        CodeLocations::maybe_output(file, line, function);
    if (time_scope)
        timer.start();
}

LocationScope::~LocationScope()
{
    if (output_scope or time_scope)
    {
        stringstream desc;
        desc << file << ":" << line << ", " << function;

        if (time_scope)
        {
            auto time = timer.elapsed() * 1e6;
            cerr << "after " << time << " microseconds, ";
        }

        cerr << "leaving " << desc.str() << endl;
    }
}
