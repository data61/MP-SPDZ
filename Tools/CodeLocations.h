/*
 * CodeLocations.h
 *
 */

#ifndef TOOLS_CODELOCATIONS_H_
#define TOOLS_CODELOCATIONS_H_

#include "Lock.h"
#include "time-func.h"

#include <set>
#include <tuple>
#include <string>
using namespace std;

class CodeLocations
{
    typedef tuple<string, int, string> location_type;

    static CodeLocations singleton;

    Lock lock;
    set<location_type> done;

public:
    static void maybe_output(const char* file, int line, const char* function);

    void output(const char* file, int line, const char* function);
};

class LocationScope
{
    string file, function;
    int line;
    bool output_scope;
    bool time_scope;
    Timer timer;

public:
    LocationScope(const char* file, int line, const char* function);
    ~LocationScope();
};

#define CODE_LOCATION LocationScope location_scope(__FILE__, __LINE__, __PRETTY_FUNCTION__);
#define CODE_LOCATION_NO_SCOPE CodeLocations::maybe_output(__FILE__, __LINE__, __PRETTY_FUNCTION__);

#endif /* TOOLS_CODELOCATIONS_H_ */
