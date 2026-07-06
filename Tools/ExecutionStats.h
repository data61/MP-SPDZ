/*
 * ExecutionsStats.h
 *
 */

#ifndef TOOLS_EXECUTIONSTATS_H_
#define TOOLS_EXECUTIONSTATS_H_

#include <map>
using namespace std;

class ExecutionStats : public map<int, size_t>
{
public:
    ExecutionStats& operator+=(const ExecutionStats& other);

    ExecutionStats operator-(const ExecutionStats& other) const;;

    void print() const;
};

#endif /* TOOLS_EXECUTIONSTATS_H_ */
