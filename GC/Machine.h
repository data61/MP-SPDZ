/*
 * Machine.h
 *
 */

#ifndef GC_MACHINE_H_
#define GC_MACHINE_H_

#include "GC/Clear.h"
#include "GC/Memory.h"

#include "Processor/BaseMachine.h"

#include <vector>
using namespace std;

namespace GC
{

class Program;

template <class T>
class Memories
{
public:
    Memory<T> MS;
    Memory<Clear> MC;

    template<class U>
    void reset(const U& program);

    void write_memory(int my_num);
};

template <class T>
class Machine : public ::BaseMachine, public Memories<T>
{
public:
    Memory<Integer> MI;

    vector<Program> progs;

    bool use_encryption;
    bool more_comm_less_comp;

    Machine();
    ~Machine();

    void load_schedule(const string& progname);
    size_t load_program(const string& threadname, const string& filename);

    template<class U>
    void reset(const U& program);
    template<class U, class V>
    void reset(const U& program, V& dynamic_memory);

    void start_timer() { timer[0].start(); }
    void stop_timer() { timer[0].stop(); }
    void reset_timer() { timer[0].reset(); }

    void run_tapes(const ArgVector& args);
    void run_tape(int thread_number, int tape_number, int arg);
    void join_tape(int thread_numer);
};

} /* namespace GC */

#endif /* GC_MACHINE_H_ */
