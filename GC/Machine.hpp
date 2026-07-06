/*
 * Machine.cpp
 *
 */

#ifndef GC_MACHINE_HPP_
#define GC_MACHINE_HPP_

#include <GC/Machine.h>

#include "GC/Program.h"
#include "ThreadMaster.h"

#include "Program.hpp"

namespace GC
{

template <class T>
Machine<T>::Machine()
{
    use_encryption = false;
    more_comm_less_comp = false;
    start_timer();
}

template<class T>
Machine<T>::~Machine()
{
#ifdef VERBOSE
    for (auto it = timer.begin(); it != timer.end(); it++)
        cerr << T::phase_name() << " timer " << it->first << " at end: "
                << it->second.elapsed() << " seconds" << endl;
#endif
}

template<class T>
size_t Machine<T>::load_program(const string& threadname,
        const string& filename)
{
    (void)threadname;
    progs.push_back({});
    progs.back().parse_file(filename);
    reset(progs.back());
    return progs.back().size();
}

template<class T>
void Machine<T>::load_schedule(const string& progname)
{
    BaseMachine::load_schedule(progname);
    print_compiler();
}

template <class T>
template <class U>
void Memories<T>::reset(const U& program)
{
    MS.resize_min(program.direct_mem(SBIT), "memory");
    MC.resize_min(program.direct_mem(CBIT), "memory");
}

template <class T>
template <class U>
void Machine<T>::reset(const U& program)
{
    Memories<T>::reset(program);
    MI.resize_min(program.direct_mem(INT), "memory");
}

template <class T>
template <class U, class V>
void Machine<T>::reset(const U& program, V& MD)
{
    reset(program);
    MD.resize_min(program.direct_mem(DYN_SBIT), "dynamic memory");
#ifdef DEBUG_MEMORY
    cerr << "reset dynamic mem to " << program.direct_mem(DYN_SBIT) << endl;
#endif
}

template<class T>
void Machine<T>::run_tapes(const ArgVector& args)
{
    assert(args.size() % 3 == 0);
    for (unsigned i = 0; i < args.size(); i += 3)
        run_tape(args[i], args[i + 1], args[i + 2]);
}

template<class T>
void Machine<T>::run_tape(int thread_number, int tape_number, int arg)
{
    ThreadMaster<T>::s().run_tape(thread_number, tape_number, arg);
}

template<class T>
void Machine<T>::join_tape(int thread_number)
{
    ThreadMaster<T>::s().join_tape(thread_number);
}

template<class T>
void Memories<T>::write_memory(int my_num)
{
    ofstream outf(BaseMachine::memory_filename("B", my_num));
    outf << 0 << endl;
    outf << MC.size() << endl << MC;
    outf << 0 << endl << 0 << endl << 0 << endl << 0 << endl;
}

} /* namespace GC */

#endif
