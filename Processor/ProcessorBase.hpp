/*
 * ProcessorBase.cpp
 *
 */

#ifndef PROCESSOR_PROCESSORBASE_HPP_
#define PROCESSOR_PROCESSORBASE_HPP_

#include "ProcessorBase.h"
#include "IntInput.h"
#include "FixInput.h"
#include "FloatInput.h"
#include "Instruction.h"
#include "Tools/Exceptions.h"

#include <iostream>

inline
void ProcessorBase::open_input_file(const string& name)
{
#ifdef DEBUG_FILES
    cerr << "opening " << name << endl;
#endif
    input_file.open(name);
    input_filename = name;
}

template<class T>
T ProcessorBase::get_input(bool interactive,
        const ArgVector::value_type* params)
{
    if (interactive)
        return get_input<T>(cin, "standard input", params);
    else
        return get_input<T>(input_file, input_filename, params);
}

template<class T>
T ProcessorBase::get_input(istream& input_file, const string& input_filename,
        const ArgVector::value_type* params)
{
    T res;
    if (input_file.peek() == EOF)
        throw IO_Error("not enough inputs in " + input_filename);
    res.read(input_file, params);
    if (input_file.fail())
    {
        throw input_error(T::NAME, input_filename, input_file, input_counter);
    }
    input_counter++;
    return res;
}

#endif
