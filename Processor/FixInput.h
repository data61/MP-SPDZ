/*
 * FixInput.h
 *
 */

#ifndef PROCESSOR_FIXINPUT_H_
#define PROCESSOR_FIXINPUT_H_

#include <iostream>

#include "Math/bigint.h"
#include "Math/Integer.h"
#include "Instruction.h"

template<class T>
class FixInput_
{
public:
    const static int N_DEST = 1;
    const static int N_PARAM = 1;
    const static char* NAME;

    const static int TYPE = 1;

    T items[N_DEST];

    void read(std::istream& in, const ArgVector::value_type* params);
};

template<class T>
const char* FixInput_<T>::NAME = "real number";

#ifdef LOW_PREC_INPUT
typedef FixInput_<Integer> FixInput;
#else
typedef FixInput_<bigint> FixInput;
#endif

#endif /* PROCESSOR_FIXINPUT_H_ */
