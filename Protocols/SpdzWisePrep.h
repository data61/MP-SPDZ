/*
 * SpdzWisePrep.h
 *
 */

#ifndef PROTOCOLS_SPDZWISEPREP_H_
#define PROTOCOLS_SPDZWISEPREP_H_

#include "ReplicatedPrep.h"

template<class T> class MaliciousShamirShare;

/**
 * Preprocessing for honest-majority protocol with MAC
 */
template<class T>
class SpdzWisePrep : public MaliciousRingPrep<T>
{
    typedef MaliciousRingPrep<T> super;

    void buffer_triples();
    void buffer_squares();
    void buffer_bits();

    void buffer_inputs(int player);

    void buffer_bits(false_type, true_type, false_type);
    void buffer_bits(true_type, true_type, false_type);
    void buffer_bits(true_type, false_type, true_type);
    void buffer_bits(false_type, false_type, false_type);
    void buffer_bits(false_type, false_type, true_type);

public:
    SpdzWisePrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage),
        BitPrep<T>(proc, usage), RingPrep<T>(proc, usage),
        MaliciousDabitOnlyPrep<T>(proc, usage),
        MaliciousRingPrep<T>(proc, usage)
    {
    }
};

#endif /* PROTOCOLS_SPDZWISEPREP_H_ */
