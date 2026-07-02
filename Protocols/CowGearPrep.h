/*
 * CowGearPrep.h
 *
 */

#ifndef PROTOCOLS_COWGEARPREP_H_
#define PROTOCOLS_COWGEARPREP_H_

#include "Protocols/ReplicatedPrep.h"

class PairwiseMachine;
template<class FD> class PairwiseGenerator;

/**
 * LowGear/CowGear preprocessing
 */
template<class T>
class CowGearPrep : public MaliciousRingPrep<T>
{
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::clear::FD FD;

    static PairwiseMachine* pairwise_machine;
    static Lock lock;

    PairwiseGenerator<typename T::clear::FD>* pairwise_generator;

    PairwiseGenerator<FD>& get_generator();

    template<int>
    void buffer_bits(true_type);
    template<int>
    void buffer_bits(false_type);

public:
    static const bool homomorphic = true;

    static void basic_setup(Player& P);
    static void key_setup(Player& P);
    static void setup(Player& P);
    static void teardown();

    static mac_key_type get_mac_key(Player& P);

    CowGearPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage),
            BitPrep<T>(proc, usage), RingPrep<T>(proc, usage),
            MaliciousDabitOnlyPrep<T>(proc, usage),
            MaliciousRingPrep<T>(proc, usage),
            pairwise_generator(0)
    {
    }
    ~CowGearPrep();

    void buffer_triples();
    void buffer_bits();
    void buffer_inputs(int player);
};

#endif /* PROTOCOLS_COWGEARPREP_H_ */
