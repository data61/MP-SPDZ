/*
 * ChaiGearPrep.h
 *
 */

#ifndef PROTOCOLS_CHAIGEARPREP_H_
#define PROTOCOLS_CHAIGEARPREP_H_

#include "FHEOffline/SimpleGenerator.h"

/**
 * HighGear/ChaiGear preprocessing
 */
template<class T>
class ChaiGearPrep : public MaliciousRingPrep<T>
{
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::clear::FD FD;
    typedef SimpleGenerator<SummingEncCommit, FD> Generator;

    static MultiplicativeMachineParams* machine;
    static Lock lock;

    Generator* generator;
    SquareProducer<FD>* square_producer;
    InputProducer<FD>* input_producer;

    Generator& get_generator();

    template<int>
    void buffer_bits(true_type);
    template<int>
    void buffer_bits(false_type);

public:
    static const bool homomorphic = true;

    static void basic_setup(Player& P);
    static void key_setup(Player& P);
    static void teardown();

    static mac_key_type get_mac_key(Player& P);

    ChaiGearPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            RingPrep<T>(proc, usage),
            MaliciousDabitOnlyPrep<T>(proc, usage),
            MaliciousRingPrep<T>(proc, usage), generator(0), square_producer(0),
            input_producer(0)
    {
    }
    ~ChaiGearPrep();

    void buffer_triples();
    void buffer_squares();
    void buffer_bits();
    void buffer_inputs(int player);
};

#endif /* PROTOCOLS_CHAIGEARPREP_H_ */
