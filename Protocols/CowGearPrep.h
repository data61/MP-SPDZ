/*
 * CowGearPrep.h
 *
 */

#ifndef PROTOCOLS_COWGEARPREP_H_
#define PROTOCOLS_COWGEARPREP_H_

#include "Protocols/ReplicatedPrep.h"

class PairwiseMachine;
template<class FD> class PairwiseGenerator;

template<class T>
typename T::mac_key_type get_mac_key(Player& P, bool read_only);

/**
 * LowGear/CowGear preprocessing
 */
template<class T>
class CowGearPrep : public MaliciousRingPrep<T>
{
public:
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::clear::FD FD;

private:
    template<class U>
    friend typename U::mac_key_type get_mac_key(Player& P, bool read_only);

    static PairwiseMachine* machine;
    static Lock lock;

    // setting this non-randomly is a security violation
    static mac_key_type maybe_mac_key;

    PairwiseGenerator<typename T::clear::FD>* pairwise_generator;

    PairwiseGenerator<FD>& get_generator();

    template<int>
    void buffer_bits(true_type);
    template<int>
    void buffer_bits(false_type);

public:
    typedef T share_type;

    static const bool homomorphic = true;

    static void basic_setup(Player& P, bool read_only = false);
    static void key_setup(Player& P, bool read_only = false);
    static void setup(Player& P);
    static void teardown();

    static mac_key_type get_mac_key(Player& P, bool read_only = false);
    static void adjust_mac_key(Player& P);

    static string get_full_secrets_filename(const Player& P);

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
