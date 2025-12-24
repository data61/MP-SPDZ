/*
 * HemiPrep.h
 *
 */

#ifndef PROTOCOLS_HEMIPREP_H_
#define PROTOCOLS_HEMIPREP_H_

#include "ReplicatedPrep.h"
#include "FHEOffline/Multiplier.h"

template<class T> class HemiMatrixPrep;

/**
 * Semi-honest triple generation with semi-homomorphic encryption (pairwise)
 */
template<class T>
class HemiPrep : public SemiHonestRingPrep<T>
{
    typedef typename T::clear::FD FD;

    friend class HemiMatrixPrep<T>;

    static PairwiseMachine* pairwise_machine;
    static Lock lock;

    vector<Multiplier<FD>*> multipliers;

    SeededPRNG G;

    map<string, Timer> timers;

    SemiPrep<T>* two_party_prep;

    SemiPrep<T>& get_two_party_prep();

public:
    static const bool homomorphic = true;

    static void basic_setup(Player& P);
    static void teardown();

    static const FHE_PK& get_pk();
    static const FD& get_FTD();

    static bool bits_from_dabits();

    HemiPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage),
            BitPrep<T>(proc, usage), RingPrep<T>(proc, usage),
            SemiHonestRingPrep<T>(proc, usage), two_party_prep(0)
    {
    }
    ~HemiPrep();

    vector<Multiplier<FD>*>& get_multipliers();

    void buffer_triples();

    void buffer_bits();
    void buffer_dabits(ThreadQueues* queues);
};

#endif /* PROTOCOLS_HEMIPREP_H_ */
