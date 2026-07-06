/*
 * MascotPrep.h
 *
 */

#ifndef PROTOCOLS_MASCOTPREP_H_
#define PROTOCOLS_MASCOTPREP_H_

#include "ReplicatedPrep.h"
#include "OT/MascotParams.h"
#include "OT/MascotMacKey.h"

template<class T>
class OTPrep : public virtual BitPrep<T>
{
public:
    typename T::TripleGenerator* triple_generator;

    MascotParams params;

    OTPrep(SubProcessor<T>* proc, DataPositions& usage);
    ~OTPrep();

    void set_protocol(typename T::Protocol& protocol);
};

/**
 * MASCOT input tuple generation
 */
template<class T>
class MascotInputPrep : public OTPrep<T>
{
    void buffer_inputs(int player);

public:
    static typename T::mac_key_type get_mac_key(Player& P, bool = false);
    static void teardown();

    MascotInputPrep(SubProcessor<T> *proc, DataPositions &usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            OTPrep<T>(proc, usage)
    {
    }
};

/**
 * MASCOT triple generation
 */
template<class T>
class MascotTriplePrep : public MascotInputPrep<T>
{
public:
    MascotTriplePrep(SubProcessor<T> *proc, DataPositions &usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            MascotInputPrep<T>(proc, usage)
    {
    }

    void buffer_triples();
};

/**
 * MASCOT random bit generation
 */
template<class T>
class MascotDabitOnlyPrep : public virtual MaliciousDabitOnlyPrep<T>,
        public virtual MascotTriplePrep<T>
{
    template<int>
    void buffer_bits(true_type);
    template<int>
    void buffer_bits(false_type);

public:
    MascotDabitOnlyPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            RingPrep<T>(proc, usage),
            MaliciousDabitOnlyPrep<T>(proc, usage),
            MascotTriplePrep<T>(proc, usage)
    {
    }
    virtual ~MascotDabitOnlyPrep()
    {
    }

    virtual void buffer_bits();
};

/**
 * MASCOT preprocessing with edaBits
 */
template<class T>
class MascotPrep : public virtual MaliciousRingPrep<T>,
        public virtual MascotDabitOnlyPrep<T>
{
public:
    static bool bits_from_triples() { return true; }

    MascotPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), BitPrep<T>(proc, usage),
            RingPrep<T>(proc, usage),
            MaliciousDabitOnlyPrep<T>(proc, usage),
            MaliciousRingPrep<T>(proc, usage),
            MascotTriplePrep<T>(proc, usage),
            MascotDabitOnlyPrep<T>(proc, usage)
    {
    }
    virtual ~MascotPrep()
    {
    }

    virtual void buffer_bits()
    {
        MascotDabitOnlyPrep<T>::buffer_bits();
    }

    void buffer_edabits(bool strict, int n_bits, ThreadQueues* queues);
};

template<class T>
class MascotFieldPrep : public virtual MascotPrep<T>
{
public:
    MascotFieldPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage),
            BitPrep<T>(proc, usage), RingPrep<T>(proc, usage),
            MaliciousDabitOnlyPrep<T>(proc, usage),
            MaliciousRingPrep<T>(proc, usage),
            MascotTriplePrep<T>(proc, usage),
            MascotDabitOnlyPrep<T>(proc, usage),
            MascotPrep<T>(proc, usage)
    {
    }
};

template<class T>
typename T::mac_key_type MascotInputPrep<T>::get_mac_key(Player& P, bool)
{
    auto mac_key = T::TripleGenerator::get_mac_key(P);
    T::set_mac_key(mac_key);
    return mac_key;
}

template<class T>
void MascotInputPrep<T>::teardown()
{
	T::TripleGenerator::reset_mac_key();
}

#endif /* PROTOCOLS_MASCOTPREP_H_ */
