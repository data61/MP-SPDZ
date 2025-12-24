/*
 * SemiPrep.cpp
 *
 */

#include "SemiPrep.h"

#include "ReplicatedPrep.hpp"
#include "MascotPrep.hpp"
#include "OT/NPartyTripleGenerator.hpp"

template<class T>
SemiPrep<T>::SemiPrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage),
        BitPrep<T>(proc, usage),
        OTPrep<T>(proc, usage),
        RingPrep<T>(proc, usage),
        SemiHonestRingPrep<T>(proc, usage)
{
    this->params.set_passive();
}

template<class T>
void SemiPrep<T>::buffer_triples()
{
    CODE_LOCATION
    assert(this->triple_generator);
    this->triple_generator->set_batch_size(
            BaseMachine::batch_size<T>(DATA_TRIPLE, this->buffer_size));
    this->triple_generator->generatePlainTriples();
    this->triple_generator->set_batch_size(OnlineOptions::singleton.batch_size);
    for (auto& x : this->triple_generator->plainTriples)
    {
        this->triples.push_back({{x[0], x[1], x[2]}});
    }
    this->triple_generator->unlock();
}

template<class T>
bool SemiPrep<T>::bits_from_dabits()
{
    return not T::clear::characteristic_two and BaseMachine::has_singleton()
            and BaseMachine::s().get_N().num_players() == 2;
}

template<class T>
void SemiPrep<T>::buffer_dabits(ThreadQueues* queues)
{
    if (bits_from_dabits())
    {
        CODE_LOCATION
        assert(this->triple_generator);
        this->triple_generator->set_batch_size(
                BaseMachine::batch_size<T>(DATA_DABIT, this->buffer_size, 0, 10));
        this->triple_generator->generatePlainBits();
        for (auto& x : this->triple_generator->plainBits)
            this->dabits.push_back({x.first, x.second});
        this->triple_generator->set_batch_size(OnlineOptions::singleton.batch_size);
    }
    else
        SemiHonestRingPrep<T>::buffer_dabits(queues);
}

template<class T>
void SemiPrep<T>::get_one_no_count(Dtype dtype, T& a)
{
    if (bits_from_dabits())
    {
        if (dtype != DATA_BIT)
            throw not_implemented();

        typename T::bit_type b;
        this->get_dabit_no_count(a, b);
    }
    else
        SemiHonestRingPrep<T>::get_one_no_count(dtype, a);
}
