/*
 * MascotPrep.cpp
 *
 */

#ifndef PROTOCOLS_MASCOTPREP_HPP_
#define PROTOCOLS_MASCOTPREP_HPP_

#include "MascotPrep.h"
#include "Processor/Processor.h"
#include "Processor/BaseMachine.h"
#include "OT/OTTripleSetup.h"
#include "OT/Triple.hpp"
#include "OT/NPartyTripleGenerator.hpp"
#include "Protocols/ShuffleSacrifice.hpp"
#include "Protocols/Spdz2kPrep.hpp"
#include "Protocols/ReplicatedPrep.hpp"

template<class T>
OTPrep<T>::OTPrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage), BitPrep<T>(proc, usage),
        triple_generator(0)
{
}

template<class T>
OTPrep<T>::~OTPrep()
{
    if (triple_generator)
        delete triple_generator;
}

template<class T>
void OTPrep<T>::set_protocol(typename T::Protocol& protocol)
{
    BitPrep<T>::set_protocol(protocol);
    SubProcessor<T>* proc = this->proc;
    assert(proc != 0);

    // make sure not to use Montgomery multiplication
    T::open_type::next::template init<typename T::open_type>(false);

    assert(not triple_generator);
    triple_generator = new typename T::TripleGenerator(
            BaseMachine::fresh_ot_setup(proc->P),
            proc->P.N, -1,
            OnlineOptions::singleton.batch_size, 1,
            params, proc->MC.get_alphai(), &proc->P);
    triple_generator->multi_threaded = false;
}

template<class T>
void MascotTriplePrep<T>::buffer_triples()
{
    CODE_LOCATION
#ifdef INSECURE
#ifdef FAKE_MASCOT_TRIPLES
    this->triples.resize(this->triples.size() + OnlineOptions::singleton.batch_size);
    return;
#endif
#endif

    auto& params = this->params;
    auto& triple_generator = this->triple_generator;
    params.generateBits = false;
    triple_generator->set_batch_size(
            BaseMachine::batch_size<T>(DATA_TRIPLE, this->buffer_size));
    triple_generator->generate();
    triple_generator->unlock();
    triple_generator->set_batch_size(OnlineOptions::singleton.batch_size);
    assert(triple_generator->uncheckedTriples.size() != 0);
    for (auto& triple : triple_generator->uncheckedTriples)
        this->triples.push_back(
        {{ triple.a[0], triple.b, triple.c[0] }});
}

template<class T>
void MascotDabitOnlyPrep<T>::buffer_bits()
{
    buffer_bits<0>(T::clear::prime_field);
}

template<class T>
template<int>
void MascotDabitOnlyPrep<T>::buffer_bits(true_type)
{
    buffer_bits_from_squares(*this);
}

template<class T>
template<int>
void MascotDabitOnlyPrep<T>::buffer_bits(false_type)
{
    this->params.generateBits = true;
    auto& triple_generator = this->triple_generator;
    triple_generator->set_batch_size(
            BaseMachine::batch_size<T>(DATA_BIT, this->buffer_size));
    triple_generator->generate();
    triple_generator->unlock();
    assert(triple_generator->bits.size() != 0);
    for (auto& bit : triple_generator->bits)
        this->bits.push_back(bit);
}

template<class T>
void MascotInputPrep<T>::buffer_inputs(int player)
{
    auto& triple_generator = this->triple_generator;
    assert(triple_generator);
    triple_generator->set_batch_size(
            BaseMachine::input_batch_size<T>(player, this->buffer_size));
    triple_generator->generateInputs(player);
    if (this->inputs.size() <= (size_t)player)
        this->inputs.resize(player + 1);
    for (auto& input : triple_generator->inputs)
        this->inputs[player].push_back(input);
}

#endif
