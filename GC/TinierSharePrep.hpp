/*
 * TinierSharePrep.cpp
 *
 */

#ifndef GC_TINIERSHARE_PREP_HPP_
#define GC_TINIERSHARE_PREP_HPP_

#include "TinierSharePrep.h"

#include "PersonalPrep.hpp"

namespace GC
{

template<class T>
TinierSharePrep<T>::TinierSharePrep(DataPositions& usage, int input_player) :
        PersonalPrep<T>(usage, input_player), triple_generator(0),
        real_triple_generator(0)
{
}

template<class T>
TinierSharePrep<T>::TinierSharePrep(SubProcessor<T>*, DataPositions& usage) :
        TinierSharePrep(usage)
{
}

template<class T>
TinierSharePrep<T>::~TinierSharePrep()
{
    if (triple_generator)
        delete triple_generator;
    if (real_triple_generator)
        delete real_triple_generator;
}

template<class T>
void TinierSharePrep<T>::set_protocol(typename T::Protocol& protocol)
{
    if (triple_generator)
    {
        assert(&triple_generator->get_player() == &protocol.P);
        return;
    }

    params.generateMACs = true;
    params.amplify = false;
    params.check = false;
    auto& thread = ShareThread<typename T::whole_type>::s();
    triple_generator = new typename T::TripleGenerator(
            BaseMachine::fresh_ot_setup(protocol.P), protocol.P.N, -1,
            OnlineOptions::singleton.batch_size, 1,
            params, &protocol.P);
    triple_generator->multi_threaded = false;
    this->inputs.resize(thread.P->num_players());
    init_real(protocol.P);
}

template<class T>
void TinierSharePrep<T>::buffer_triples()
{
    if (this->input_player != this->SECURE)
    {
        this->buffer_personal_triples();
        return;
    }
    else
        buffer_secret_triples();
}

template<class T>
void TinierSharePrep<T>::buffer_inputs(int player)
{
    CODE_LOCATION
    auto& inputs = this->inputs;
    assert(triple_generator);
    triple_generator->generateInputs(player);
    for (auto& x : triple_generator->inputs)
        inputs.at(player).push_back(x);
}

template<class T>
void GC::TinierSharePrep<T>::buffer_bits()
{
    auto& thread = ShareThread<secret_type>::s();
    this->bits.push_back(
            BufferPrep<T>::get_random_from_inputs(thread.P->num_players()));
}

}

#endif
