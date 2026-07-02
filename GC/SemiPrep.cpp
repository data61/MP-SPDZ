/*
 * SemiPrep.cpp
 *
 */

#include "SemiPrep.h"
#include "Semi.h"
#include "ThreadMaster.h"
#include "OT/NPartyTripleGenerator.h"
#include "OT/BitDiagonal.h"

#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/Replicated.hpp"
#include "OT/NPartyTripleGenerator.hpp"

namespace GC
{

SemiPrep::SemiPrep(DataPositions& usage, bool) :
        BufferPrep<SemiSecret>(usage), triple_generator(0)
{
}

void SemiPrep::set_protocol(SemiSecret::Protocol& protocol)
{
    if (triple_generator)
    {
        assert(&triple_generator->get_player() == &protocol.P);
        return;
    }

    (void) protocol;
    params.set_passive();
    triple_generator = new SemiSecret::TripleGenerator(
            BaseMachine::fresh_ot_setup(protocol.P),
            protocol.P.N, -1, OnlineOptions::singleton.batch_size,
            1, params, &protocol.P);
    triple_generator->multi_threaded = false;
    this->P = &protocol.P;
}

void SemiPrep::buffer_triples()
{
    CODE_LOCATION
    assert(this->triple_generator);
    this->triple_generator->set_batch_size(
            DIV_CEIL(BaseMachine::batch_size<SemiSecret>(DATA_TRIPLE,
                        this->buffer_size), 64));
    this->triple_generator->generatePlainTriples();
    for (auto& x : this->triple_generator->plainTriples)
    {
        this->triples.push_back({{x[0], x[1], x[2]}});
    }
    this->triple_generator->unlock();
}

SemiPrep::~SemiPrep()
{
    if (triple_generator)
        delete triple_generator;
    this->print_left("mixed triples", mixed_triples.size(),
            SemiSecret::type_string(),
            this->usage.files.at(DATA_GF2N).at(DATA_MIXED));
}

void SemiPrep::buffer_bits()
{
    word r = secure_prng.get_word();
    for (size_t i = 0; i < sizeof(word) * 8; i++)
    {
        this->bits.push_back((r >> i) & 1);
    }
}

array<SemiSecret, 3> SemiPrep::get_mixed_triple(int n)
{
    assert(n < 128);

    if (mixed_triples.empty())
    {
        assert(this->triple_generator);
        this->triple_generator->set_batch_size(
                BaseMachine::batch_size<SemiSecret>(DATA_MIXED,
                        this->buffer_size));
        this->triple_generator->generateMixedTriples();
        for (auto& x : this->triple_generator->mixedTriples)
        {
            this->mixed_triples.push_back({{x[0], x[1], x[2]}});
        }
        this->triple_generator->unlock();
    }

    this->count(DATA_MIXED);
    auto res = mixed_triples.back();
    mixed_triples.pop_back();
    return res;
}

} /* namespace GC */
