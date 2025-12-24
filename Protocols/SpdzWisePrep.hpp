/*
 * SpdzWisePrep.cpp
 *
 */

#include "SpdzWisePrep.h"
#include "SpdzWiseRingPrep.h"
#include "SpdzWiseRingShare.h"
#include "MaliciousShamirShare.h"
#include "SquarePrep.h"
#include "Math/gfp.h"
#include "ProtocolSet.h"

#include "ReplicatedPrep.hpp"
#include "Spdz2kPrep.hpp"
#include "ShamirMC.hpp"
#include "MaliciousRepPO.hpp"
#include "GC/RepPrep.hpp"

template<class T>
void SpdzWisePrep<T>::buffer_triples()
{
    assert(this->protocol != 0);
    assert(this->proc != 0);
    this->protocol->init_mul();
    generate_triples_initialized(this->triples,
            BaseMachine::batch_size<T>(DATA_TRIPLE, this->buffer_size),
            this->protocol);
}

template<class T>
void SpdzWisePrep<T>::buffer_squares()
{
    assert(this->protocol != 0);
    generate_squares(this->squares,
            BaseMachine::batch_size<T>(DATA_SQUARE, this->buffer_size),
            this->protocol);
}

template<class T>
void SpdzWisePrep<T>::buffer_bits(false_type, true_type, false_type)
{
    MaliciousRingPrep<T>::buffer_bits();
}

template<class T>
void SpdzWisePrep<T>::buffer_bits(false_type, false_type, true_type)
{
    CODE_LOCATION
    typedef MaliciousRep3Share<gf2n> part_type;
    vector<typename part_type::Honest> bits;
    ProtocolSet<typename part_type::Honest> set(this->proc->P, {});
    auto& protocol = set.protocol;
    auto& prep = set.preprocessing;
    int buffer_size = BaseMachine::batch_size<
            SpdzWiseShare<MaliciousRep3Share<gf2n>>>(DATA_BIT,
            this->buffer_size);
    for (int i = 0; i < buffer_size; i++)
        bits.push_back(prep.get_bit());
    protocol.init_mul();
    for (auto& bit : bits)
        protocol.prepare_mul(bit, this->proc->MC.get_alphai());
    protocol.exchange();
    for (auto& bit : bits)
        this->bits.push_back({bit, protocol.finalize_mul()});
}

template<int K, int S>
void buffer_bits_from_squares_in_ring(vector<SpdzWiseRingShare<K, S>>& bits,
        SubProcessor<SpdzWiseRingShare<K, S>>* proc)
{
    CODE_LOCATION
    assert(proc != 0);
    typedef SpdzWiseRingShare<K + 2, S> BitShare;
    typename BitShare::MAC_Check MC(proc->MC.get_alphai());
    DataPositions usage;
    SquarePrep<BitShare> prep(usage);
    SubProcessor<BitShare> bit_proc(MC, prep, proc->P, proc->Proc);
    prep.set_proc(&bit_proc);
    bits_from_square_in_ring(bits,
            BaseMachine::batch_size<SpdzWiseRingShare<K, S>>(DATA_BIT),
            &prep);
}

template<class T>
void SpdzWiseRingPrep<T>::buffer_bits()
{
    if (OnlineOptions::singleton.bits_from_squares)
        buffer_bits_from_squares_in_ring(this->bits, this->proc);
    else
        MaliciousRingPrep<T>::buffer_bits();
}

template<class T>
void SpdzWisePrep<T>::buffer_bits()
{
    buffer_bits(T::share_type::variable_players, T::clear::prime_field,
            T::clear::characteristic_two);
}

template<class T>
void SpdzWisePrep<T>::buffer_bits(true_type, true_type, false_type)
{
    buffer_bits_from_squares(*this);
}

template<class T>
void SpdzWisePrep<T>::buffer_bits(false_type, false_type, false_type)
{
    super::buffer_bits();
}

template<class T>
void SpdzWisePrep<T>::buffer_bits(true_type, false_type, true_type)
{
    super::buffer_bits();
}

template<class T>
void SpdzWisePrep<T>::buffer_inputs(int player)
{
    CODE_LOCATION
    assert(this->proc != 0);
    assert(this->protocol != 0);
    vector<T> rs(BaseMachine::input_batch_size<T>(player,
            this->buffer_size));
    auto& P = this->proc->P;
    this->inputs.resize(P.num_players());
    this->protocol->init_mul();
    for (auto& r : rs)
    {
        r = this->protocol->get_random();
    }

    typename T::part_type::PO output(P);
    if (player != P.my_num())
    {
        for (auto& r : rs)
        {
            this->inputs[player].push_back({r, 0});
            output.prepare_sending(r.get_share(), player);
        }
        output.send(player);
    }
    else
    {
        output.receive();
        for (auto& r : rs)
        {
            this->inputs[player].push_back({r, output.finalize(r.get_share())});
        }
    }
}
