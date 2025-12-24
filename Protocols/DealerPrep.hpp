/*
 * DealerPrep.hpp
 *
 */

#ifndef PROTOCOLS_DEALERPREP_HPP_
#define PROTOCOLS_DEALERPREP_HPP_

#include "DealerPrep.h"
#include "GC/SemiSecret.h"

template<class T>
DealerPrep<T>::~DealerPrep()
{
    if (bit_input_)
        delete bit_input_;
}

template<class T>
void DealerPrep<T>::buffer_triples()
{
    CODE_LOCATION
    assert(this->proc);
    int buffer_size = BaseMachine::batch_size<T>(DATA_TRIPLE,
            this->buffer_size);
    auto& input = this->proc->input;
    input.reset(input.dealer_player());
    if (input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::open_type> to_share;
        to_share.reserve(3 * buffer_size);
        for (int i = 0; i < buffer_size; i++)
        {
            T triples[3];
            for (int i = 0; i < 2; i++)
                triples[i] = input.random_for_dealer();
            triples[2] = triples[0] * triples[1];
            to_share.push_back(triples[2]);
            this->triples.push_back({});
        }
        input.add_from_dealer(to_share);
    }
    else
    {
        input.add_n_from_dealer(2 * buffer_size, true);
        input.add_n_from_dealer(buffer_size, false);
    }

    input.exchange();
    finalize<3, true>(this->triples, size_t(buffer_size));
}

template<class T>
template<size_t N, bool RANDOM>
void DealerPrep<T>::finalize(vector<array<T, N> >& items, size_t buffer_size)
{
    assert(this->proc);
    auto& input = this->proc->input;

    if (not input.is_dealer())
    {
        if (RANDOM)
            input.require(buffer_size);
        else
            input.require(N * buffer_size);

        if (input.is_king())
        {
            for (size_t i = 0; i < buffer_size; i++)
                items.push_back(
                        input.template finalize_no_check<true, N, RANDOM>());
        }
        else
        {
            for (size_t i = 0; i < buffer_size; i++)
                items.push_back(
                        input.template finalize_no_check<false, N, RANDOM>());
        }
    }
}

template<class T>
void DealerPrep<T>::buffer_inverses()
{
    buffer_inverses(T::invertible);
}

template<class T>
template<int>
void DealerPrep<T>::buffer_inverses(false_type)
{
    throw not_implemented();
}

template<class T>
template<int>
void DealerPrep<T>::buffer_inverses(true_type)
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int buffer_size = BaseMachine::batch_size<T>(DATA_INVERSE);
    auto& input = this->proc->input;
    input.reset(input.dealer_player());
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::open_type> items;
        items.reserve(2 * buffer_size);
        for (int i = 0; i < buffer_size; i++)
        {
            T tuple[2];
            while (tuple[0] == 0)
                tuple[0] = G.get<T>();
            tuple[1] = tuple[0].invert();
            for (auto& value : tuple)
            {
                items.push_back(value);
            }
            this->inverses.push_back({});
        }
        input.add_from_dealer(items);
    }
    else
    {
        input.add_n_from_dealer(2 * buffer_size);
    }

    input.exchange();
    finalize(this->inverses, buffer_size);
}

template<class T>
void DealerPrep<T>::buffer_bits()
{
    CODE_LOCATION
    assert(this->proc);
    auto& input = this->proc->input;
    input.reset(input.dealer_player());
    int buffer_size = BaseMachine::batch_size<T>(DATA_BIT);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::clear> bits;
        bits.reserve(buffer_size);
        for (int i = 0; i < buffer_size; i++)
        {
            T bit = G.get_bit();
            bits.push_back(bit);
            this->bits.push_back({});
        }
        input.add_from_dealer(bits);
    }
    else
    {
        input.add_n_from_dealer(buffer_size);
    }

    input.exchange();

    if (not input.is_dealer())
    {
        for (int i = 0; i < buffer_size; i++)
            this->bits.push_back(input.finalize_from_dealer());
    }
}

template<class T>
void DealerPrep<T>::buffer_dabits(ThreadQueues*)
{
    CODE_LOCATION
    assert(this->proc);
    auto& input = this->proc->input;
    input.reset(input.dealer_player());
    int buffer_size = BaseMachine::batch_size<T>(DATA_DABIT);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::clear> values;
        for (int i = 0; i < buffer_size; i++)
        {
            auto bit = G.get_bit();
            values.push_back(bit);
            this->dabits.push_back({});
        }
        input.add_from_dealer(values);
    }
    else
    {
        input.add_n_from_dealer(buffer_size);
    }

    input.exchange();

    if (not input.is_dealer())
    {
        for (int i = 0; i < buffer_size; i++)
        {
            auto a = input.finalize_from_dealer();
            this->dabits.push_back({a, a.get_bit(0)});
        }
    }
}

template<class T>
void DealerPrep<T>::buffer_sedabits(int length, ThreadQueues*)
{
    auto& buffer = this->edabits[{false, length}];
    if (buffer.empty())
        buffer_edabits(length, 0);
    this->edabits[{true, length}].push_back(buffer.back());
    buffer.pop_back();
}

template<class T>
void DealerPrep<T>::buffer_edabits(int length, ThreadQueues*)
{
    buffer_edabits(length, T::clear::characteristic_two);
}

template<class T>
template<int>
void DealerPrep<T>::buffer_edabits(int, true_type)
{
    throw not_implemented();
}

template<class T>
template<int>
void DealerPrep<T>::buffer_edabits(int length, false_type)
{
    CODE_LOCATION
    assert(this->proc);
    auto& input = this->proc->input;
    auto& bit_input = get_bit_input();
    input.reset(input.dealer_player());
    bit_input.reset(input.dealer_player());
    int n_vecs = DIV_CEIL(BaseMachine::edabit_batch_size<T>(length),
            edabitvec<T>::MAX_SIZE);
    auto& buffer = this->edabits[{false, length}];
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<typename T::clear> all_as;
        vector<typename T::bit_type::part_type::clear> all_bs;
        vector<typename T::clear> as;
        vector<typename T::bit_type::part_type::clear> bs;
        for (int i = 0; i < n_vecs; i++)
        {
            plain_edabits(as, bs, length, G, edabitvec<T>::MAX_SIZE);
            all_as.insert(all_as.end(), as.begin(), as.end());
            all_bs.insert(all_bs.end(), bs.begin(), bs.end());
            buffer.push_back({});
            buffer.back().a.resize(edabitvec<T>::MAX_SIZE);
            buffer.back().b.resize(length);
        }
        input.add_from_dealer(all_as);
        bit_input.add_from_dealer(all_bs);
    }
    else
    {
        input.add_n_from_dealer(edabitvec<T>::MAX_SIZE * n_vecs);
        bit_input.add_n_from_dealer(length * n_vecs);
    }

    input.exchange();
    bit_input.exchange();

    if (not input.is_dealer())
    {
        for (int i = 0; i < n_vecs; i++)
        {
            buffer.push_back({});
            for (int j = 0; j < edabitvec<T>::MAX_SIZE; j++)
                buffer.back().a.push_back(input.finalize_from_dealer());
            for (int j = 0; j < length; j++)
                buffer.back().b.push_back(bit_input.finalize_from_dealer());
        }
    }
}

template<class T>
DealerInput<typename T::bit_type>& DealerPrep<T>::get_bit_input()
{
    assert(this->proc);

    if (not bit_input_)
        bit_input_ = new DealerInput<typename T::bit_type>(this->proc->P);

    return *bit_input_;
}

#endif /* PROTOCOLS_DEALERPREP_HPP_ */
