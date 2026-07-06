/*
 * RepRingOnlyEdabitPrep.cpp
 *
 */

#ifndef PROTOCOLS_REPRINGONLYEDABITPREP_HPP_
#define PROTOCOLS_REPRINGONLYEDABITPREP_HPP_

#include "RepRingOnlyEdabitPrep.h"
#include "GC/BitAdder.h"
#include "Processor/Instruction.h"

template<class T>
void RepRingOnlyEdabitPrep<T>::buffer_edabits(int n_bits, ThreadQueues*)
{
    CODE_LOCATION
    assert(this->proc);
    int dl = T::bit_type::default_length;
    int buffer_size = DIV_CEIL(BaseMachine::edabit_batch_size<T>(n_bits, this->buffer_size), dl) * dl;
    StackedVector<T> swholes;
    swholes.resize(buffer_size);
    Instruction inst;
    inst.r[0] = 0;
    inst.n = n_bits;
    inst.size = buffer_size;
    this->proc->protocol.randoms_inst(swholes, inst);
    vector<T> wholes(swholes.begin(), swholes.end());

    auto& P = this->proc->P;
    ArgVector regs(P.num_players() * n_bits);
    for (size_t i = 0; i < regs.size(); i++)
        regs[i] = i * buffer_size / dl;
    typedef typename T::bit_type bt;
    StackedVector<bt> bits(n_bits * P.num_players() * buffer_size);
    T::split(bits, regs, n_bits, wholes.data(), wholes.size(),
            *GC::ShareThread < bt > ::s().protocol);

    BitAdder bit_adder;
    vector<vector<vector<bt>>> summands;
    for (int i = 0; i < n_bits; i++)
    {
        summands.push_back({});
        auto& x = summands.back();
        for (int j = 0; j < P.num_players(); j++)
        {
            x.push_back({});
            auto& y = x.back();
            for (int k = 0; k < buffer_size / dl; k++)
                y.push_back(bits.at(k + buffer_size / dl * (j + P.num_players() * i)));
        }
    }
    vector<vector<bt>> sums(buffer_size / dl);
    auto &party = GC::ShareThread<typename T::bit_type>::s();
    SubProcessor<bt> bit_proc(party.MC->get_part_MC(), this->proc->bit_prep, P);
    bit_adder.multi_add(sums, summands, 0, buffer_size / dl, bit_proc, dl, 0);

    this->push_edabits(this->edabits[{false, n_bits}], wholes, sums);
}

#endif
