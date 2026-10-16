/*
 * Instruction.cpp
 *
 */

#include "Instruction.h"
#include "instructions.h"
#include "Processor.h"
#include "Memory.h"
#include "Math/gf2n.h"
#include "GC/instructions.h"

#include "Memory.hpp"
#include "Instruction.hpp"

#include <iomanip>
#include <ranges>

template<class cgf2n>
void Instruction::execute_clear_gf2n(StackedVector<cgf2n>& registers,
        MemoryPart<cgf2n>& memory, ArithmeticProcessor& Proc) const
{
    auto& C2 = registers;
    auto& M2C = memory;
    switch (opcode)
    {
#define X(NAME, PRE, CODE) \
        case NAME: { PRE; for (int i = 0; i < size; i++) { CODE; } } break;
        CLEAR_GF2N_INSTRUCTIONS
#undef X
    }
}

template<class cgf2n>
void Instruction::gbitdec(StackedVector<cgf2n>& registers) const
{
    for (int j = 0; j < size; j++)
    {
        typename cgf2n::internal_type a = registers.at(r[0] + j).get();
        for (unsigned int i = 0; i < start.size(); i++)
        {
            registers.at(start[i] + j) = a & 1;
            a >>= n;
        }
    }
}

template<class cgf2n>
void Instruction::gbitcom(StackedVector<cgf2n>& registers) const
{
    for (int j = 0; j < size; j++)
    {
        typename cgf2n::internal_type a = 0;
        for (unsigned int i = 0; i < start.size(); i++)
        {
            a ^= registers.at(start[i] + j).get() << (i * n);
        }
        registers.at(r[0] + j) = a;
    }
}

void Instruction::execute_regint(ArithmeticProcessor& Proc, MemoryPart<Integer>& Mi) const
{
    (void) Mi;
    auto& Ci = Proc.get_Ci();
    switch (opcode)
    {
#define X(NAME, PRE, CODE) \
        case NAME: { PRE; for (int i = 0; i < size; i++) { CODE; } } break;
        REGINT_INSTRUCTIONS
#undef X
    }
}

void Instruction::incint(StackedVector<Integer>& Ci) const
{
    auto base = Ci[r[1]];
    if (start[0] == 1 and start[1] >= size_t(size))
    {
        for (auto& dest : Ci.span_for_size(r[0], size))
        {
            dest = base;
            base += int(n);
        }
    }
    else
    {
        auto dest = Ci.begin() + r[0];
        assert(dest + size <= Ci.end());
        for (int i = 0; i < size; i++)
        {
            int inc = (i / start[0]) % start[1];
            *dest++ = base + inc * int(n);
        }
    }
}

void Instruction::shuffle(ArithmeticProcessor& Proc) const
{
    for (int i = 0; i < size; i++)
        Proc.write_Ci(r[0] + i, Proc.read_Ci(r[1] + i));
    for (int i = 0; i < size; i++)
    {
        int j = Proc.shared_prng.get_uint(size - i);
        swap(Proc.get_Ci_ref(r[0] + i), Proc.get_Ci_ref(r[0] + i + j));
    }
}

void Instruction::bitdecint(ArithmeticProcessor& Proc) const
{
    for (int j = 0; j < size; j++)
    {
        long a = Proc.read_Ci(r[0] + j);
        for (unsigned int i = 0; i < start.size(); i++)
        {
            Proc.get_Ci_ref(start[i] + j) = (a >> i) & 1;
        }
    }
}

void Instruction::groupsumint(StackedVector<Integer>& Ci) const
{
    vector<span<Integer>> spans;
    for (int i = 0; i < 3; i++)
        spans.push_back(Ci.span_for_size(r[i], size));
    auto res = spans[0];
    auto g = spans[1];
    auto x = spans[2];

    Integer sum = 0;
    size_t base = 0;
    for (int i = 0; i < size; i++)
    {
        if (g[i])
        {
            for (int j = base; j < i; j++)
                res[j] = sum;
            sum = 0;
            base = i;
        }
        sum += x[i];
    }

    for (int j = base; j < size; j++)
        res[j] = sum;
}

void Instruction::qs_perm(StackedVector<Integer>& Ci) const
{
    vector<span<Integer>> spans;
    for (int i = 0; i < 4; i++)
        spans.push_back({ Ci.begin() + start.at(i), size_t(size) });
    auto res = spans[0];
    auto g_out = spans[1];
    auto g_in = spans[2];
    auto c = spans[3];

    for (int i = 0; i < size; i++)
    {
        res[i] = i;
        g_out[i] = g_in[i];
    }

    long base = 0, curr = 0;
    assert(g_in[0].get());

    for (int i = 0; i < size; i++)
    {
        if (g_in[i].get())
        {
            if (i)
            {
                swap(res[base], res[curr]);
                if (curr == i - 1)
                    g_out[i - 1] = 1;
                else
                    g_out[curr + 1] = 1;
            }
            base = i;
            curr = i;
        }
        else
        {
            if (c[i] == 0)
            {
                curr += 1;
                swap(res[curr], res[i]);
            }
        }
    }
    swap(res[base], res[curr]);
    if (curr == size - 1)
        g_out[size - 1] = 1;
    else
        g_out[curr + 1] = 1;
}

string BaseInstruction::get_name() const
{
    switch (get_opcode())
    {
#define X(NAME, PRE, CODE) \
    case NAME: return #NAME;
    ALL_INSTRUCTIONS
#undef X
#define X(NAME, CODE) \
    case NAME: return #NAME;
    COMBI_INSTRUCTIONS
    default:
        stringstream ss;
        ss << showbase << hex << get_opcode();
        return ss.str();
    }
}

void BaseInstruction::bytecode_assert(bool condition) const
{
    if (not condition)
        throw runtime_error("bytecode assertion violated");
}

ostream& operator<<(ostream& s, const Instruction& instr)
{
    s << instr.get_name();
    s << " size=" << instr.get_size();
    s << " n=" << instr.get_n();
    s << " r=(";
    for (int i = 0; i < 3; i++)
        s << instr.get_r(i) << ", ";
    s << instr.get_r(3);
    s << ")";
    if (not instr.get_start().empty())
    {
        s << " args=(";
        for (unsigned i = 0; i < instr.get_start().size() - 1; i++)
            s << instr.get_start()[i] << ", ";
        s << instr.get_start().back();
        s << ")";
    }
    return s;
}

template void Instruction::execute_clear_gf2n(StackedVector<gf2n_short>& registers,
        MemoryPart<gf2n_short>& memory, ArithmeticProcessor& Proc) const;
template void Instruction::execute_clear_gf2n(StackedVector<gf2n_long>& registers,
        MemoryPart<gf2n_long>& memory, ArithmeticProcessor& Proc) const;
