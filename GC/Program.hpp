/*
 * Program.cpp
 *
 */

#ifndef GC_PROGRAM_HPP_
#define GC_PROGRAM_HPP_

#include <GC/Program.h>
#include "Instruction_inline.h"
#include "instructions.h"

#include "config.h"

#include "Tools/callgrind.h"

#include "Processor/Instruction.hpp"

namespace GC
{

inline
Program::Program()
{
    compute_constants();
}

inline
void Program::compute_constants()
{
    for (int reg_type = 0; reg_type < MAX_REG_TYPE; reg_type++)
    {
        max_reg[reg_type] = 0;
        max_mem[reg_type] = 0;
    }
    for (unsigned int i = 0; i < p.size(); i++)
    {
        for (int reg_type = 0; reg_type < MAX_REG_TYPE; reg_type++)
        {
            max_reg[reg_type] = max(max_reg[reg_type],
                    p[i].get_max_reg(RegType(reg_type)));
            max_mem[reg_type] = max(max_mem[reg_type],
                    p[i].get_mem(RegType(reg_type)));
        }
    }
}

inline
void Program::parse(const string& bytecode_name)
{
    string filename = "Programs/Bytecode/" + bytecode_name + ".bc";
    parse_file(filename);
}

inline
void Program::parse_file(const string& filename)
{
    ifstream s(filename.c_str());
    if (s.bad() or s.fail())
        throw runtime_error("Cannot open " + filename);
    parse(s);
}

inline
void Program::parse(istream& s)
{
    p.resize(0);
    Instruction instr;
    s.peek();
    int pos = 0;
    CALLGRIND_STOP_INSTRUMENTATION;
    while (!s.eof())
    {
        instr.parse(s, pos);
        if (s.bad() or s.fail())
            throw runtime_error("error reading program");
        p.push_back(instr);
        //cerr << "\t" << instr << endl;
        s.peek();
        pos++;
    }
    CALLGRIND_START_INSTRUMENTATION;
    compute_constants();
}

template <class T, class U>
BreakType Program::execute(Processor<T>& Proc, U& dynamic_memory,
        int PC) const
{
    if (OnlineOptions::singleton.has_option("throw_exceptions"))
        return execute_with_errors(Proc, dynamic_memory, PC);
    else
    {
        try
        {
            return execute_with_errors(Proc, dynamic_memory, PC);
        }
        catch (needs_cleaning& e)
        {
            throw e;
        }
        catch (exception& e)
        {
            cerr << "Fatal error at " << Proc.last_PC << " ("
                    << p[Proc.last_PC].get_name() << "): " << e.what() << endl;
            exit(1);
        }
    }
}

template <class T, class U>
BreakType Program::execute_with_errors(Processor<T>& Proc, U& dynamic_memory,
        int PC) const
{
    if (PC != -1)
        Proc.PC = PC;
#ifdef DEBUG_ROUNDS
    cout << typeid(T).name() << " starting at PC " << Proc.PC << "/" <<
            p.size() << endl;
#endif
    unsigned int size = p.size();
    size_t time = Proc.time;
    Proc.complexity = 0;
    auto& Ci = Proc.I;
    auto& processor = Proc;
    do
    {
#ifdef DEBUG_EXE
        cout << "execute " << time << "/" << Proc.PC << " " << T::phase_name()
                << endl;
#endif
        if (Proc.PC >= size)
        {
            Proc.time = time;
            return DONE_BREAK;
        }
#ifdef COUNT_INSTRUCTIONS
        Proc.stats[p[Proc.PC].get_opcode()]++;
#endif
        Proc.last_PC = Proc.PC;
        auto& instruction = p[Proc.PC++];
        switch (instruction.get_opcode())
        {
#define X(NAME, CODE) case NAME: {CODE;} break;
        INSTRUCTIONS
#undef X
        default:
            fallback_code(instruction, processor);
        }
        time++;
#ifdef DEBUG_COMPLEXITY
        cout << T::part_type::name() << " complexity at " << time << ": " <<
                Proc.complexity << " after " << hex <<
                instruction.get_opcode() << dec << endl;
#endif
    }
    while (Proc.complexity < (size_t) OnlineOptions::singleton.batch_size);
    Proc.time = time;
#ifdef DEBUG_ROUNDS
    cout << "breaking at time " << Proc.time << endl;
#endif
    return TIME_BREAK;
}

} /* namespace GC */

#endif
