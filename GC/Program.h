/*
 * Program.h
 *
 */

#ifndef GC_PROGRAM_H_
#define GC_PROGRAM_H_

#include "GC/Instruction.h"
#include "Processor/Program.h"

#include <vector>
using namespace std;

namespace GC
{

enum BreakType {
    TIME_BREAK,
    DONE_BREAK,
    CAP_BREAK,
    CLEANING_BREAK,
};

template <class T> class Processor;

class Program
{
    vector<Instruction> p;

    // Maximal register used
    unsigned max_reg[MAX_REG_TYPE];

    // Memory size used directly
    unsigned max_mem[MAX_REG_TYPE];

    void compute_constants();

    public:

    Program();

    size_t size() const { return p.size(); }

    // Read in a program
    void parse_file(const string& filename);
    void parse(const string& programe);
    void parse(istream& s);

    unsigned num_reg(RegType reg_type) const
      { return max_reg[reg_type]; }

    unsigned direct_mem(RegType reg_type) const
      { return max_mem[reg_type]; }

    template<class T, class U>
    BreakType execute(Processor<T>& Proc, U& dynamic_memory, int PC = -1) const;
    template<class T, class U>
    BreakType execute_with_errors(Processor<T>& Proc, U& dynamic_memory, int PC =
            -1) const;
};


} /* namespace GC */

#endif /* GC_PROGRAM_H_ */
