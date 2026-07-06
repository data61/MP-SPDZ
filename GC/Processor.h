/*
 * Processor.h
 *
 */

#ifndef GC_PROCESSOR_H_
#define GC_PROCESSOR_H_

#include <vector>
using namespace std;

#include "GC/Clear.h"
#include "GC/Machine.h"
#include "GC/RuntimeBranching.h"

#include "Math/Integer.h"
#include "Processor/ProcessorBase.h"
#include "Processor/Instruction.h"
#include "Tools/CheckVector.h"

namespace GC
{

template <class T>
class Processor : public ::ProcessorBase, public GC::RuntimeBranching
{
public:
    static int check_args(const ArgVector& args, int n);

    template<class U>
    static void check_input(const U& in, const ArgVector::value_type* params);

    Machine<T>* machine;
    Memories<T>& memories;

    unsigned int PC, last_PC;
    unsigned int time;

    // rough measure for the memory usage
    size_t complexity;

    StackedVector<T> S;
    StackedVector<Clear> C;
    StackedVector<Integer> I;

    Timer xor_timer;

    typename T::out_type out;

    Processor(Machine<T>& machine);
    Processor(Memories<T>& memories, Machine<T>* machine = 0);
    ~Processor();

    template<class U>
    void reset(const U& program, int arg);
    template<class U>
    void reset(const U& program);

    long long get_input(const ArgVector::value_type* params, bool interactive = false);
    template<class U>
    U get_long_input(const ArgVector::value_type* params, ProcessorBase& input_proc,
            bool interactive = false);

    void bitcoms(T& x, const ArgVector& regs) { x.bitcom(S, regs); }
    void bitdecs(const ArgVector& regs, const T& x) { x.bitdec(S, regs); }
    void bitdecc(const ArgVector& regs, const Clear& x);
    void bitdecint(const ArgVector& regs, const Integer& x);

    void random_bit(T &x) { x.random_bit(); }

    template<class U>
    void load_dynamic_direct(const ArgVector& args, U& dynamic_memory);
    template<class U>
    void store_dynamic_direct(const ArgVector& args, U& dynamic_memory);
    template<class U>
    void load_dynamic_indirect(const ArgVector& args, U& dynamic_memory);
    template<class U>
    void store_dynamic_indirect(const ArgVector& args, U& dynamic_memory);
    template<class U>
    void store_clear_in_dynamic(const ArgVector& args, U& dynamic_memory);

    template<class U, class V>
    void mem_op(int n, U& dest, const V& source,
            Integer dest_address, Integer source_address);

    void xors(const ArgVector& args);
    void xors(const ArgVector& args, size_t start, size_t end);
    void xorc(const ::BaseInstruction& instruction);
    void nots(const ::BaseInstruction& instruction);
    void notcb(const ::BaseInstruction& instruction);
    void movsb(const ::BaseInstruction& instruction);
    void andm(const ::BaseInstruction& instruction);
    void and_(const ArgVector& args, bool repeat);
    void andrs(const ArgVector& args) { and_(args, true); }
    void ands(const ArgVector& args) { and_(args, false); }
    void andrsvec(const ArgVector& args);

    void input(const ArgVector& args);
    void inputb(typename T::Input& input, ProcessorBase& input_processor,
            const ArgVector& args, int my_num);
    void inputbvec(typename T::Input& input, ProcessorBase& input_processor,
            const ArgVector& args, PlayerBase& P);

    void reveal(const ArgVector& args);

    template<int = 0>
    void convcbit2s(const BaseInstruction& instruction);

    void convcbitvec(const BaseInstruction& instruction, StackedVector<Integer>& Ci,
            Player* P);

    void print_reg(int reg, int n, int size);
    template<class U>
    void print_reg_plain(U& value);
    void print_reg_signed(unsigned n_bits, Integer value);
    void print_chr(int n);
    void print_str(int n);
    void print_float(const ArgVector& args);
    void print_float_prec(int n);

    void incint(const BaseInstruction& instruction);

    void push_stack();
    void push_args(const ArgVector& args);
    void pop_stack(const ArgVector& results);

    template<class U>
    void call_tape(const BaseInstruction& instruction, U& dynamic_memory);
};

template <class T>
inline int GC::Processor<T>::check_args(const ArgVector& args, int n)
{
    if (args.size() % n != 0)
        throw runtime_error("invalid number of arguments");
    int total = 0;
    for (auto it = args.begin(); it < args.end(); it += n)
    {
        total += *it;
    }
    return total;
}

} /* namespace GC */

#endif /* GC_PROCESSOR_H_ */
