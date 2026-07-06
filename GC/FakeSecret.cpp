/*
 * Secret.cpp
 *
 */

#include <GC/FakeSecret.h>
#include "GC/Processor.h"
#include "GC/square64.h"

#include "GC/Processor.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/ThreadMaster.hpp"
#include "Processor/Input.hpp"

namespace GC
{

const int FakeSecret::default_length;

false_type FakeSecret::is_clear;

void FakeSecret::load_clear(int n, const Integer& x)
{
	if ((size_t)n < 8 * sizeof(x) and abs(x.get()) >= (1LL << n))
		throw out_of_range("public value too long");
	*this = x;
}

void FakeSecret::bitcom(StackedVector<FakeSecret>& S, const ArgVector& regs)
{
    *this = 0;
    for (unsigned int i = 0; i < regs.size(); i++)
        *this ^= (S[regs[i]] << i);
}

void FakeSecret::bitdec(StackedVector<FakeSecret>& S, const ArgVector& regs) const
{
    for (unsigned int i = 0; i < regs.size(); i++)
        S[regs[i]] = (*this >> i) & 1;
}

void FakeSecret::load(vector<ReadAccess<FakeSecret> >& accesses,
        const Memory<FakeSecret>& mem)
{
    for (auto access : accesses)
        access.dest = mem[access.address];
}

void FakeSecret::store(Memory<FakeSecret>& mem,
        vector<WriteAccess<FakeSecret> >& accesses)
{
    for (auto access : accesses)
        mem[access.address] = access.source;
}

void FakeSecret::store_clear_in_dynamic(Memory<DynamicType>& mem,
		const vector<GC::ClearWriteAccess>& accesses)
{
	for (auto access : accesses)
		mem[access.address] = access.value;
}

void FakeSecret::ands(Processor<FakeSecret>& processor,
        const ArgVector& regs)
{
	processor.ands(regs);
}

void FakeSecret::trans(Processor<FakeSecret>& processor, int n_outputs,
        const ArgVector& args)
{
	square64 square;
	for (size_t i = n_outputs; i < args.size(); i++)
		square.rows[i - n_outputs] = processor.S[args[i]].a;
	square.transpose(args.size() - n_outputs, n_outputs);
	for (int i = 0; i < n_outputs; i++)
		processor.S[args[i]] = square.rows[i];
}

FakeSecret FakeSecret::input(GC::Processor<FakeSecret>& processor, const InputArgs& args)
{
	return input(args.from, processor.get_input(args.params), args.n_bits);
}

FakeSecret FakeSecret::input(int from, word input, int n_bits)
{
	(void)from;
	(void)n_bits;
	if (n_bits < 64 and input > word(1) << n_bits)
		throw out_of_range("input too large");
	return input;
}

void FakeSecret::inputbvec(Processor<FakeSecret>& processor,
        ProcessorBase& input_processor, const ArgVector& args)
{
    Input input;
    input.reset_all(*ShareThread<FakeSecret>::s().P);
    processor.inputbvec(input, input_processor, args,
            *ShareThread<FakeSecret>::s().P);
}

void FakeSecret::and_(int n, const FakeSecret& x, const FakeSecret& y,
        bool repeat)
{
	if (repeat)
		return andrs(n, x, y);
	else
		*this = BitVec(x & y).mask(n);
}

void FakeSecret::my_input(Input& inputter, BitVec value, int n_bits)
{
    inputter.add_mine(value, n_bits);
}

void FakeSecret::other_input(Input&, int, int)
{
    throw runtime_error("emulation is supposed to be lonely");
}

void FakeSecret::finalize_input(Input& inputter, int from, int n_bits)
{
    *this = inputter.finalize(from, n_bits);
}

void FakeSecret::run_tapes(const ArgVector& args)
{
    Thread<FakeSecret>::s().master.machine.run_tapes(args);
}

} /* namespace GC */
