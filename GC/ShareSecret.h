/*
 * ReplicatedSecret.h
 *
 */

#ifndef GC_SHARESECRET_H_
#define GC_SHARESECRET_H_

#include <vector>
using namespace std;

#include "GC/Memory.h"
#include "GC/Clear.h"
#include "GC/Access.h"
#include "GC/ArgTuples.h"
#include "GC/NoShare.h"
#include "Math/FixedVec.h"
#include "Math/BitVec.h"
#include "Tools/SwitchableOutput.h"
#include "Protocols/Replicated.h"
#include "Protocols/ReplicatedMC.h"
#include "Processor/DummyProtocol.h"
#include "Processor/ProcessorBase.h"
#include "Processor/Instruction.h"

namespace GC
{

template <class T>
class Processor;

template <class T>
class Thread;

template <class T>
class Machine;

template<class T, class U>
void plain_bitcom(T& res, StackedVector<U>& S, const ArgVector& regs);
template<class T, class U>
void plain_bitdec(const T& res, StackedVector<U>& S, const ArgVector& regs);

template<class U>
class ShareSecret
{
public:
    typedef U whole_type;

    typedef Memory<U> DynamicMemory;
    typedef SwitchableOutput out_type;

    static const bool is_real = true;
    static const bool actual_inputs = true;
    static const bool symmetric = true;
    static const bool garbled = false;

    static bool real_shares(const Player&) { return true; }

    static ShareThread<U>& get_party()
    {
        return ShareThread<U>::s();
    }

    static void store_clear_in_dynamic(Memory<U>& mem,
            const vector<ClearWriteAccess>& accesses);

    static void load(vector< ReadAccess<U> >& accesses, const Memory<U>& mem);
    static void store(Memory<U>& mem, vector< WriteAccess<U> >& accesses);

    static void andrs(Processor<U>& processor, const ArgVector& args)
    { and_(processor, args, true); }
    static void ands(Processor<U>& processor, const ArgVector& args)
    { and_(processor, args, false); }
    static void and_(Processor<U>& processor, const ArgVector& args, bool repeat);
    static void andrsvec(Processor<U>& processor, const ArgVector& args);
    static void xors(Processor<U>& processor, const ArgVector& args);
    static void inputb(Processor<U>& processor, const ArgVector& args)
    { inputb(processor, processor, args); }
    static void inputb(Processor<U>& processor, ProcessorBase& input_processor,
            const ArgVector& args);
    static void inputbvec(Processor<U>& processor, ProcessorBase& input_processor,
            const ArgVector& args);
    static void reveal_inst(Processor<U>& processor, const ArgVector& args);

    template<class T>
    static void convcbit(Integer& dest, const Clear& source, T&) { dest = source; }

    template<class T>
    static void convcbit2s(Processor<T>& processor, const BaseInstruction& instruction)
    { processor.convcbit2s(instruction); }
    static void andm(Processor<U>& processor, const BaseInstruction& instruction)
    { processor.andm(instruction); }

    static BitVec get_mask(int n) { return n >= 64 ? -1 : ((1L << n) - 1); }

    static void run_tapes(const ArgVector& args)
    { Thread<U>::s().master.machine.run_tapes(args); }

    void check_length(int n, const Integer& x);

    void invert(int n, const U& x);

    void random_bit();

    template<class T>
    void my_input(T& inputter, BitVec value, int n_bits);
    template<class T>
    void other_input(T& inputter, int from, int n_bits = 1);
    template<class T>
    void finalize_input(T& inputter, int from, int n_bits);

    U& operator=(const U&);
};

template<class U, int L>
class RepSecretBase : public FixedVec<BitVec, L>, public ShareSecret<U>
{
    typedef FixedVec<BitVec, L> super;
    typedef RepSecretBase This;

public:
    typedef U part_type;
    typedef U small_type;
    typedef U whole_type;

    typedef BitVec clear;
    typedef BitVec open_type;
    typedef NoShare mac_type;
    typedef NoValue mac_key_type;
    typedef NoShare mac_share_type;

    typedef NoShare bit_type;

    typedef void DefaultMC;

    static const int N_BITS = clear::N_BITS;

    static const bool dishonest_majority = false;
    static const bool variable_players = false;
    static const bool needs_ot = false;
    static const bool has_mac = false;
    static const bool randoms_for_opens = false;
    static const bool function_dependent = false;

    static const false_type is_clear;

    static string type_string() { return "replicated secret"; }
    static string phase_name() { return "Replicated computation"; }

    static const int default_length = N_BITS;

    static int threshold(int)
    {
        return 1;
    }

    static void trans(Processor<U>& processor, int n_outputs,
            const ArgVector& args);

    template<class T>
    static void generate_mac_key(mac_key_type, T)
    {
    }

    static void read_or_generate_mac_key(string, const Player&, mac_key_type)
    {
    }

    static GC::NoValue get_mac_key()
    {
        throw runtime_error("no MAC");
    }

    static void set_mac_key(GC::NoValue)
    {
    }

    template<class T>
    static string proto_fake_opts()
    {
        return T::fake_opts();
    }

    static size_t maximum_size()
    {
        return default_length;
    }

    RepSecretBase()
    {
    }
    template <class T>
    RepSecretBase(const T& other) :
            super(other)
    {
    }

    void bitcom(StackedVector<U>& S, const ArgVector& regs);
    void bitdec(StackedVector<U>& S, const ArgVector& regs) const;

    This operator&(const Clear& other)
    { return super::operator&(BitVec(other)); }

    This lsb()
    { return *this & 1; }

    This get_bit(int i)
    { return (*this >> i) & 1; }
};

template<class U>
class ReplicatedSecret : public RepSecretBase<U, 2>
{
    typedef RepSecretBase<U, 2> super;

public:
    typedef ReplicatedBase Protocol;

    static ReplicatedSecret constant(const typename super::clear& value,
        int my_num, typename super::mac_key_type = {}, int = -1)
    {
      ReplicatedSecret res;
      if (my_num < 2)
        res[my_num] = value;
      return res;
    }

    ReplicatedSecret() {}
    template <class T>
    ReplicatedSecret(const T& other) : super(other) {}

    void load_clear(int n, const Integer& x);

    BitVec local_mul(const ReplicatedSecret& other) const;

    void reveal(size_t n_bits, Clear& x);

    static ReplicatedSecret from_rep3(const FixedVec<BitVec, 2>& x)
    {
        return x;
    }
};

class SemiHonestRepPrep;

class SmallRepSecret : public FixedVec<BitVec_<unsigned char>, 2>
{
    typedef FixedVec<BitVec_<unsigned char>, 2> super;
    typedef SmallRepSecret This;

public:
    typedef ReplicatedMC<This> MC;
    typedef BitVec_<unsigned char> open_type;
    typedef open_type clear;
    typedef NoValue mac_key_type;

    static MC* new_mc(mac_key_type)
    {
        return new MC;
    }

    SmallRepSecret()
    {
    }
    template<class T>
    SmallRepSecret(const T& other) :
            super(other)
    {
    }

    This lsb() const
    {
        return *this & 1;
    }
};

class SemiHonestRepSecret : public ReplicatedSecret<SemiHonestRepSecret>
{
    typedef ReplicatedSecret<SemiHonestRepSecret> super;

public:
    typedef Memory<SemiHonestRepSecret> DynamicMemory;

    typedef ReplicatedMC<SemiHonestRepSecret> MC;
    typedef Replicated<SemiHonestRepSecret> Protocol;
    typedef MC MAC_Check;
    typedef SemiHonestRepPrep LivePrep;
    typedef ReplicatedInput<SemiHonestRepSecret> Input;

    typedef SemiHonestRepSecret part_type;
    typedef SmallRepSecret small_type;
    typedef SemiHonestRepSecret whole_type;

    static const bool expensive_triples = false;
    static const bool malicious = false;

    static MC* new_mc(mac_key_type) { return new MC; }

    SemiHonestRepSecret() {}
    template<class T>
    SemiHonestRepSecret(const T& other) : super(other) {}
};

}

#endif /* GC_SHARESECRET_H_ */
