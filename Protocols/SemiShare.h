/*
 * SemiShare.h
 *
 */

#ifndef PROTOCOLS_SEMISHARE_H_
#define PROTOCOLS_SEMISHARE_H_

#include "Protocols/Beaver.h"
#include "Protocols/Semi.h"
#include "Processor/DummyProtocol.h"
#include "GC/NoShare.h"
#include "ShareInterface.h"

#include <string>
using namespace std;

template<class T> class Input;
template<class T> class SemiMC;
template<class T> class DirectSemiMC;
template<class T> class Semi;
template<class T> class Hemi;
template<class T> class SemiPrep;
template<class T> class SemiInput;
template<class T> class PrivateOutput;
template<class T> class SemiMultiplier;
template<class T> class OTTripleGenerator;
template<class T> class DummyMatrixPrep;

template<class T>
using MaybeHemi = typename conditional<T::clear::characteristic_two,
        typename T::BasicProtocol, Hemi<T>>::type;

namespace GC
{
class SemiSecret;
class NoValue;
}

template<class T>
class BasicSemiShare : public T
{
public:
    typedef T open_type;
    typedef T clear;

    typedef GC::NoValue mac_key_type;

    template<class U>
    BasicSemiShare(const U& other) : T(other)
    {
    }
};

template<class T>
class SemiShare : public T, public ShareInterface
{
    typedef T super;
    typedef SemiShare This;

public:
    typedef T open_type;
    typedef T clear;
    typedef SemiShare share_type;

    typedef SemiMC<SemiShare> MAC_Check;
    typedef DirectSemiMC<SemiShare> Direct_MC;
    typedef SemiInput<SemiShare> Input;
    typedef ::PrivateOutput<SemiShare> PrivateOutput;
    typedef Semi<SemiShare> BasicProtocol;
    typedef SemiPrep<SemiShare> LivePrep;
    typedef LivePrep TriplePrep;
    typedef MaybeHemi<This> Protocol;
    typedef DummyMatrixPrep<This> MatrixPrep;

    typedef SemiShare<typename T::next> prep_type;
    typedef SemiMultiplier<SemiShare> Multiplier;
    typedef OTTripleGenerator<prep_type> TripleGenerator;
    typedef T sacri_type;
    typedef typename T::Square Rectangle;

#ifndef NO_MIXED_CIRCUITS
    typedef GC::SemiSecret bit_type;
#endif

    const static bool needs_ot = true;
    const static bool dishonest_majority = true;
    const static bool variable_players = true;
    const static bool expensive = false;
    static const bool has_trunc_pr = true;
    static const bool malicious = false;

    static false_type is_clear;

    static string type_short() { return "D" + string(1, T::type_char()); }

    static int threshold(int nplayers)
    {
        return nplayers - 1;
    }

    static SemiShare constant(const open_type& other, int my_num,
            mac_key_type = {}, int = -1)
    {
        if (my_num == 0)
            return other;
        else
            return {};
    }

    SemiShare()
    {
    }
    template<class U>
    SemiShare(const U& other) : T(other)
    {
    }

    void assign(const void* buffer)
    {
        super::assign(buffer);
    }

    void pack(octetStream& os, bool full = true) const
    {
        (void)full;
        super::pack(os);
    }
    void unpack(octetStream& os, bool full = true)
    {
        (void)full;
        super::unpack(os);
    }

    void pack(octetStream& os, int n_bits) const
    {
        super::pack(os, n_bits);
    }
    void unpack(octetStream& os, int n_bits)
    {
        super::unpack(os, n_bits);
    }

    template<class U>
    static void shrsi(SubProcessor<U>& proc, const Instruction& inst)
    {
        shrsi(proc, inst, T::prime_field);
    }

    template<class U>
    static void shrsi(SubProcessor<U>&, const Instruction&,
            true_type)
    {
        throw runtime_error("shrsi not implemented");
    }

    template<class U>
    static void shrsi(SubProcessor<U>& proc, const Instruction& inst,
            false_type)
    {
        for (int i = 0; i < inst.get_size(); i++)
        {
            auto& dest = proc.get_S_ref(inst.get_r(0) + i);
            auto& source = proc.get_S_ref(inst.get_r(1) + i);
            dest = source >> inst.get_n();
        }
    }
};

template<class T>
false_type SemiShare<T>::is_clear;

#endif /* PROTOCOLS_SEMISHARE_H_ */
