/*
 * Rep3Share.h
 *
 */

#ifndef PROTOCOLS_REP3SHARE_H_
#define PROTOCOLS_REP3SHARE_H_

#include "Math/FixedVec.h"
#include "Math/Integer.h"
#include "Protocols/Replicated.h"
#include "Protocols/Rep3Shuffler.h"
#include "GC/ShareSecret.h"
#include "ShareInterface.h"
#include "Processor/Instruction.h"

template<class T> class ReplicatedPrep;
template<class T> class SemiRep3Prep;
template<class T> class ReplicatedRingPrep;
template<class T> class ReplicatedPO;
template<class T> class SpecificPrivateOutput;

template<class T, int L>
class RepShare : public FixedVec<T, L>, public ShareInterface
{
    typedef RepShare This;
    typedef FixedVec<T, L> super;

public:
    typedef T clear;
    typedef T open_type;
    typedef This share_type;

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    const static bool expensive = false;

    static int threshold(int)
    {
        return 1;
    }

    static void specification(octetStream& os)
    {
        T::specification(os);
    }

    RepShare()
    {
    }
    template<class U>
    RepShare(const U& other) :
            super(other)
    {
    }

    template<class U>
    RepShare operator*(const U& other) const
    {
        This res = *this;
        res *= other;
        return res;
    }

    template<class U>
    RepShare operator*=(const U& other)
    {
        for (int i = 0; i < L; i++)
            (*this)[i] *= other;
        return *this;
    }

    void pack(octetStream& os, T) const
    {
        pack(os, false);
    }
    void pack(octetStream& os, bool full = true) const
    {
        if (full)
            FixedVec<T, L>::pack(os);
        else
            (*this)[0].pack(os);
    }
    void unpack(octetStream& os, bool full = true)
    {
        assert(full);
        FixedVec<T, L>::unpack(os);
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
class Rep3Share : public RepShare<T, 2>
{
    typedef RepShare<T, 2> super;
    typedef Rep3Share This;

public:
    typedef T clear;

    typedef Replicated<Rep3Share> Protocol;
    typedef ReplicatedMC<Rep3Share> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Rep3Share> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef typename conditional<T::characteristic_two,
            ReplicatedPrep<Rep3Share>, SemiRep3Prep<Rep3Share>>::type LivePrep;
    typedef ReplicatedRingPrep<Rep3Share> TriplePrep;
    typedef Rep3Share Honest;

    typedef Rep3Share Scalar;

    typedef GC::SemiHonestRepSecret bit_type;

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    const static bool expensive = false;
    static false_type variable_players;
    static const bool has_trunc_pr = true;
    static const bool malicious = false;

    static string type_short()
    {
        return "R" + string(1, clear::type_char());
    }
    static string type_string()
    {
        return "replicated " + T::type_string();
    }
    static char type_char()
    {
        return T::type_char();
    }

    static Rep3Share constant(T value, int my_num,
            typename super::mac_key_type = {})
    {
        This res;
        Replicated<Rep3Share>::assign(res, value, my_num);
        return res;
    }

    Rep3Share()
    {
    }
    template<class U>
    Rep3Share(const U& other) :
            super(other)
    {
    }

    void assign(const char* buffer)
    {
        FixedVec<T, 2>::assign(buffer);
    }

    clear local_mul(const Rep3Share& other) const
    {
        auto a = (*this)[0].lazy_mul(other.lazy_sum());
        auto b = (*this)[1].lazy_mul(other[0]);
        return a.lazy_add(b);
    }
};

template<class T>
false_type Rep3Share<T>::variable_players;

#endif /* PROTOCOLS_REP3SHARE_H_ */
