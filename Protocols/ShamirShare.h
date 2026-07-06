/*
 * ShamirShare.h
 *
 */

#ifndef PROTOCOLS_SHAMIRSHARE_H_
#define PROTOCOLS_SHAMIRSHARE_H_

#include "Protocols/Shamir.h"
#include "Protocols/ShamirInput.h"
#include "GC/NoShare.h"
#include "ShamirOptions.h"
#include "ShareInterface.h"

template<class T> class ReplicatedPrep;
template<class T> class ReplicatedRingPrep;
template<class T> class MaliciousShamirPO;
template<class T> class SpecificPrivateOutput;

namespace GC
{
template<class T> class CcdSecret;
}

template<class T>
class ShamirShare : public T, public ShareInterface
{
    typedef ShamirShare This;

public:
    typedef T clear;
    typedef T open_type;
    typedef void sacri_type;
    typedef This share_type;

    typedef Shamir<ShamirShare> Protocol;
    typedef IndirectShamirMC<ShamirShare> MAC_Check;
    typedef ShamirMC<ShamirShare> Direct_MC;
    typedef ShamirInput<ShamirShare> Input;
    typedef MaliciousShamirPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef ReplicatedPrep<ShamirShare> LivePrep;
    typedef ReplicatedRingPrep<ShamirShare> TriplePrep;
    typedef ShamirShare Honest;

#ifndef NO_MIXED_CIRCUITS
    typedef GC::CcdSecret<gf2n_<octet>> bit_type;
#endif

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    static true_type variable_players;
    const static bool expensive = false;
    const static bool malicious = false;
    const static int bit_generation_threshold = 3;
    static false_type is_clear;

    static string type_short()
    {
        auto res = "S" + string(1, clear::type_char());
        auto opts = ShamirOptions::singleton;
        if (opts.threshold != (opts.nparties - 1) / 2)
            res += "T" + to_string(opts.threshold);
        return res;
    }
    static string type_string()
    {
        return "Shamir " + T::type_string();
    }

    static string alt()
    {
        return "ATLAS";
    }

    static int threshold(int)
    {
        return ShamirMachine::s().threshold;
    }

    static T get_rec_factor(int i, int n)
    {
        return Protocol::get_rec_factor(i, n);
    }

    static ShamirShare constant(T value, int, const mac_key_type& = {})
    {
        return ShamirShare(value);
    }

    ShamirShare()
    {
    }
    template<class U>
    ShamirShare(const U& other)
    {
        T::operator=(other);
    }

    void assign(const char* buffer)
    {
        T::assign(buffer);
    }

    ShamirShare operator<<(int i)
    {
        return *this * (T(1) << i);
    }
    ShamirShare& operator<<=(int i)
    {
        *this = *this << i;
        return *this;
    }

    void force_to_bit()
    {
        throw not_implemented();
    }

    ShamirShare get_bit(int)
    {
        throw runtime_error("never call this");
    }

    void pack(octetStream& os, const T& rec_factor) const
    {
        (*this * rec_factor).pack(os);
    }
    void pack(octetStream& os) const
    {
        T::pack(os);
    }
    void unpack(octetStream& os, bool full = true)
    {
        assert(full);
        T::unpack(os);
    }
};

template<class T>
true_type ShamirShare<T>::variable_players;

template<class T>
false_type ShamirShare<T>::is_clear;

#endif /* PROTOCOLS_SHAMIRSHARE_H_ */
