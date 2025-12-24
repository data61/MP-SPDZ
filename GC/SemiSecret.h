/*
 * SemiSecret.h
 *
 */

#ifndef GC_SEMISECRET_H_
#define GC_SEMISECRET_H_

#include "Protocols/SemiMC.h"
#include "Protocols/SemiShare.h"
#include "Protocols/DealerShare.h"
#include "Processor/DummyProtocol.h"
#include "ShareSecret.h"

template<class T> class Beaver;

namespace GC
{

class SemiPrep;
class DealerPrep;
class Semi;

template<class T, class V>
class SemiSecretBase : public V, public ShareSecret<T>
{
    typedef V super;

public:
    typedef Memory<T> DynamicMemory;

    typedef Beaver<T> Protocol;

    typedef T part_type;
    typedef T small_type;

    static const bool is_real = true;

    static const int default_length = sizeof(BitVec) * 8;

    static const bool symmetric = V::symmetric;

    static bool real_shares(const Player& P)
    {
        return V::real_shares(P);
    }

    static string type_string() { return "binary secret"; }
    static string phase_name() { return "Binary computation"; }

    static void trans(Processor<T>& processor, int n_outputs,
            const vector<int>& args);

    static size_t maximum_size()
    {
        return default_length;
    }

    SemiSecretBase()
    {
    }
    SemiSecretBase(long other) :
            V(other)
    {
    }
    template<class U>
    SemiSecretBase(const IntBase<U>& other) :
            V(other)
    {
    }
    template<int K>
    SemiSecretBase(const Z2<K>& other) :
            V(other)
    {
    }

    void load_clear(int n, const Integer& x);

    void bitcom(StackedVector<T>& S, const vector<int>& regs);
    void bitdec(StackedVector<T>& S, const vector<int>& regs) const;

    void xor_(int n, const T& x, const T& y)
    { *this = BitVec(x ^ y).mask(n); }

    void xor_bit(int i, const T& bit)
    { *this ^= bit << i; }

    void reveal(size_t n_bits, Clear& x);

    T lsb()
    { return *this & 1; }
};

class SemiSecret: public SemiSecretBase<SemiSecret, SemiShare<BitVec>>
{
    typedef SemiSecret This;

public:
    typedef SemiSecretBase<SemiSecret, SemiShare<BitVec>> super;

    typedef SemiMC<This> MC;
    typedef DirectSemiMC<This> Direct_MC;
    typedef MC MAC_Check;
    typedef SemiInput<This> Input;
    typedef SemiPrep LivePrep;
    typedef Semi Protocol;

    static MC* new_mc(typename SemiShare<BitVec>::mac_key_type);

    static void andrsvec(Processor<SemiSecret>& processor,
            const vector<int>& args);

    SemiSecret()
    {
    }

    template<class T>
    SemiSecret(const T& other) :
            super(other)
    {
    }
};

class DealerSecret : public SemiSecretBase<DealerSecret, DealerShare<BitVec>>
{
    typedef DealerSecret This;

public:
    typedef SemiSecretBase<DealerSecret, DealerShare<BitVec>> super;

    typedef DealerMC<This> MC;
    typedef DirectDealerMC<This> Direct_MC;
    typedef MC MAC_Check;
    typedef DealerInput<This> Input;
    typedef DealerPrep LivePrep;

    static MC* new_mc(typename super::mac_key_type);

    DealerSecret()
    {
    }

    template<class T>
    DealerSecret(const T& other) :
            super(other)
    {
    }
};

template<class T, class V>
const int SemiSecretBase<T, V>::default_length;

} /* namespace GC */

#endif /* GC_SEMISECRET_H_ */
