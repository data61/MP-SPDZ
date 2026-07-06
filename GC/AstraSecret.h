/*
 * AstraSecret.h
 *
 */

#ifndef GC_ASTRASECRET_H_
#define GC_ASTRASECRET_H_

#include "ShareSecret.h"
#include "Protocols/AstraMC.h"
#include "Protocols/AstraShare.h"
#include "Tools/CheckVector.h"

namespace GC
{

template<class T>
class AstraSecretBase : public ShareSecret<T>
{
public:
    static void trans(Processor<T>& processor, int n_outputs,
            const ArgVector& args)
    {
        vec_trans(processor, n_outputs, args);
    }
};

template<class U>
class AstraSecret : public U, public AstraSecretBase<AstraSecret<U>>
{
    typedef AstraSecret This;
    typedef U super;

public:
    typedef This part_type;
    typedef This small_type;

    typedef typename super::template mc_template<This> MC;
    typedef MC MAC_Check;

    typedef NoLivePrep<This> LivePrep;
    typedef typename super::template protocol_template<This> Protocol;
    typedef typename super::template input_template<This> Input;

    static const bool is_real = super::is_real;
    static const bool symmetric = super::symmetric;
    static const int default_length = super::clear::N_BITS;

    static bool real_shares(const Player& P)
    {
        return super::real_shares(P);
    }

    static MC* new_mc(typename super::mac_key_type)
    {
        return new MC;
    }

    static This constant(const typename super::clear& value, int my_num,
            typename super::mac_key_type, int = -1)
    {
        return super::constant(value, my_num);
    }

    AstraSecret()
    {
    }
    template <class T>
    AstraSecret(const T& other) :
            super(other)
    {
    }

    void load_clear(int n, const Integer& x)
    {
        this->check_length(n, x);
        *this = super::constant(x);
    }

    void bitcom(StackedVector<This>& S, const ArgVector& regs)
    {
        plain_bitcom(*this, S, regs);
    }

    void bitdec(StackedVector<This>& S, const ArgVector& regs) const
    {
        plain_bitdec(*this, S, regs);
    }
};

template<class T>
const int AstraSecret<T>::default_length;

}

#endif /* GC_ASTRASECRET_H_ */
