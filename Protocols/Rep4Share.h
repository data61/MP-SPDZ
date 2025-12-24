/*
 * Rep4Share.h
 *
 */

#ifndef PROTOCOLS_REP4SHARE_H_
#define PROTOCOLS_REP4SHARE_H_

#include "Rep3Share.h"

template<class T> class Rep4MC;
template<class T> class Rep4;
template<class T> class Rep4RingPrep;
template<class T> class Rep4Input;

namespace GC
{
class Rep4Secret;
}

template<class T>
class Rep4Share : public RepShare<T, 3>
{
    typedef Rep4Share This;
    typedef RepShare<T, 3> super;

public:
    typedef T clear;

    typedef Rep4<This> Protocol;
    typedef Rep4MC<This> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef Rep4Input<This> Input;
    typedef ::PrivateOutput<This> PrivateOutput;
    typedef Rep4RingPrep<This> LivePrep;
    typedef LivePrep SquarePrep;
    typedef LivePrep TriplePrep;

    typedef This Honest;

    typedef GC::Rep4Secret bit_type;

    static const bool malicious = true;
    static const bool variable_players = false;
    static const bool semi_honest_option = true;

    static string type_short()
    {
        return "R4" + string(1, T::type_char());
    }

    static This constant(clear value, int my_num, typename super::mac_key_type = {})
    {
        This res;
        if (my_num != 0)
            res[3 - my_num] = value;
        return res;
    }

    Rep4Share()
    {
    }

    template<class U>
    Rep4Share(const FixedVec<U, 3>& other) : super(other)
    {
    }

    void assign(clear value, int my_num, clear = {})
    {
        *this = constant(value, my_num);
    }
    void assign(const char* buffer)
    {
        super::assign(buffer);
    }

};

#endif /* PROTOCOLS_REP4SHARE_H_ */
