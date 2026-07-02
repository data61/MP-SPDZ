/*
 * Spdz2kShare.h
 *
 */

#ifndef PROTOCOLS_SPDZ2KSHARE_H_
#define PROTOCOLS_SPDZ2KSHARE_H_

#ifndef SPDZ2K_DEFAULT_SECURITY
#define SPDZ2K_DEFAULT_SECURITY 64
#endif

#include "Math/Z2k.h"
#include "Protocols/Share.h"
#include "Protocols/MAC_Check.h"
#include "Processor/DummyProtocol.h"
#include "OT/Rectangle.h"

template<int K, int S> class Spdz2kMultiplier;
template<class T> class Spdz2kTripleGenerator;
template<class T> class SPDZ2k;

namespace GC
{
template<int S> class TinySecret;
}

template<int K, int S>
class Spdz2kShare : public Share<Z2<K + S>>
{
    typedef Spdz2kShare This;

public:
    typedef Z2<K + S> tmp_type;
    typedef Share<tmp_type> super;

//    typedef Integer clear;
    typedef SignedZ2<K> clear;

    typedef Z2<S> mac_key_type;
    typedef Z2<K + S> open_type;

    typedef Spdz2kShare prep_type;
    typedef Spdz2kShare<K + 2, S> bit_prep_type;
    typedef Spdz2kShare<K + S, S> prep_check_type;
    typedef Spdz2kShare input_check_type;
    typedef Spdz2kMultiplier<K, S> Multiplier;
    typedef Spdz2kTripleGenerator<Spdz2kShare> TripleGenerator;
    typedef Z2<K + 2 * S> sacri_type;
    typedef Z2kRectangle<TAU(K, S), K + S> Rectangle;
    typedef This part_type;

    typedef MAC_Check_Z2k<Z2<K + S>, Z2<S>, open_type, Spdz2kShare> MAC_Check;
    typedef Direct_MAC_Check_Z2k<Spdz2kShare> Direct_MC;
    typedef ::Input<Spdz2kShare> Input;
    typedef ::PrivateOutput<Spdz2kShare> PrivateOutput;
    typedef Beaver<This> BasicProtocol;
    typedef DummyMatrixPrep<This> MatrixPrep;
    typedef SPDZ2k<Spdz2kShare> Protocol;
    typedef Spdz2kPrep<Spdz2kShare> LivePrep;

#ifndef NO_MIXED_CIRCUITS
#ifdef SPDZ2K_BIT
    typedef GC::TinySecret<S> bit_type;
#endif
#endif

    const static int k = K;
    const static int s = S;

    const static bool randoms_for_opens = true;

    static string type_string() { return "SPDZ2^(" + to_string(K) + "+" + to_string(S) + ")"; }
    static string type_short() { return "Z" + to_string(K) + "," + to_string(S); }

    template<class T>
    static string proto_fake_opts() { return " -Z " + to_string(K) + " -S " + to_string(S); }

    Spdz2kShare() {}
    template<class T, class V>
    Spdz2kShare(const Share_<T, V>& x) : super(x) {}
    template<class T, class V>
    Spdz2kShare(const T& share, const V& mac) : super(share, mac) {}
};


template<int K, int S>
Spdz2kShare<K, S> operator*(const typename Spdz2kShare<K,S>::open_type& x, Spdz2kShare<K, S>& y)
{
    return typename Spdz2kShare<K,S>::tmp_type(x) * typename Spdz2kShare<K,S>::super(y);
}

#endif /* PROTOCOLS_SPDZ2KSHARE_H_ */
