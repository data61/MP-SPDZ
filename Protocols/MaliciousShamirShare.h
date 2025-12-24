/*
 * MaliciousShamirShare.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSSHAMIRSHARE_H_
#define PROTOCOLS_MALICIOUSSHAMIRSHARE_H_

#include "ShamirShare.h"
#include "Protocols/Beaver.h"
#include "Protocols/MaliciousShamirMC.h"

template<class T> class MaliciousRepPrepWithBits;
template<class T> class MaliciousRepPrep;
template<class T> class MaliciousShamirPO;
template<class T> class SpecificPrivateOutput;

namespace GC
{
template<class T> class MaliciousCcdSecret;
}

template<class T>
class MaliciousShamirShare : public ShamirShare<T>
{
    typedef ShamirShare<T> super;
    typedef MaliciousShamirShare This;

public:
    typedef Beaver<MaliciousShamirShare<T>> BasicProtocol;
    typedef MaliciousShamirMC<MaliciousShamirShare> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ShamirInput<MaliciousShamirShare> Input;
    typedef MaliciousShamirPO<MaliciousShamirShare> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef ShamirShare<T> Honest;
    typedef MaliciousRepPrepWithBits<MaliciousShamirShare> LivePrep;
    typedef MaliciousRepPrep<MaliciousShamirShare> TriplePrep;
    typedef T random_type;
    typedef MaybeHemi<This> Protocol;
    typedef DummyMatrixPrep<This> MatrixPrep;

    // indicate security relevance of field size
    typedef T mac_key_type;

#ifndef NO_MIXED_CIRCUITS
    typedef GC::MaliciousCcdSecret<gf2n_short> bit_type;
#endif

    static const bool malicious = true;

    static string type_short()
    {
        return "M" + super::type_short();
    }

    static string alt()
    {
        return "";
    }

    MaliciousShamirShare()
    {
    }
    template<class U>
    MaliciousShamirShare(const U& other) : super(other)
    {
    }
};

#endif /* PROTOCOLS_MALICIOUSSHAMIRSHARE_H_ */
