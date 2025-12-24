/*
 * PostSacriRepRingShare.h
 *
 */

#ifndef PROTOCOLS_POSTSACRIREPRINGSHARE_H_
#define PROTOCOLS_POSTSACRIREPRINGSHARE_H_

#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/MalRepRingShare.h"
#include "Protocols/Rep3Share2k.h"
#include "GC/MaliciousRepSecret.h"

template<class T> class MalRepRingPrepWithBits;
template<class T> class PostSacrifice;

template<int K, int S>
class PostSacriRepRingShare : public Rep3Share2<K>
{
    typedef Rep3Share2<K> super;
    typedef PostSacriRepRingShare This;

public:
    static const int BIT_LENGTH = K;
    static const int SECURITY = S;

    static const bool has_trunc_pr = false;
    static const bool malicious = true;

    typedef SignedZ2<K> clear;
    typedef MaliciousRep3Share<Z2<K + S>> prep_type;
    typedef Z2<S> random_type;
    typedef MalRepRingShare<K + 2, S> SquareToBitShare;

    typedef PostSacrifice<PostSacriRepRingShare> BasicProtocol;
    typedef HashMaliciousRepMC<PostSacriRepRingShare> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<PostSacriRepRingShare> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef MalRepRingPrepWithBits<PostSacriRepRingShare> LivePrep;
    typedef MaybeHemi<This> Protocol;
    typedef DummyMatrixPrep<This> MatrixPrep;

    typedef GC::MaliciousRepSecret bit_type;

    const static bool expensive = true;

    static string type_short()
    {
        return "PR";
    }

    PostSacriRepRingShare()
    {
    }
    template<class U>
    PostSacriRepRingShare(const U& other) : super(other)
    {
    }

    template<class U>
    static void split(StackedVector<U>& dest, const vector<int>& regs, int n_bits,
            const super* source, int n_inputs,
            typename bit_type::Protocol& protocol)
    {
        if (regs.size() / n_bits != 3)
            throw runtime_error("only secure with three-way split");

        super::split(dest, regs, n_bits, source, n_inputs, protocol);
    }
};

#endif /* PROTOCOLS_POSTSACRIREPRINGSHARE_H_ */
