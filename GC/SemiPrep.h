/*
 * SemiPrep.h
 *
 */

#ifndef GC_SEMIPREP_H_
#define GC_SEMIPREP_H_

#include "Protocols/ReplicatedPrep.h"
#include "OT/MascotParams.h"
#include "SemiSecret.h"
#include "ShiftableTripleBuffer.h"
#include "SemiSecureShuffle.h"

template<class T> class Beaver;
template<class T> class SubProcessor;

namespace GC
{

template<class T> class ShareThread;

class SemiPrep : public BufferPrep<SemiSecret>, ShiftableTripleBuffer<SemiSecret>
{
    SemiSecret::TripleGenerator* triple_generator;
    MascotParams params;

    SeededPRNG secure_prng;

    vector<array<SemiSecret, 3>> mixed_triples;

    SemiSecureTripleState* state;

    OTExtensionWithMatrix* rot_ext;

public:
    SemiPrep(DataPositions& usage, bool = true);
    SemiPrep(void*, DataPositions& usage) : SemiPrep(usage) {}
    ~SemiPrep();

    void set_protocol(SemiSecret::Protocol& protocol);

    void buffer_triples();
    void buffer_bits();

    void buffer_squares() { throw not_implemented(); }
    void buffer_inverses() { throw not_implemented(); }

    array<SemiSecret, 3> get_mixed_triple(int n);

    void get(Dtype type, SemiSecret* data)
    {
        BufferPrep<SemiSecret>::get(type, data);
    }

    array<SemiSecret, 3> get_triple_no_count(int n_bits)
    {
        if (n_bits == -1)
            n_bits = SemiSecret::default_length;
        return ShiftableTripleBuffer<SemiSecret>::get_triple_no_count(n_bits);
    }

    void buffer_personal_triples(vector<array<SemiSecret, 3>>&, size_t, size_t)
    {
        throw not_implemented();
    }
};

} /* namespace GC */

#endif /* GC_SEMIPREP_H_ */
