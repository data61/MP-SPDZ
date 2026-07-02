/*
 * TinierSharePrep.h
 *
 */

#ifndef GC_TINIERSHAREPREP_H_
#define GC_TINIERSHAREPREP_H_

#include "Protocols/ReplicatedPrep.h"
#include "OT/NPartyTripleGenerator.h"
#include "ShareThread.h"
#include "PersonalPrep.h"

namespace GC
{

template<class T> class TinierPrep;
template<class T> class TinierSecret;

template<class T>
class TinierSharePrep : public PersonalPrep<T>
{
    typename T::TripleGenerator* triple_generator;
    typename T::whole_type::TripleGenerator* real_triple_generator;
    MascotParams params;

    typedef typename T::whole_type secret_type;

    void buffer_triples();
    void buffer_squares() { throw not_implemented(); }
    void buffer_bits();
    void buffer_inverses() { throw not_implemented(); }

    void buffer_inputs(int player);

    void buffer_secret_triples();

    void init_real(Player& P);

public:
    static typename T::mac_key_type get_mac_key(Player& P)
    {
        return T::TripleGenerator::get_mac_key(P);
    }

    TinierSharePrep(DataPositions& usage, int input_player =
            PersonalPrep<T>::SECURE);
    TinierSharePrep(SubProcessor<T>*, DataPositions& usage);
    ~TinierSharePrep();

    void set_protocol(typename T::Protocol& protocol);
};

}

#endif /* GC_TINIERSHAREPREP_H_ */
