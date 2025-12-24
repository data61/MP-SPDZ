/*
 * TinyPrep.cpp
 *
 */

#include "TinierSharePrep.h"

#include "Protocols/MascotPrep.hpp"
#include "Protocols/ShuffleSacrifice.hpp"
#include "Protocols/MalRepRingPrep.hpp"

namespace GC
{

template<class T>
void TinierSharePrep<T>::init_real(Player& P)
{
    assert(real_triple_generator == 0);
    auto& thread = ShareThread<secret_type>::s();
    real_triple_generator = new typename T::whole_type::TripleGenerator(
            BaseMachine::fresh_ot_setup(P), P.N, -1,
            OnlineOptions::singleton.batch_size, 1, params,
            thread.MC->get_alphai(), &P);
    real_triple_generator->multi_threaded = false;
}

template<class T>
void TinierSharePrep<T>::buffer_secret_triples()
{
    CODE_LOCATION
    auto& thread = ShareThread<secret_type>::s();
    auto& triple_generator = real_triple_generator;
    assert(triple_generator != 0);
    params.generateBits = false;
    vector<array<T, 3>> triples;
    TripleShuffleSacrifice<T> sacrifice;
    size_t required;
    required = sacrifice.minimum_n_inputs_with_combining(
            BaseMachine::batch_size<T>(DATA_TRIPLE));
    triple_generator->set_batch_size(DIV_CEIL(required, 64));
    while (triples.size() < required)
    {
        triple_generator->generatePlainTriples();
        triple_generator->unlock();
        assert(triple_generator->plainTriples.size() != 0);
        for (size_t i = 0; i < triple_generator->plainTriples.size(); i++)
            triple_generator->valueBits[2].set_portion(i,
                    triple_generator->plainTriples[i][2]);
        triple_generator->run_multipliers({});
        assert(triple_generator->plainTriples.size() != 0);
        for (size_t i = 0; i < triple_generator->plainTriples.size(); i++)
        {
            int dl = secret_type::default_length;
            for (int j = 0; j < dl; j++)
            {
                triples.push_back({});
                for (int k = 0; k < 3; k++)
                {
                    auto& share = triples.back()[k];
                    share.set_share(
                            triple_generator->plainTriples.at(i).at(k).get_bit(
                                    j));
                    typename T::mac_type mac;
                    mac = thread.MC->get_alphai() * share.get_share();
                    for (auto& multiplier : triple_generator->ot_multipliers)
                        mac += multiplier->macs.at(k).at(i * dl + j);
                    share.set_mac(mac);
                }
            }
        }
    }
    sacrifice.triple_sacrifice(triples, triples,
            *thread.P, thread.MC->get_part_MC());
    sacrifice.triple_combine(triples, triples, *thread.P,
            thread.MC->get_part_MC());
    for (auto& triple : triples)
        this->triples.push_back(triple);
}

} /* namespace GC */
