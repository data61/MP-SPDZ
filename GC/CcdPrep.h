/*
 * CcdPrep.h
 *
 */

#ifndef GC_CCDPREP_H_
#define GC_CCDPREP_H_

#include "Protocols/ReplicatedPrep.h"

class DataPositions;

namespace GC
{

template<class T> class ShareThread;

template<class T>
class CcdPrep : public BufferPrep<T>
{
    typename T::part_type::LivePrep part_prep;
    SubProcessor<typename T::part_type>* part_proc;

public:
    static const bool use_part = true;

    static typename T::mac_key_type get_mac_key(Player& P)
    {
        return T::part_type::LivePrep::get_mac_key(P);
    }

    CcdPrep(DataPositions& usage) :
            BufferPrep<T>(usage), part_prep(usage), part_proc(0)
    {
    }

    CcdPrep(SubProcessor<T>*, DataPositions& usage) :
            CcdPrep(usage)
    {
    }

    ~CcdPrep();

    void set_protocol(typename T::Protocol& protocol);

    Preprocessing<typename T::part_type>& get_part()
    {
        return part_prep;
    }

    void buffer_triples()
    {
        assert(part_proc);
        this->triples.push_back({});
        for (auto& x : this->triples.back())
            x.resize_regs(T::default_length);
        for (int i = 0; i < T::default_length; i++)
        {
            auto triple = part_prep.get_triple(1);
            for (int j = 0; j < 3; j++)
                this->triples.back()[j].get_bit(j) = triple[j];
        }
    }

    void buffer_bits()
    {
        assert(part_proc);
        for (int i = 0; i < OnlineOptions::singleton.batch_size; i++)
        {
            typename T::part_type tmp;
            part_prep.get_one_no_count(DATA_BIT, tmp);
            this->bits.push_back(tmp);
        }
    }

    void buffer_squares()
    {
        throw not_implemented();
    }

    void buffer_inverses()
    {
        throw not_implemented();
    }

    void buffer_inputs(int player)
    {
        this->inputs[player].push_back({});
        this->inputs[player].back().share.resize_regs(T::default_length);
        for (int i = 0; i < T::default_length; i++)
        {
            typename T::part_type::open_type tmp;
            part_prep.get_input(this->inputs[player].back().share.get_reg(i),
                    tmp, player);
            this->inputs[player].back().value ^=
                    (typename T::clear(tmp.get_bit(0)) << i);
        }
    }
};

} /* namespace GC */

#endif /* GC_CCDPREP_H_ */
