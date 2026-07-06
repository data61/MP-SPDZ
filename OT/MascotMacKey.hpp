/*
 * MascotMayKey.hpp
 *
 */

#ifndef OT_MASCOTMACKEY_HPP_
#define OT_MASCOTMACKEY_HPP_

#include "MascotMacKey.h"
#include "OTMultiplier.hpp"

#include "Protocols/Share.hpp"

template<class share_type>
string get_ot_secrets_filename(const Player& P)
{
    octetStream os;
    share_type::specification(os);
    string filename = string(PREP_DIR) + "/Mascot-Secrets-"
            + share_type::clear::type_short() + "-"
            + to_string(share_type::clear::length()) + "-"
            + os.check_sum(20).get_str(16) + "-P" + to_string(P.my_num()) + "-"
            + to_string(P.num_players());
    return filename;
}

template<class T>
template<class share_type>
void MascotMacKey<T>::read_or_generate(Player& P)
{
    auto filename = get_ot_secrets_filename<share_type>(P);
    octetStream os;

    auto& key = *this;

    try
    {
        os.input(filename);
        unpack(os);
        BitVector keyBits;
        keyBits.set(key);
        if (key.ot.base_receiver_inputs != keyBits)
            throw runtime_error("inconsistent key");
    }
    catch (exception& e)
    {
        cerr << "No proper key material found in " << filename
                << ", generating from scratch (" << e.what() << ")" << endl;
        SeededPRNG G;
        key.randomize(G);
        key.ot = OTTripleSetup(P, true);
        key.ot.base_receiver_inputs.set(key);
        auto ot_setup = BaseMachine::fresh_ot_setup(P);
        for (int i = 0; i < P.num_players(); i++)
            if (i != P.my_num())
                OTMultiplierBase::init(key, P, i, ot_setup);
    }

    os.reset_write_head();
    key.get_fresh().pack(os);
    os.output(filename);
    share_type::set_mac_key(key);
    write_mac_key<typename share_type::part_type>(P.N, key);
}

#endif /* OT_MASCOTMACKEY_HPP_ */
