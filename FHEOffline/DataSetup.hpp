/*
 * DataSetup.hpp
 *
 */

#ifndef FHEOFFLINE_DATASETUP_HPP_
#define FHEOFFLINE_DATASETUP_HPP_

#include "Networking/Player.h"
#include "Tools/Bundle.h"

#include "Protocols/fake-stuff.hpp"

template<class T, class U, class V, class W>
void read_or_generate_secrets(T& setup, Player& P, U& machine,
        int num_runs, V, W)
{
    octetStream os;
    setup.params.pack(os);
    setup.FieldD.pack(os);
    bool covert = num_runs > 0;
    assert(covert == V());
    string filename = PREP_DIR + setup.protocol_name(covert) + "-Secrets-"
            + (covert ? to_string(num_runs) : to_string(machine.sec)) + "-"
            + os.check_sum(20).get_str(16) + "-P" + to_string(P.my_num()) + "-"
            + to_string(P.num_players());

    string error;

    try
    {
        os.input(filename);
        setup.unpack(os);
        machine.unpack(os);
    }
    catch (exception& e)
    {
        error = e.what();
    }

    try
    {
        setup.check(P, machine);
        machine.check(P);
    }
    catch (mismatch_among_parties& e)
    {
        if (error.empty())
            error = e.what();
    }

    if (not error.empty())
    {
        if (OnlineOptions::singleton.has_option("expect_setup"))
            throw runtime_error("error in setup: " + error);

        cerr << "Running secrets generation because no suitable material "
                "from a previous run was found (" << error << ")" << endl;
        setup.key_and_mac_generation(P, machine, num_runs, V());

        ofstream output(filename);
        octetStream os;
        setup.pack(os);
        machine.pack(os);
        os.output(output);
    }

    W::set_mac_key(setup.alphai);
    write_mac_key<W>(P.N, setup.alphai);
}

template <class T, class U, class V>
void secure_init(T& setup, Player& P, U& machine, int sec, V, true_type)
{
    OnlineOptions::singleton.prime = V::pr(true);
    setup.secure_init(P, machine,
            V::length() ? V::length() : OnlineOptions::singleton.lgp, sec);
}

template <class T, class U, class V>
void secure_init(T& setup, Player& P, U& machine, int sec, V, false_type)
{
    setup.secure_init(P, machine, V::length(), sec);
}

template <class T, class U, class V>
void secure_init(T& setup, Player& P, U& machine, V, int sec)
{
    secure_init(setup, P, machine, sec, V(), V::prime_field);
}

#endif /* FHEOFFLINE_DATASETUP_HPP_ */
