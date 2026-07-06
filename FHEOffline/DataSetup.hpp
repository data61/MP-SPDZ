/*
 * DataSetup.hpp
 *
 */

#ifndef FHEOFFLINE_DATASETUP_HPP_
#define FHEOFFLINE_DATASETUP_HPP_

#include "Networking/Player.h"
#include "Tools/Bundle.h"

template<class T, class U, class V>
string full_secrets_filename(T& setup, U& machine, const Player& P,
        int num_runs, V)
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
    return filename;
}

template<class T, class U, class V, class W>
void read_or_generate_secrets(T& setup, Player& P, U& machine,
        int num_runs, V, W, bool read_only = false)
{
    octetStream os;
    string filename = full_secrets_filename(setup, machine, P, num_runs, V());
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
        if (OnlineOptions::singleton.has_option("expect_setup") or read_only)
            throw runtime_error("error in setup: " + error);

        cerr << "Running secrets generation because no suitable material "
                "from a previous run was found (" << error << ")" << endl;
        setup.key_and_mac_generation(P, machine, num_runs, V());
        W::LivePrep::adjust_mac_key(P);

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
void secure_init(T& setup, Player& P, U& machine, int sec, V, bool read_only,
        true_type)
{
    OnlineOptions::singleton.prime = V::pr(true);
    setup.secure_init(P, machine,
            V::length() ? V::length() : OnlineOptions::singleton.lgp, sec,
            read_only);
}

template<class T, class U, class V>
void secure_init(T& setup, Player& P, U& machine, int sec, V, bool read_only,
        false_type)
{
    setup.secure_init(P, machine, V::length(), sec, read_only);
}

template <class T, class U, class V>
void secure_init(T& setup, Player& P, U& machine, V, int sec, bool read_only = false)
{
    secure_init(setup, P, machine, sec, V(), read_only, V::prime_field);
}

#endif /* FHEOFFLINE_DATASETUP_HPP_ */
