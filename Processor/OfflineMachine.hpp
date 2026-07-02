/*
 * DishonestMajorityOfflineMachine.hpp
 *
 */

#ifndef PROCESSOR_OFFLINEMACHINE_HPP_
#define PROCESSOR_OFFLINEMACHINE_HPP_

#include "OfflineMachine.h"
#include "Protocols/mac_key.hpp"
#include "Tools/Buffer.h"

template<class W>
template<class V>
OfflineMachine<W>::OfflineMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, OnlineOptions& online_opts, V,
        int nplayers) :
        W(argc, argv, opt, online_opts, V(), nplayers), playerNames(
                W::playerNames), P(*this->new_player("machine"))
{
    load_schedule(online_opts.progname, false);
    Program program(playerNames.num_players());
    program.parse(bc_filenames[0]);
    progs.push_back(program);

    if (program.usage_unknown())
    {
        cerr << "Preprocessing will be insufficient "
                << "due to unknown requirements" << endl;
        exit(1);
    }

    usage = program.get_offline_data_used();
}

template<class W>
OfflineMachine<W>::~OfflineMachine()
{
    delete &P;
}

template<class W>
template<class T, class U>
int OfflineMachine<W>::run()
{
    if (this->online_opts.prime)
        T::clear::init_field(this->online_opts.prime);
    else
        T::clear::init_default(this->online_opts.prime_length());
    Machine<T, U>::init_binary_domains(this->online_opts.security_parameter,
            this->get_lg2());
    auto binary_mac_key = T::bit_type::LivePrep::get_mac_key(P);
    typename T::bit_type::LivePrep bit_prep(usage);
    GC::ShareThread<typename T::bit_type> thread(bit_prep, P, binary_mac_key);

    // setup before generation to fix prime
    T::LivePrep::basic_setup(P);

    T::MAC_Check::setup(P);
    T::bit_type::MAC_Check::setup(P);
    U::MAC_Check::setup(P);

    generate<T>();
    generate<typename T::bit_type::part_type>();
    generate<U>();

    thread.MC->Check(P);

    T::MAC_Check::teardown();
    T::bit_type::MAC_Check::teardown();
    U::MAC_Check::teardown();

    return 0;
}

template<class W>
int OfflineMachine<W>::buffered_total(size_t required, size_t batch)
{
    return DIV_CEIL(required, batch) * batch + (nthreads - 1) * batch;
}

template<class W>
template<class T>
void OfflineMachine<W>::generate()
{
    T::clear::next::template init<typename T::clear>(false);
    T::clear::template write_setup<T>(P.num_players());
    auto mac_key = T::LivePrep::get_mac_key(P);
    DataPositions generated;
    generated.set_num_players(P.num_players());
    typename T::MAC_Check output(mac_key);
    typename T::LivePrep preprocessing(0, generated);
    SubProcessor<T> processor(output, preprocessing, P);

    auto& domain_usage = usage.files[T::clear::field_type()];
    for (unsigned i = 0; i < domain_usage.size(); i++)
    {
        auto my_usage = domain_usage[i];
        Dtype dtype = Dtype(i);
        string filename = Sub_Data_Files<T>::get_filename(playerNames, dtype,
                0);
        if (my_usage > 0)
        {
            ofstream out(filename, iostream::out | iostream::binary);
            file_signature<T>().output(out);
            if (i == DATA_DABIT)
            {
                for (long long j = 0;
                        j < buffered_total(my_usage, BUFFER_SIZE); j++)
                {
                    T a;
                    typename T::bit_type b;
                    preprocessing.get_dabit(a, b);
                    dabit<T>(a, b).output(out, false);
                }
            }
            else if (not (i == DATA_RANDOM or i == DATA_OPEN))
            {
                vector<T> tuple(DataPositions::tuple_size[i]);
                for (long long j = 0;
                        j < buffered_total(my_usage, BUFFER_SIZE); j++)
                {
                    preprocessing.get(dtype, tuple.data());
                    for (auto& x : tuple)
                        x.output(out, false);
                }
            }
        }
        else
            remove(filename.c_str());
    }

    long additional_inputs = Sub_Data_Files<T>::additional_inputs(usage);

    for (int i = 0; i < P.num_players(); i++)
    {
        auto n_inputs = usage.inputs[i][T::clear::field_type()]
                + additional_inputs;
        string filename = Sub_Data_Files<T>::get_input_filename(playerNames, i, 0);
        if (n_inputs > 0)
        {
            ofstream out(filename, iostream::out | iostream::binary);
            file_signature<T>().output(out);
            InputTuple<T> tuple;
            for (long long j = 0;
                    j < buffered_total(n_inputs, BUFFER_SIZE); j++)
            {
                preprocessing.get_input(tuple.share, tuple.value, i);
                tuple.share.output(out, false);
                if (i == P.my_num())
                    tuple.value.output(out, false);
            }
        }
        else
            remove(filename.c_str());
    }

    if (T::clear::field_type() == DATA_INT)
    {
        int max_n_bits = 0;
        for (auto& x : usage.edabits)
            max_n_bits = max(max_n_bits, x.first.second);

        for (int n_bits = 1; n_bits <= max(100, max_n_bits); n_bits++)
        {
            int batch = edabitvec<T>::MAX_SIZE;
            int total = usage.edabits[{false, n_bits}] +
                    usage.edabits[{true, n_bits}];
            string filename = Sub_Data_Files<T>::get_edabit_filename(playerNames,
                                n_bits, 0);
            if (total > 0)
            {
                ofstream out(filename, ios::binary);
                file_signature<T>().output(out);
                auto& opts = OnlineOptions::singleton;
                opts.batch_size = DIV_CEIL(opts.batch_size, batch) * batch;
                for (int i = 0; i < buffered_total(total, batch) / batch; i++)
                    preprocessing.get_edabitvec(true, n_bits).output(n_bits,
                            out);
            }
            else
                remove(filename.c_str());
        }
    }

    output.Check(P);
}

template<class W>
const Names& OfflineMachine<W>::get_N()
{
    return playerNames;
}

#endif /* PROCESSOR_OFFLINEMACHINE_HPP_ */
