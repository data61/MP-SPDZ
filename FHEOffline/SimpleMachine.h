/*
 * SimpleMachine.h
 *
 */

#ifndef FHEOFFLINE_SIMPLEMACHINE_H_
#define FHEOFFLINE_SIMPLEMACHINE_H_

#include "FHE/FHE_Keys.h"
#include "FHEOffline/DataSetup.h"
#include "Networking/Player.h"
#include "FHEOffline/SimpleGenerator.h"
#include "Tools/OfflineMachineBase.h"

class MachineBase : public OfflineMachineBase
{
    template<class T> friend class CowGearPrep;

protected:
    vector<GeneratorBase*> generators;
    string hostname;
    Timer timer;
    pthread_t throughput_loop_thread;
    int portnum_base;
    Dtype data_type;

public:
    int sec;
    int field_size;
    int extra_slack;
    bool produce_inputs;
    bool use_gf2n;

    MachineBase();
    MachineBase(int argc, const char** argv);
    void run();

    void parse_options(int argc, const char** argv);

    string item_type();

    void throughput_loop();
    static void* run_throughput_loop(void* machine);

    size_t report_size(ReportType type);

    template<class FD>
    string get_prep_dir(Player& P) const
    { return get_prep_sub_dir<Share<typename FD::T>>(P.num_players()); }

    string tradeoff();

    void mult_performance();

    void pack(octetStream&) const {}
    void unpack(octetStream&) {}

    void check(Player&) const {}

    // computational security doesn't matter in global proofs
    int comp_sec() { return 0; }
};

class MultiplicativeMachineParams : public MachineBase
{
public:
    DataSetup setup;

    virtual ~MultiplicativeMachineParams() {}

    virtual int get_covert() const { return 0; }
};

class MultiplicativeMachine : public MultiplicativeMachineParams
{
    PlainPlayer P;

protected:
    void parse_options(int argc, const char** argv);

    void generate_setup(int slack);
    template <class FD>
    void fake_keys(int slack);

public:
    MultiplicativeMachine();
    virtual ~MultiplicativeMachine();
};

class SimpleMachine : public MultiplicativeMachine
{
    template <template <class FD> class EC, class FD>
    GeneratorBase* new_generator(int i);

public:
    SimpleMachine(int argc, const char** argv);
};

#endif /* FHEOFFLINE_SIMPLEMACHINE_H_ */
