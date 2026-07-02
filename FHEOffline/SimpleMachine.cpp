/*
 * SimpleMachine.cpp
 *
 */

#include <FHEOffline/SimpleEncCommit.h>
#include <FHEOffline/SimpleMachine.h>
#include "FHEOffline/Producer.h"
#include "FHEOffline/Sacrificing.h"
#include "FHE/FHE_Keys.h"
#include "Tools/time-func.h"
#include "Tools/ezOptionParser.h"
#include "Protocols/MAC_Check.h"
#include "Protocols/fake-stuff.h"

#include "Protocols/fake-stuff.hpp"
#include "Protocols/mac_key.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "Math/modp.hpp"

void* run_generator(void* generator)
{
    ((GeneratorBase*)generator)->run();
    return 0;
}

MachineBase::MachineBase() :
        throughput_loop_thread(0),portnum_base(0),
        data_type(DATA_TRIPLE),
        sec(0), field_size(0), extra_slack(0),
        produce_inputs(false),
        use_gf2n(false)
{
}

MachineBase::MachineBase(int argc, const char** argv) : MachineBase()
{
    parse_options(argc, argv);
    mult_performance();
}

void MachineBase::parse_options(int argc, const char** argv)
{
    opt.add(
          "localhost", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Host where party 0 is running (default: localhost)", // Help description.
          "-h", // Flag token.
          "--hostname" // Flag token.
    );
    opt.add(
        "5000", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Base port number (default: 5000).", // Help description.
        "-pn", // Flag token.
        "--portnum" // Flag token.
    );
    opt.add(
          "40", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Statistical security parameter (default: 40)", // Help description.
          "-s", // Flag token.
          "--security" // Flag token.
    );
    opt.add(
          "128", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Logarithmic field size (default: 128)", // Help description.
          "-f", // Flag token.
          "--field-size" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Use extension field GF(2^40)", // Help description.
          "-2", // Flag token.
          "--gf2n" // Flag token.
    );

    OfflineMachineBase::parse_options(argc, argv);
    opt.get("-h")->getString(hostname);
    opt.get("-pn")->getInt(portnum_base);
    opt.get("-s")->getInt(sec);
    opt.get("-f")->getInt(field_size);
    use_gf2n = opt.isSet("-2");
    if (use_gf2n)
    {
        cout << "Using GF(2^40)" << endl;
        field_size = 40;
    }
    start_networking_with_server(hostname, portnum_base);
}

MultiplicativeMachine::MultiplicativeMachine() :
        P(N, "machine-coordinator")
{
    Share<gfp>::MAC_Check::setup(P);
    Share<gf2n_short>::MAC_Check::setup(P);
}

MultiplicativeMachine::~MultiplicativeMachine()
{
    Share<gfp>::MAC_Check::teardown();
    Share<gf2n_short>::MAC_Check::teardown();
}

void MultiplicativeMachine::parse_options(int argc, const char** argv)
{
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Produce squares instead of multiplication triples (default: false)", // Help description.
          "-S", // Flag token.
          "--squares" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Produce bits instead of multiplication triples (default: false)", // Help description.
          "-B", // Flag token.
          "--bits" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Produce inverses instead of multiplication triples (default: false)", // Help description.
          "-I", // Flag token.
          "--inverses" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Produce input tuples instead of multiplication triples (default: false)", // Help description.
          "-i", // Flag token.
          "--inputs" // Flag token.
    );
    MachineBase::parse_options(argc, argv);
    if (opt.isSet("--bits"))
        data_type = DATA_BIT;
    else if (opt.isSet("--squares"))
        data_type = DATA_SQUARE;
    else if (opt.isSet("--inverses"))
        data_type = DATA_INVERSE;
    else
        data_type = DATA_TRIPLE;
    produce_inputs = opt.isSet("--inputs");
    cout << "Going to produce " << item_type() << endl;
}

string MachineBase::item_type()
{
    string res;
    if (produce_inputs)
        res = "Inputs";
    else
        res = DataPositions::dtype_names[data_type];
    transform(res.begin(), res.end(), res.begin(), ::tolower);
    return res;
}

SimpleMachine::SimpleMachine(int argc, const char** argv)
{
    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Use global zero-knowledge proof", // Help description.
          "-g", // Flag token.
          "--global-proof" // Flag token.
    );
    parse_options(argc, argv);
    if (opt.get("-g")->isSet)
        generate_setup(INTERACTIVE_SPDZ1_SLACK);
    else
        generate_setup(NONINTERACTIVE_SPDZ1_SLACK);
    for (int i = 0; i < nthreads; i++)
        if (opt.get("-g")->isSet)
            if (use_gf2n)
                generators.push_back(new_generator<SummingEncCommit, P2Data>(i));
            else
                generators.push_back(new_generator<SummingEncCommit, FFT_Data>(i));
        else
            if (use_gf2n)
                generators.push_back(new_generator<SimpleEncCommit_, P2Data>(i));
            else
                generators.push_back(new_generator<SimpleEncCommit_, FFT_Data>(i));
}

template <template <class FD> class EC, class FD>
GeneratorBase* SimpleMachine::new_generator(int i)
{
    return new SimpleGenerator<EC, FD>(N, setup.part<FD>(), *this, i, data_type);
}


void MultiplicativeMachine::generate_setup(int slack)
{
    if (use_gf2n)
    {
        gf2n_short::init_field(field_size);
        fake_keys<P2Data>(slack);
    }
    else
    {
        fake_keys<FFT_Data>(slack);
    }
}

template <class FD>
void MultiplicativeMachine::fake_keys(int slack)
{
    PlainPlayer P(N, "fake");
    octetStream os;
    PartSetup<FD>& part_setup = setup.part<FD>();
    if (P.my_num() == 0)
    {
        part_setup.generate_setup(N.num_players(), field_size, sec, slack, true);
        vector<PartSetup<FD> > setups;
        part_setup.fake(setups, P.num_players(), false);
        for (int i = 1; i < P.num_players(); i++)
        {
            setups[i].pack(os);
            P.send_to(i, os);
            os.reset_write_head();
        }
        // same transmission for all players, less problem
        setups[0].pack(os);
    }
    else
    {
        P.receive_player(0, os);
    }
    part_setup.unpack(os);
    part_setup.check();

    SeededPRNG G;
    part_setup.alphai.randomize(G);
    Share<typename FD::T>::set_mac_key(part_setup.alphai);
    Plaintext_<FD> m(part_setup.FieldD);
    m.assign_constant(part_setup.alphai);
    vector<Ciphertext> C({part_setup.pk.encrypt(m)});
    TreeSum<Ciphertext>().run(C, P);
    part_setup.calpha = C[0];

    if (output)
        part_setup.output(N);
}

void MachineBase::run()
{
    size_t start_size = 0;
    for (auto& generator : generators)
        start_size += generator->report_size(CAPACITY);
    cout << "Memory requirement at start: " << 1e-9 * start_size << " GB" << endl;
    Timer cpu_timer(CLOCK_PROCESS_CPUTIME_ID);
    timer.start();
    cpu_timer.start();
    pthread_create(&throughput_loop_thread, 0, run_throughput_loop, this);
    for (int i = 0; i < nthreads; i++)
        pthread_create(&(generators[i]->thread), 0, run_generator, generators[i]);
    long long total = 0;
    map<string, double> times;
    size_t memory = 0, sent = 0;
    MemoryUsage memory_usage;
    for (int i = 0; i < nthreads; i++)
    {
        pthread_join(generators[i]->thread, 0);
        total += generators[i]->total;
        auto timers = generators[i]->timers;
        for (auto timer = timers.begin(); timer != timers.end(); timer++)
            times[timer->first] += timer->second.elapsed();
        memory += generators[i]->report_size(CAPACITY);
        cout << "Generator required up to "
                << 1e-9 * generators[i]->report_size(CAPACITY) << " GB" << endl;
        sent += generators[i]->report_sent();
        generators[i]->report_size(CAPACITY, memory_usage);
    }
    pthread_cancel(throughput_loop_thread);
    timer.stop();
    cpu_timer.stop();
    memory_usage.print();
    cout << "Machine required up to " << 1e-9 * memory << " GB" << endl;
    cout << "Minimal requirements are " << 1e-9 * report_size(MINIMAL) << " GB"
            << endl;

    for (int i = 0; i < nthreads; i++)
        delete generators[i];

    for (auto time = times.begin(); time != times.end(); time++)
        cout << time->first << " time on average: " << time->second / nthreads << endl;
    cout << "Sent " << 1e-9 * sent << " GB in total, " << 8e-3 * sent / total
            << " kbit per " << item_type().substr(0, item_type().length() - 1) << endl;
    cout << "Produced " << total << " " << item_type() << " in "
            << timer.elapsed() << " seconds" << endl;
    cout << "CPU time: " << cpu_timer.elapsed() << endl;

    cout << "Time: " << timer.elapsed() << endl;
    cout << "Throughput: " << total / timer.elapsed() << endl;
    mult_performance();
}

void MachineBase::throughput_loop()
{
    deque<size_t> totals;
    for (int j = 1;; j++)
    {
        sleep(60);
        long long total = 0;
        for (int i = 0; i < nthreads; i++)
            total += generators[i]->total;
        double elapsed = timer.elapsed();
        cout << "Throughput after " << j << " minutes: " << total / elapsed
                << " = " << total << " / " << elapsed << tradeoff() << endl;
        totals.push_back(total);
        if (totals.size() > 60)
        {
            cout << "Throughput in the last hour: "
                    << (total - totals.front()) / 3600.0 << tradeoff() << endl;
            totals.pop_front();
        }
    }
}

void* MachineBase::run_throughput_loop(void* machine)
{
    pthread_detach(pthread_self());
    ((MachineBase*)machine)->throughput_loop();
    return 0;
}

size_t MachineBase::report_size(ReportType type)
{
    size_t res = 0;
    for (auto generator : generators)
        res += generator->report_size(type);
    return res;
}

string MachineBase::tradeoff()
{
#ifdef LESS_ALLOC_MORE_MEM
    return " (computation over memory)";
#else
    return " (memory over computation)";
#endif
}

void MachineBase::mult_performance()
{
    int n = 1e7;
    bigint pr = 1;
    int bl = MAX_MOD_SZ > 5 ? 300 : (MAX_MOD_SZ) * 64 - 1;
    pr=(pr<<bl)+1;
    while (!probPrime(pr)) { pr=pr+2; }

    Zp_Data prM(pr,true);
    modp a,b;
    PRNG G;
    G.ReSeed();
    a.randomize(G, prM);
    b.randomize(G, prM);

    Timer timer;
    timer.start();
    for (int i = 0; i < 1e7; i++)
        Mul(a, a, b, prM);
    cout << bl << "-bit Montgomery multiplication performance: "
            << n / timer.elapsed() << endl;
}
