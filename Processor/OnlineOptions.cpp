/*
 * OnlineOptions.cpp
 *
 */

#include "OnlineOptions.h"
#include "BaseMachine.h"
#include "Math/gfp.h"
#include "Math/gfpvar.h"
#include "Protocols/HemiOptions.h"
#include "Protocols/config.h"
#include "FHEOffline/config.h"

#include "Math/gfp.hpp"

#include <boost/filesystem.hpp>
#include <regex>

using namespace std;

OnlineOptions OnlineOptions::singleton;
HemiOptions HemiOptions::singleton;

OnlineOptions::OnlineOptions() : playerno(-1)
{
    interactive = false;
    lgp = gfp0::MAX_N_BITS;
    lg2 = 0;
    live_prep = true;
    batch_size = 1000;
    memtype = "empty";
    bits_from_squares = false;
    direct = false;
    bucket_size = 4;
    security_parameter = DEFAULT_SECURITY;
    use_security_parameter = false;
    cmd_private_input_file = "Player-Data/Input";
    cmd_private_output_file = "";
    file_prep_per_thread = false;
    trunc_error = DEFAULT_SECURITY;
    opening_sum = 0;
    max_broadcast = 0;
    receive_threads = false;
    code_locations = false;
    have_warned_about_comp_sec = false;
    semi_honest = false;
#ifdef VERBOSE
    verbose = true;
#else
    verbose = false;
#endif
}

OnlineOptions::OnlineOptions(ez::ezOptionParser& opt, int argc,
        const char** argv, bool security) :
        OnlineOptions()
{
    use_security_parameter = security;

    opt.syntax = std::string(argv[0]) + " [OPTIONS] [<playerno>] <progname>";

    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Interactive mode in the main thread (default: disabled)", // Help description.
          "-I", // Flag token.
          "--interactive" // Flag token.
    );
    opt.add(
          cmd_private_input_file.c_str(), // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Prefix for input file path (default: Player-Data/Input). "
          "Text input will be read from {prefix}-P{id}-{thread_id} and "
          "binary input from {prefix}-Binary-P{id}-{thread_id}", // Help description.
          "-IF", // Flag token.
          "--input-file" // Flag token.
    );
    opt.add(
          cmd_private_output_file.c_str(), // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Prefix for output file path "
          "(default: output to stdout for party 0 (silent otherwise "
          "unless interactive mode is active). "
          "Output will be written to {prefix}-P{id}-{thread_id}. "
          "Use '.' for stdout on all parties.", // Help description.
          "-OF", // Flag token.
          "--output-file" // Flag token.
    );
 
    opt.add(
            "", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "This player's number (required if not given before program name)", // Help description.
            "-p", // Flag token.
            "--player" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Verbose output, in particular more data on communication", // Help description.
            "-v", // Flag token.
            "--verbose" // Flag token.
    );
    opt.add(
            "4", // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Batch size for sacrifice (3-5, default: 4)", // Help description.
            "-B", // Flag token.
            "--bucket-size" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            -1, // Number of args expected.
            ',', // Delimiter if expecting multiple args.
            "Further options", // Help description.
            "-o", // Flag token.
            "--options" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            ',', // Delimiter if expecting multiple args.
            "Output code locations of the most relevant protocols used", // Help description.
            "--code-locations" // Flag token.
    );

    if (security)
        opt.add(
            to_string(security_parameter).c_str(), // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            ("Statistical security parameter (default: " + to_string(security_parameter)
                    + ")").c_str(), // Help description.
            "-S", // Flag token.
            "--security" // Flag token.
        );

    opt.parse(argc, argv);

    interactive = opt.isSet("-I");

    opt.get("-IF")->getString(cmd_private_input_file);
    opt.get("-OF")->getString(cmd_private_output_file);

    opt.get("--bucket-size")->getInt(bucket_size);

#ifndef VERBOSE
    verbose = opt.isSet("--verbose");
#endif

    opt.get("--options")->getStrings(options);

    for (auto& option : options)
        if (option.find("verbose") == 0)
            verbose = true;

    code_locations = opt.isSet("--code-locations");

#ifdef THROW_EXCEPTIONS
    options.push_back("throw_exceptions");
#endif

    if (security)
    {
        opt.get("-S")->getInt(security_parameter);
        if (security_parameter <= 0)
        {
            cerr << "Invalid security parameter: " << security_parameter << endl;
            exit(1);
        }
    }
    else
        security_parameter = 1000;

    opt.resetArgs();

    if (argc > 0)
        executable = boost::filesystem::path(argv[0]).filename().string();
}

OnlineOptions::OnlineOptions(ez::ezOptionParser& opt, int argc,
        const char** argv, int default_batch_size, bool default_live_prep,
        bool variable_prime_length, bool security) :
        OnlineOptions(opt, argc, argv, security)
{
    if (default_batch_size <= 0)
        default_batch_size = batch_size;

    string default_lgp = to_string(lgp);
    if (variable_prime_length)
    {
        opt.add(
                default_lgp.c_str(), // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                ("Bit length of GF(p) field (default: " + default_lgp + ")").c_str(), // Help description.
                "-lgp", // Flag token.
                "--lgp" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Prime for GF(p) field (default: read from file or "
                "generated from -lgp argument)", // Help description.
                "-P", // Flag token.
                "--prime" // Flag token.
        );
    }
    if (default_live_prep)
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Preprocessing from files", // Help description.
                "-F", // Flag token.
                "--file-preprocessing" // Flag token.
        );
    else
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Live preprocessing", // Help description.
                "-L", // Flag token.
                "--live-preprocessing" // Flag token.
        );

    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Preprocessing from files by thread (use with pipes)", // Help description.
            "-f", // Flag token.
            "--file-prep-per-thread" // Flag token.
    );

    opt.add(
            to_string(default_batch_size).c_str(), // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            ("Size of preprocessing batches (default: " + to_string(default_batch_size) + ")").c_str(), // Help description.
            "-b", // Flag token.
            "--batch-size" // Flag token.
    );
    opt.add(
            memtype.c_str(), // Default.
            0, // Required?
            1, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Where to obtain memory, old|empty (default: empty)\n\t"
            "old: reuse previous memory in Memory-<type>-P<i>\n\t"
            "empty: create new empty memory", // Help description.
            "-m", // Flag token.
            "--memory" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Compute random bits from squares", // Help description.
            "-Q", // Flag token.
            "--bits-from-squares" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Direct communication instead of star-shaped "
            "(only for dishonest-majority protocols)", // Help description.
            "-d", // Flag token.
            "--direct" // Flag token.
    );

    opt.parse(argc, argv);

    if (variable_prime_length)
    {
        opt.get("--lgp")->getInt(lgp);
        string p;
        opt.get("--prime")->getString(p);
        if (not p.empty())
            prime = bigint(p);
    }
    if (default_live_prep)
        live_prep = not opt.get("-F")->isSet;
    else
        live_prep = opt.get("-L")->isSet;
    if (opt.isSet("-f"))
    {
        live_prep = false;
        file_prep_per_thread = true;
    }
    opt.get("-b")->getInt(batch_size);
    opt.get("--memory")->getString(memtype);
    bits_from_squares = opt.isSet("-Q");

    direct = opt.isSet("--direct");

    opt.resetArgs();
}

void OnlineOptions::finalize(ez::ezOptionParser& opt, int argc,
        const char** argv, bool networking)
{
    opt.resetArgs();
    opt.parse(argc, argv);

    vector<string*> allArgs(opt.firstArgs);
    allArgs.insert(allArgs.end(), opt.unknownArgs.begin(), opt.unknownArgs.end());
    allArgs.insert(allArgs.end(), opt.lastArgs.begin(), opt.lastArgs.end());
    string usage;
    vector<string> badOptions;
    unsigned int i;

    if (networking)
        opt.footer += "See also "
                "https://mp-spdz.readthedocs.io/en/latest/networking.html "
                "for documentation on the networking setup.\n\n";

    size_t name_index = 1 + networking - opt.isSet("-p");

    if (allArgs.size() < name_index + 1)
    {
        opt.getUsage(usage);
        cout << usage;
        cerr << "ERROR: incorrect number of arguments to " << argv[0] << endl;
        cerr << "Arguments given were:\n";
        for (unsigned int j = 1; j < allArgs.size(); j++)
            cout << "'" << *allArgs[j] << "'" << endl;
        exit(1);
    }
    else
    {
        if (opt.isSet("-p"))
            opt.get("-p")->getInt(playerno);
        else
            sscanf((*allArgs[1]).c_str(), "%d", &playerno);
        progname = *allArgs.at(name_index);
    }

    if (!opt.gotRequired(badOptions))
    {
        opt.getUsage(usage);
        cout << usage;
        for (i = 0; i < badOptions.size(); ++i)
            cerr << "ERROR: Missing required option " << badOptions[i] << ".";
        exit(1);
    }

    if (!opt.gotExpected(badOptions))
    {
        opt.getUsage(usage);
        cout << usage;
        for (i = 0; i < badOptions.size(); ++i)
            cerr << "ERROR: Got unexpected number of arguments for option "
                    << badOptions[i] << ".";
        exit(1);
    }

    for (size_t i = name_index + 1; i < allArgs.size(); i++)
    {
        try
        {
            args.push_back(stol(*allArgs[i]));
        }
        catch (exception& e)
        {
            opt.getUsage(usage);
            cerr << usage;
            cerr << "Additional argument has to be integer: " << *allArgs[i]
                    << endl;
            exit(1);
        }
    }

    if (has_option("throw_exceptions"))
        finalize_with_error(opt);
    else
    {
        try
        {
            finalize_with_error(opt);
        }
        catch (exception& e)
        {
            cerr << "Fatal error in option processing: " << e.what() << endl;
            exit(1);
        }
    }
}

void OnlineOptions::finalize_with_error(ez::ezOptionParser& opt)
{
    if (opt.get("-lgp"))
    {
        bigint schedule_prime = BaseMachine::prime_from_schedule(progname);
        if (prime != 0 and prime != schedule_prime and schedule_prime != 0)
        {
            cerr << "Different prime for compilation and computation." << endl;
            cerr << "Run with '--prime " << schedule_prime
                    << "' or compile with '--prime " << prime << "'." << endl;
            exit(1);
        }
        if (schedule_prime != 0)
            prime = schedule_prime;
    }

    // ignore program if length explicitly set from command line
    if (opt.get("-lgp") and not opt.isSet("-lgp"))
    {
        int prog_lgp = BaseMachine::prime_length_from_schedule(progname);
        prog_lgp = DIV_CEIL(prog_lgp, 64) * 64;
        // only increase to be consistent with program not demanding any length
        if (prog_lgp > lgp)
            lgp = prog_lgp;
    }

    if (opt.get("--lg2"))
        opt.get("--lg2")->getInt(lg2);

    int prog_lg2 = BaseMachine::gf2n_length_from_schedule(progname);
    if (prog_lg2)
    {
        if (prog_lg2 != lg2 and opt.isSet("lg2"))
        {
            cerr << "GF(2^n) mismatch between command line and program" << endl;
            exit(1);
        }

        if (verbose)
            cerr << "Using GF(2^" << prog_lg2 << ") as requested by program" << endl;
        lg2 = prog_lg2;
    }

    set_trunc_error(opt);

    auto o = opt.get("--opening-sum");
    if (o)
        o->getInt(opening_sum);

    o = opt.get("--max-broadcast");
    if (o)
        o->getInt(max_broadcast);

    o = opt.get("--disk-memory");
    if (o)
        o->getString(disk_memory);

    receive_threads = opt.isSet("--threads");
    semi_honest = opt.isSet("--semi-honest");

    if (use_security_parameter)
    {
        int program_sec = BaseMachine::security_from_schedule(progname);

        if (program_sec > 0)
        {
            if (not opt.isSet("-S"))
                security_parameter = program_sec;
            if (program_sec < security_parameter)
            {
                cerr << "Security parameter used in compilation is insufficient" << endl;
                exit(1);
            }
        }

        cerr << "Using statistical security parameter " << security_parameter << endl;
    }
}

void OnlineOptions::set_trunc_error(ez::ezOptionParser& opt)
{
    if (opt.get("-E"))
    {
        opt.get("-E")->getInt(trunc_error);
        if (verbose)
            cerr << "Truncation error probability 2^-" << trunc_error << endl;
    }
}

int OnlineOptions::prime_length()
{
    if (prime == 0)
        return lgp;
    else
        return prime.numBits();
}

int OnlineOptions::prime_limbs()
{
    return DIV_CEIL(prime_length(), 64);
}

bool OnlineOptions::has_param(const string& param)
{
    for (auto& x : options)
        if (x.find(param + "=") == 0)
            return true;
    return false;
}

int OnlineOptions::get_param(const string& param)
{
    basic_regex re(param + "=([0-9]+)");
    smatch match;
    for (auto& x : options)
        if (regex_match(x, match, re))
            return atoi(match[1].str().c_str());
    throw runtime_error("parameter not found: " + param);
}

int OnlineOptions::comp_sec()
{
    int res = COMP_SEC;
    if (has_param("comp_sec"))
        res = get_param("comp_sec");
    if (res < 128 and not have_warned_about_comp_sec)
    {
        cerr << "WARNING: computational security parameter " << res
                << " suitable for testing only" << endl;
        have_warned_about_comp_sec = true;
    }
    return res;
}
