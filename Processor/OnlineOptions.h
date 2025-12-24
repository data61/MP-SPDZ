/*
 * OnlineOptions.h
 *
 */

#ifndef PROCESSOR_ONLINEOPTIONS_H_
#define PROCESSOR_ONLINEOPTIONS_H_

#include "Tools/ezOptionParser.h"
#include "Math/bigint.h"
#include "Math/Setup.h"
#include "Math/gf2n.h"

class OnlineOptions
{
    void finalize_with_error(ez::ezOptionParser& opt);

    bool have_warned_about_comp_sec;

public:
    static OnlineOptions singleton;

    bool interactive;
    int lgp;
    int lg2;
    bigint prime;
    bool live_prep;
    int playerno;
    std::string progname;
    int batch_size;
    std::string memtype;
    bool bits_from_squares;
    bool direct;
    int bucket_size;
    int security_parameter;
    bool use_security_parameter;
    std::string cmd_private_input_file;
    std::string cmd_private_output_file;
    bool verbose;
    bool file_prep_per_thread;
    int trunc_error;
    int opening_sum, max_broadcast;
    bool receive_threads;
    std::string disk_memory;
    vector<long> args;
    vector<string> options;
    string executable;
    bool code_locations;
    bool semi_honest;

    OnlineOptions();
    OnlineOptions(ez::ezOptionParser& opt, int argc, const char** argv,
            bool security);
    OnlineOptions(ez::ezOptionParser& opt, int argc, const char** argv,
            int default_batch_size = 0, bool default_live_prep = true,
            bool variable_prime_length = false, bool security = true);
    template<class T, class V = gf2n>
    OnlineOptions(ez::ezOptionParser& opt, int argc, const char** argv, T,
            bool default_live_prep = true, V = {});
    template<class T>
    OnlineOptions(T);
    ~OnlineOptions() {}

    void finalize(ez::ezOptionParser& opt, int argc, const char** argv,
            bool networking = true);

    void set_trunc_error(ez::ezOptionParser& opt);

    int prime_length();
    int prime_limbs();

    template<class T>
    string prep_dir_prefix(int nplayers)
    {
        int lgp = this->lgp;
        if (prime)
            lgp = numBits(prime);
        return get_prep_sub_dir<T>(PREP_DIR, nplayers, lgp);
    }

    bool has_option(const string& option)
    {
        return find(options.begin(), options.end(), option) != options.end();
    }

    bool has_param(const string& param);
    int get_param(const string& param);

    int comp_sec();
};

#endif /* PROCESSOR_ONLINEOPTIONS_H_ */
