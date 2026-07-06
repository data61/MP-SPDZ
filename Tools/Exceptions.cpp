/*
 * Exceptions.cpp
 *
 */

#include "Exceptions.h"
#include "Math/bigint.h"
#include "Processor/OnlineOptions.h"

void exit_error(const string& message)
{
    if (OnlineOptions::singleton.has_option("throw_exceptions"))
        throw runtime_error(message);

    cerr << message << endl;
    exit(1);
}

IO_Error::IO_Error(const string& m) :
        ans(m)
{
}

file_error::file_error(const string& m) :
        ans(m)
{
}

Processor_Error::Processor_Error(const string& m) :
        msg(m)
{
}

Processor_Error::Processor_Error(const char* m) :
        Processor_Error(string(m))
{
}

wrong_gfp_size::wrong_gfp_size(const char* name, const bigint& p,
        const char* symbol, int n_limbs) :
        runtime_error(
                string() + name + " wrong size for modulus " + to_string(p)
                        + ". Maybe change " + symbol + " to "
                        + to_string(n_limbs) + ".")
{
}

overflow::overflow(const string& name, size_t i, size_t n) :
    runtime_error(
        name + " overflow: " + to_string(long(i)) + "/" + to_string(n)
            + ((long(i) < 0) ? ". A negative value indicates that "
                               "the computation modulus might be too small" :
                               ""))
{
}

unknown_input_type::unknown_input_type(int type) :
        runtime_error("unkown type: " + to_string(type))
{
}

invalid_opcode::invalid_opcode(int opcode) :
        runtime_error("invalid opcode: " + to_string(opcode))
{
}

input_error::input_error(const char* name, const string& filename,
        istream& input_file, size_t input_counter)
{
    input_file.clear();
    string token;
    input_file >> token;
    msg += string() + "cannot read " + name + " from " + filename
            + ", problem with '" + token + "' after "
            + to_string(input_counter);
}

signature_mismatch::signature_mismatch(const string& filename, bool has_mac) :
        runtime_error("Signature in " + filename + " doesn't match protocol. " +
                "Maybe re-run preprocessing"
                        + (has_mac ? " or check for MAC mismatch" : ""))
{
}

insufficient_memory::insufficient_memory(size_t size, const string& type) :
        runtime_error(
                "program requires too much " + type + " memory: "
                        + to_string(size))
{
}

not_enough_to_buffer::not_enough_to_buffer(const string& type, const string& filename)  :
        runtime_error(
                "Not enough data available for buffer"
                        + (filename.empty() ? "" : (" in " + filename)) + ". "
                                "Maybe insufficient preprocessing" + type
                        + ".\nFor benchmarking, you can activate reusing data by "
                                "adding -DINSECURE to the compiler options.")
{
}

gf2n_not_supported::gf2n_not_supported(int n, string options) :
        runtime_error(
                "GF(2^" + to_string(n) + ") not supported"
                        + (options.empty() ? "" : ", options are " + options))
{
}

setup_error::setup_error(const string& error) :
        runtime_error(error)
{
}

prep_setup_error::prep_setup_error(const string& error, int nplayers,
        const string& fake_opts) :
        setup_error(
                "Something is wrong with the preprocessing data on disk: "
                        + error
                        + "\nHave you run the right program for generating it, "
                                "such as './Fake-Offline.x "
                        + to_string(nplayers) + " " + fake_opts + "'?")
{
}

insufficient_shares::insufficient_shares(int expected, int actual, exception& e) :
        runtime_error(
                "expected " + to_string(expected) + " shares but only got "
                        + to_string(actual) + " (" + e.what() + ")")
{
}

persistence_error::persistence_error(const string& error) :
        runtime_error(
                "Error while reading from persistence file. "
                "You need to write to it first. "
                "See https://mp-spdz.readthedocs.io/en/latest/io.html#persistence. "
                "Details: " + error)
{
}

bytecode_error::bytecode_error(const string& error) :
        runtime_error(error)
{
}

no_dynamic_memory::no_dynamic_memory() :
        runtime_error("this functionality is only implemented "
                "for online-only BMR, see "
                "https://github.com/data61/MP-SPDZ?tab=readme-ov-file#bmr-1")
{
}

field_too_small::field_too_small(int length, int security) :
        runtime_error(
                "Field too small (" + to_string(length)
                        + " bits) for chosen security (" + to_string(security)
                        + "). Increase size with -lgp or "
                        "decrease security with --security")
{
}

invalid_commitment::invalid_commitment(int player, const char* message) :
        runtime_error(
                "invalid commitment"
                        + (player < 0 ?
                                string() : " from party " + to_string(player))
                        + (message ? string(": ") + message : string()))
{
}
