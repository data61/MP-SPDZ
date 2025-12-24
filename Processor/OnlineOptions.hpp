/*
 * OnlineOptions.hpp
 *
 */

#ifndef PROCESSOR_ONLINEOPTIONS_HPP_
#define PROCESSOR_ONLINEOPTIONS_HPP_

#include "OnlineOptions.h"

template<class T, class V>
OnlineOptions::OnlineOptions(ez::ezOptionParser& opt, int argc,
        const char** argv, T, bool default_live_prep, V) :
        OnlineOptions(opt, argc, argv, OnlineOptions(T()).batch_size,
                default_live_prep, T::clear::prime_field,
                T::LivePrep::homomorphic or T::malicious)
{
    if (T::has_trunc_pr)
        opt.add(
                to_string(trunc_error).c_str(), // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                ("Probabilistic truncation error (2^-x, default: "
                        + to_string(trunc_error) + ")").c_str(), // Help description.
                "-E", // Flag token.
                "--trunc-error" // Flag token.
        );

    if (T::dishonest_majority)
    {
        opt.add(
              "0", // Default.
              0, // Required?
              1, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              "Sum at most n shares at once when using indirect communication", // Help description.
              "-s", // Flag token.
              "--opening-sum" // Flag token.
        );
        opt.add(
              "", // Default.
              0, // Required?
              0, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              "Use player-specific threads for communication", // Help description.
              "-t", // Flag token.
              "--threads" // Flag token.
        );
        opt.add(
              "0", // Default.
              0, // Required?
              1, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              "Maximum number of parties to send to at once", // Help description.
              "-mb", // Flag token.
              "--max-broadcast" // Flag token.
        );
    }

    if (not T::clear::binary)
    {
        opt.add(
              "", // Default.
              0, // Required?
              1, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              "Use directory on disk for memory (container data structures) "
              "instead of RAM", // Help description.
              "-D", // Flag token.
              "--disk-memory" // Flag token.
        );

        opt.add(
              to_string(V::default_degree()).c_str(), // Default.
              0, // Required?
              1, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              ("Bit length of GF(2^n) field (default: "
                      + to_string(V::default_degree()) + "; options are "
                      + V::options() + ")").c_str(), // Help description.
              "-lg2", // Flag token.
              "--lg2" // Flag token.
        );
    }

    if (T::variable_players)
        opt.add(
              T::dishonest_majority ? "2" : "3", // Default.
              0, // Required?
              1, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              ("Number of players (default: "
                      + (T::dishonest_majority ?
                              to_string("2") : to_string("3")) + "). " +
              "Ignored if external server is used.").c_str(), // Help description.
              "-N", // Flag token.
              "--nparties" // Flag token.
        );

    if (T::semi_honest_option)
        opt.add(
              "", // Default.
              0, // Required?
              0, // Number of args expected.
              0, // Delimiter if expecting multiple args.
              "Semi-honest operation (default: malicious security)"
              // Help description.
              "-sh", // Flag token.
              "--semi-honest" // Flag token.
        );
}

template<class T>
OnlineOptions::OnlineOptions(T) : OnlineOptions()
{
    if (not T::dishonest_majority)
        batch_size = 10000;
}

#endif /* PROCESSOR_ONLINEOPTIONS_HPP_ */
