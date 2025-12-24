/*
 * ReplicatedRingMachine.hpp
 *
 */

#ifndef PROCESSOR_RINGMACHINE_HPP_
#define PROCESSOR_RINGMACHINE_HPP_

#include "RingMachine.h"
#include "HonestMajorityMachine.h"
#include "Processor/RingOptions.h"
#include "Tools/ezOptionParser.h"
#include "Math/gf2n.h"
#include "Protocols/Spdz2kPrep.h"
#include "OnlineMachine.hpp"
#include "OnlineOptions.hpp"


template<template<int L> class U, template<class T> class V>
HonestMajorityRingMachine<U, V>::HonestMajorityRingMachine(int argc, const char** argv, int nplayers)
{
    ez::ezOptionParser opt;
    HonestMajorityRingMachine<U, V>(argc, argv, opt, nplayers);
}

template<template<int L> class U, template<class T> class V>
HonestMajorityRingMachine<U, V>::HonestMajorityRingMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, int nplayers)
{
    OnlineOptions online_opts(opt, argc, argv, U<64>());
    RingMachine<U, V, HonestMajorityMachine>(argc, argv, opt, online_opts, nplayers);
}

inline void ring_domain_error(int R, int max)
{
    cerr << "The virtual machine is not compiled for " << R
            << "-bit computation." << endl;
    cerr << "Compile with 'MY_CFLAGS += -DRING_SIZE=" << R
            << "' in 'CONFIG.mine'";
    (void) max;
#ifndef FEWER_RINGS
    for (int r = 0; r <= max; r += 64)
    {
        if (r >= R)
        {
            cerr << " or try " << "'-R " << r << "'";
            break;
        }
    }
#endif
    cerr << "." << endl;
    exit(1);
}

template<template<int L> class U, template<class T> class V, class W>
RingMachine<U, V, W>::RingMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, OnlineOptions& online_opts, int nplayers)
{
    assert(nplayers or U<64>::variable_players);
    RingOptions opts(opt, argc, argv);
    W machine(argc, argv, opt, online_opts, gf2n(), nplayers);
    int R = opts.ring_size_from_opts_or_schedule(online_opts.progname);
#define X(L) \
    if (R == L) \
    { \
        machine.template run<U<L>, V<gf2n>>(); \
        return; \
    }
    X(64)
#ifndef FEWER_RINGS
    X(72) X(128) X(192)
#endif
#ifdef RING_SIZE
    X(RING_SIZE)
#endif
#undef X
    ring_domain_error(R, 192);
}

template<template<int K, int S> class U, template<class T> class V>
HonestMajorityRingMachineWithSecurity<U, V>::HonestMajorityRingMachineWithSecurity(
        int argc, const char** argv, ez::ezOptionParser& opt)
{
    OnlineOptions online_opts(opt, argc, argv, U<64, 40>());
    RingOptions opts(opt, argc, argv);
    HonestMajorityMachine machine(argc, argv, opt, online_opts);
    int R = opts.ring_size_from_opts_or_schedule(online_opts.progname);
#define Y(K, S) \
    case S: \
        machine.run<U<K, S>, V<gf2n>>(); \
        break;
#define X(K) \
    if (R == K) \
    { \
        int S = online_opts.security_parameter; \
        switch (S) \
        { \
        Y(K, DEFAULT_SECURITY) \
        default: \
            cerr << "not compiled for security parameter " << to_string(S) << endl; \
            cerr << "add 'Y(K, " << S << ")' to " __FILE__ ", line 76" << endl; \
            cerr << "or compile with -DDEFAULT_SECURITY=" << S << endl; \
            exit(1); \
        } \
        return; \
    }
    X(64)
#ifdef RING_SIZE
    X(RING_SIZE)
#endif
#ifndef FEWER_RINGS
    X(72) X(128)
#endif
#undef X
    ring_domain_error(R, 128);
}

#endif /* PROCESSOR_RINGMACHINE_HPP_ */
