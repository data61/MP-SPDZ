/*
 * ReplicatedFieldMachine.hpp
 *
 */

#ifndef PROCESSOR_FIELDMACHINE_HPP_
#define PROCESSOR_FIELDMACHINE_HPP_

#include "FieldMachine.h"
#include "HonestMajorityMachine.h"
#include "Math/gfp.h"
#include "OnlineMachine.hpp"
#include "OnlineOptions.hpp"

template<template<class U> class T, class V>
HonestMajorityFieldMachine<T, V>::HonestMajorityFieldMachine(int argc,
        const char **argv)
{
    ez::ezOptionParser opt;
    HonestMajorityFieldMachine<T>(argc, argv, opt);
}

template<template<class U> class T, class V>
HonestMajorityFieldMachine<T, V>::HonestMajorityFieldMachine(int argc,
        const char **argv, ez::ezOptionParser& opt, int nplayers)
{
    OnlineOptions online_opts(opt, argc, argv, T<gfp0>());
    FieldMachine<T, T, V>(argc, argv, opt, online_opts,
            nplayers);
}

template<template<class U> class T, template<class U> class V, class W, class X>
FieldMachine<T, V, W, X>::FieldMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, OnlineOptions& online_opts, int nplayers)
{
    assert(nplayers or T<gfpvar>::variable_players);
    W machine(argc, argv, opt, online_opts, X(), nplayers);
    int n_limbs = online_opts.prime_limbs();
    cerr << "Trying to run " << online_opts.prime_length()
            << "-bit computation (" << n_limbs * 64 << "-bit representation)"
            << endl;
    switch (n_limbs)
    {
#undef X
#define X(L) \
    case L: \
        machine.template run<T<gfp_<0, L>>, V<X>>(); \
        break;
#ifndef FEWER_PRIMES
    X(1) X(2) X(3) X(4)
#endif
#if GFP_MOD_SZ > 4 or defined(FEWER_PRIMES)
    X(GFP_MOD_SZ)
#endif
#undef X
    default:
        cerr << "Not compiled for " << online_opts.prime_length() << "-bit primes" << endl;
        cerr << "Put 'MOD = -DGFP_MOD_SZ=" << n_limbs
                << "' in CONFIG.mine and run " << "'make " << argv[0] << "'"
                << endl;
        exit(1);
    }
}

#endif /* PROCESSOR_FIELDMACHINE_HPP_ */
