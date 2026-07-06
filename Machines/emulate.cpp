/*
 * emulate.cpp
 *
 */

#include "Protocols/FakeShare.h"
#include "Processor/Machine.h"
#include "Math/Z2k.h"
#include "Math/gf2n.h"
#include "Processor/RingOptions.h"

#include "Processor/Machine.hpp"
#include "Processor/OnlineOptions.hpp"
#include "Math/Z2k.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/ShuffleSacrifice.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/FakeShare.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "Protocols/MAC_Check_Base.hpp"

int main(int argc, const char** argv)
{
    OnlineOptions& online_opts = OnlineOptions::singleton;
    Names N;
    ez::ezOptionParser opt;
    RingOptions ring_opts(opt, argc, argv);
    online_opts = {opt, argc, argv, FakeShare<SignedZ2<64>>()};
    opt.syntax = string(argv[0]) + " <progname>";
    online_opts.finalize(opt, argc, argv, false);
    string& progname = online_opts.progname;

#ifdef ROUND_NEAREST_IN_EMULATION
    cerr << "Using nearest rounding instead of probabilistic truncation" << endl;
#endif

    int R = ring_opts.ring_size_from_opts_or_schedule(progname);

#define X(L) \
    if (L == R) \
    { \
        Machine<FakeShare<SignedZ2<L>>, FakeShare<gf2n>>( \
                N, false, online_opts).run(progname); \
        return 0; \
    }

    X(64)
#ifndef FEWER_RINGS
    X(32) X(128) X(256) X(192) X(384) X(512)
#endif
#ifdef RING_SIZE
    X(RING_SIZE)
#endif
#undef X
    cerr << "Not compiled for " << R << "-bit rings" << endl;
    return 1;
}
