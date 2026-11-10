/*
 * ReplicatedMachine.cpp
 *
 */

#include "HonestMajorityMachine.h"

#include "Tools/ezOptionParser.h"
#include "Tools/benchmarking.h"
#include "Tools/NetworkOptions.h"
#include "Networking/Server.h"
#include "Protocols/Rep3Share.h"
#include "Processor/Machine.h"

#include "OnlineMachine.hpp"

HonestMajorityMachine::HonestMajorityMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, OnlineOptions& online_opts, int nplayers) :
        OnlineMachine(argc, argv, opt, online_opts, nplayers)
{
    online_opts.finalize(opt, argc, argv);
    OnlineOptions::singleton = online_opts;

    start_networking();
}
