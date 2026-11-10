/*
 * fake-spdz-ecdsa-party.cpp
 *
 */

#define NO_MIXED_CIRCUITS

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "GC/VectorInput.h"
#include "Protocols/SPDZ.h"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/Hemi.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Protocols/MascotPrep.hpp"
#include "GC/Secret.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"
#include "OT/NPartyTripleGenerator.hpp"

#include <assert.h>

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    EcdsaOptions opts(opt, argc, argv);
    Names N(opt, argc, argv, 2);
    int n_tuples = 1000;
    if (not opt.lastArgs.empty())
        n_tuples = atoi(opt.lastArgs[0]->c_str());
    CryptoPlayer P(N, "ecdsa");
    P256Element::init();

    P256Element::Scalar keyp;
    typedef Share<P256Element::Scalar> pShare;
    string prefix = get_prep_sub_dir<pShare>(PREP_DIR "ECDSA/", 2);
    read_mac_key(prefix, N, keyp);
    pShare::set_mac_key(keyp);

    pShare::MAC_Check::setup(P);
    Share<P256Element>::MAC_Check::setup(P);

    DataPositions usage;
    Sub_Data_Files<pShare> prep(N, prefix, usage);
    typename pShare::Direct_MC MCp(keyp);
    ArithmeticProcessor _({}, 0);
    SubProcessor<pShare> proc(_, MCp, prep, P);

    pShare sk, __;
    proc.DataF.get_two(DATA_INVERSE, sk, __);

    vector<EcTuple<Share>> tuples;
    preprocessing(tuples, n_tuples, sk, proc, opts);
    check(tuples, sk, keyp, P);
    sign_benchmark(tuples, sk, MCp, P, opts);

    pShare::MAC_Check::teardown();
    Share<P256Element>::MAC_Check::teardown();
    P256Element::finish();
}
