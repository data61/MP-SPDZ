/*
 * Fake-ECDSA.cpp
 *
 */

#include "ECDSA/P256Element.h"
#include "Tools/mkpath.h"
#include "GC/TinierSecret.h"

#include "Protocols/fake-stuff.hpp"
#include "Protocols/Share.hpp"
#include "Processor/Data_Files.hpp"
#include "Math/gfp.hpp"

int main()
{
    P256Element::init();
    KeySetup<Share<P256Element::Scalar>> key;
    string prefix = PREP_DIR "ECDSA/";
    mkdir_p(prefix.c_str());
    P256Element::Scalar::write_setup(prefix);
    PRNG G;
    G.ReSeed();
    generate_mac_keys<Share<P256Element::Scalar>>(key, 2, prefix, G);
    make_mult_triples<Share<P256Element::Scalar>>(key, 2, 1000, false, prefix, G);
    make_inverse<Share<P256Element::Scalar>>(key, 2, 1000, false, prefix, G);
    P256Element::finish();
}
