/*
 * mama-party.cpp
 *
 */

#include "Protocols/MamaShare.h"

#include "Protocols/MamaPrep.hpp"
#include "Protocols/MascotPrep.hpp"
#include "Processor/FieldMachine.hpp"
#include "SPDZ.hpp"
#include "Math/gfp.hpp"

template<int L, int N_MACS>
int run(OnlineMachine& machine)
{
    return machine.run<MamaShare<gfp_<0, L>, N_MACS>, MamaShare<gf2n, N_MACS>>();
}

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    OnlineOptions& online_opts = OnlineOptions::singleton;
    online_opts = {opt, argc, argv, MamaShare<gfp_<0, 1>, 3>()};
    DishonestMajorityMachine machine(argc, argv, opt, online_opts, 0);
    int length = min(online_opts.prime_length() - 1, machine.get_lg2());
    int n_macs = DIV_CEIL(online_opts.security_parameter, length);
    n_macs = 1 << int(ceil(log2(n_macs)));
    if (n_macs > 4)
        n_macs = 10;

    if (online_opts.prime_limbs() == 1)
    {
#define X(N) if (n_macs == N) return run<1, N>(machine);
        X(1) X(2) X(4) X(10)
    }

    if (online_opts.prime_limbs() == 2)
        return run<2, 1>(machine);

    if (online_opts.prime_limbs() > 2)
        cerr << "Use MASCOT with large primes" << endl;
    else
        cerr << "Not compiled for choice of parameters" << endl;

    exit(1);
}
