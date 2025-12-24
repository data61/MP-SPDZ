/*
 * NoiseBound.cpp
 *
 */

#include <FHE/NoiseBounds.h>
#include "FHEOffline/Proof.h"
#include "Protocols/CowGearOptions.h"
#include <math.h>

SemiHomomorphicNoiseBounds::SemiHomomorphicNoiseBounds(const bigint& p,
        int phi_m, int n, int sec, int slack_param, bool extra_h,
        const FHE_Params& params) :
        p(p), phi_m(phi_m), n(n), sec(sec),
        slack(numBits(Proof::slack(slack_param, sec, phi_m))),
        sigma(params.get_R())
{
    if (sigma <= 0)
        this->sigma = sigma = FHE_Params().get_R();
    if (extra_h)
    {
        sigma *= 1.4;
        params.set_R(params.get_R() * 1.4);
    }

    if (OnlineOptions::singleton.has_option("verbose_he_setup"))
        cerr << "Standard deviation: " << this->sigma << endl;

    produce_epsilon_constants();

    // according to documentation of SCALE-MAMBA 1.7
    // excluding a factor of n because we don't always add up n ciphertexts
    assert(phi_m != 0);
    V_s = sigma * sqrt(phi_m);
    B_clean = (bigint(phi_m) << (sec + 1)) * p
            * (20.5 + c1 * sigma * sqrt(phi_m) + 20 * c1 * V_s);
    // unify parameters by taking maximum over TopGear or not
    bigint B_clean_top_gear = B_clean * 2;
    bigint B_clean_not_top_gear = B_clean << max(slack - sec, 0);
    B_clean = max(B_clean_not_top_gear, B_clean_top_gear);
    B_scale = (c1 + c2 * V_s) * p * sqrt(phi_m / 12.0);
    int matrix_dim = params.get_matrix_dim();

    assert(matrix_dim > 0);
    assert(params.secp() >= 0);
    drown = 1 + (p > 2 ? matrix_dim : 1) * n * (bigint(1) << params.secp());

    if (OnlineOptions::singleton.has_option("verbose_he_setup"))
    {
        cerr << "phi(m): " << phi_m << endl;
        cerr << "p * sqrt(phi(m) / 12): " << p * sqrt(phi_m / 12.0) << endl;
        cerr << "V_s: " << V_s << endl;
        cerr << "c1: " << c1 << endl;
        cerr << "c2: " << c2 << endl;
        cerr << "c1 + c2 * V_s: " << c1 + c2 * V_s << endl;
        cerr << "log(slack): " << slack << endl;
        cerr << "B_clean bits: " << B_clean.numBits() << endl;
        cerr << "B_scale bits: " << B_scale.numBits() << endl;
        cerr << "matrix dimension: " << matrix_dim << endl;
        cerr << "drown sec: " << params.secp() << endl;
        cerr << "sec: " << sec << endl;
        cerr << "drown bits: " << drown.numBits() << endl;
    }
}

bigint SemiHomomorphicNoiseBounds::min_p0(const bigint& p1)
{
    return p * drown * n * B_clean / p1 + B_scale;
}

bigint SemiHomomorphicNoiseBounds::min_p0()
{
    // slack is already in B_clean
    return B_clean * drown * p;
}

double SemiHomomorphicNoiseBounds::min_phi_m(int log_q, double sigma)
{
    if (sigma <= 0)
        sigma = FHE_Params().get_R();
    // the constant was updated using Martin Albrecht's LWE estimator in Mar 2022
    // found the following pairs for 128-bit security
    // and alpha = 0.7 * sqrt(2*pi) / q
    // m = 2048, log_2(q) = 68
    // m = 4096, log_2(q) = 138
    // m = 8192, log_2(q) = 302
    // m = 16384, log_2(q) = 560
    return 15.1 * log_q;
}

double SemiHomomorphicNoiseBounds::min_phi_m(int log_q, const FHE_Params& params)
{
    return min_phi_m(log_q, params.get_R());
}

void SemiHomomorphicNoiseBounds::produce_epsilon_constants()
{
    double C[3];

    for (int i = 0; i < 3; i++)
    {
        C[i] = -1;
    }
    for (double x = 0.1; x < 10.0; x += .1)
    {
        double t = erfc(x), tp = 1;
        for (int i = 1; i < 3; i++)
        {
            tp *= t;
            double lgtp = log(tp) / log(2.0);
            if (C[i] < 0 && lgtp < -FHE_epsilon)
            {
                C[i] = pow(x, i);
            }
        }
    }

    c1 = C[1];
    c2 = C[2];
}

NoiseBounds::NoiseBounds(const bigint& p, int phi_m, int n, int sec, int slack,
        const FHE_Params& params) :
        SemiHomomorphicNoiseBounds(p, phi_m, n, sec, slack, sec, params)
{
    B_KS = p * c2 * this->sigma * phi_m / sqrt(12);
#ifdef NOISY
    cout << "p size: " << numBits(p) << endl;
    cout << "phi(m): " << phi_m << endl;
    cout << "n: " << n << endl;
    cout << "sec: " << sec << endl;
    cout << "sigma: " << this->sigma << endl;
    cout << "B_clean size: " << numBits(B_clean) << endl;
    cout << "B_scale size: " << numBits(B_scale) << endl;
    cout << "B_KS size: " << numBits(B_KS) << endl;
    cout << "drown size: " << numBits(drown) << endl;
#endif
}

bigint NoiseBounds::U1(const bigint& p0, const bigint& p1)
{
    bigint tmp = n * B_clean / p1 + B_scale;
    return tmp * tmp + B_KS * p0 / p1 + B_scale;
}

bigint NoiseBounds::U2(const bigint& p0, const bigint& p1)
{
    return U1(p0, p1) + n * B_clean / p1 + B_scale;
}

bigint NoiseBounds::min_p0(const bigint& p0, const bigint& p1)
{
    return 2 * U2(p0, p1) * drown;
}

bigint NoiseBounds::min_p0(const bigint& p1)
{
    bigint U = n * B_clean / p1 + 1 + B_scale;
    bigint res = 2 * (U * U + U + B_scale) * drown;
    mpf_class div = (1 - 1. * min_p1() / p1);
    res = ceil(res / div);
#ifdef NOISY
    cout << "U size: " << numBits(U) << endl;
    cout << "before div size: " << numBits(res) << endl;
    cout << "div: " << div << endl;
    cout << "minimal p0 size: " << numBits(res) << endl;
#endif
    return res;
}

bigint NoiseBounds::min_p1()
{
    return max(bigint(drown * B_KS), bigint((phi_m * p) << 10));
}

bigint NoiseBounds::opt_p1()
{
    assert(B_scale != 0);
    // square equation parameters
    bigint a, b, c;
    a = B_scale * B_scale + B_scale;
    b = -2 * a * min_p1();
    c = -n * B_clean * (2 * B_scale + 1) * min_p1() + n * n * B_scale * B_scale;
    // solve
    mpf_class s = (-b + sqrt(b * b - 4 * a * c)) / (2 * a);
    bigint res = ceil(s);
#ifdef VERBOSE
    cout << "Optimal p1 vs minimal: " << numBits(res) << "/"
            << numBits(min_p1()) << endl;
#endif
    return res;
}

double NoiseBounds::optimize(int& lg2p0, int& lg2p1)
{
    bigint min_p1 = opt_p1();
    bigint min_p0 = this->min_p0(min_p1);
    while (this->min_p0(min_p0, min_p1) > min_p0)
      {
        min_p0 *= 2;
        min_p1 *= 2;
#ifdef VERBOSE
        cout << "increasing lengths: " << numBits(min_p0) << "/"
            << numBits(min_p1) << endl;
#endif
      }
    lg2p1 = numBits(min_p1);
    lg2p0 = numBits(min_p0);
    return min_phi_m(lg2p0 + lg2p1, sigma.get_d());
}
