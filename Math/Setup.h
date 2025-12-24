/*
 * Setup.h
 *
 */

#ifndef MATH_SETUP_H_
#define MATH_SETUP_H_

#include "Math/bigint.h"
#include "Tools/mkpath.h"

#include <iostream>
#include <fstream>
using namespace std;

#ifndef PREP_DIR
#define PREP_DIR "Player-Data/"
#endif

/*
 * Routines to create and read setup files for the finite fields
 */

// Create setup file for gfp and gf2n
template<class T>
void generate_prime_setup(string dir, int lgp);
template<class T>
void generate_online_setup(string dirname, bigint& p, int lgp);

// Setup primes only
// Chooses a p of at least lgp bits
bigint SPDZ_Data_Setup_Primes(int lgp);
void SPDZ_Data_Setup_Primes(bigint& p,int lgp,int& idx,int& m);
void generate_prime(bigint& p, int lgp, int m, bool force_degree = false);
bigint generate_prime(int lgp, int m, bool force_degree = false);
int default_m(int& lgp, int& idx);

string get_prep_sub_dir(const string& prep_dir, int nparties, int log2mod,
        const string& type_short, bool create = false);

template<class T>
string get_prep_sub_dir(const string& prep_dir, int nparties, int log2mod,
        bool create = false)
{
    if (T::clear::length() > 1)
        log2mod = T::clear::length();
    return get_prep_sub_dir(prep_dir, nparties, log2mod, T::type_short(), create);
}

template<class T>
string get_prep_sub_dir(const string& prep_dir, int nparties, bool create =
        false)
{
    return get_prep_sub_dir<T>(prep_dir, nparties, T::clear::length(), create);
}

template<class T>
string get_prep_sub_dir(int nparties, bool create = false)
{
    return get_prep_sub_dir<T>(PREP_DIR, nparties, create);
}

template<class T>
void generate_prime_setup(string dir, int nparties, int lgp)
{
    bigint p;
    generate_online_setup<typename T::clear>(
            get_prep_sub_dir<T>(dir, nparties, lgp), p, lgp);
}

#endif /* MATH_SETUP_H_ */
