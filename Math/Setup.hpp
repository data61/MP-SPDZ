/*
 * Setup.hpp
 *
 */

#ifndef MATH_SETUP_HPP_
#define MATH_SETUP_HPP_

#include "gfp.h"

template<class T>
void generate_online_setup(string dirname, bigint& p, int lgp)
{
    int idx, m;
    SPDZ_Data_Setup_Primes(p, lgp, idx, m);
    T::init_field(p);
    T::write_setup(dirname);
}

template<class T = gfp>
void read_setup(const string& dir_prefix, int lgp = -1)
{
    bigint p;
    bool montgomery = true;

    string filename = dir_prefix + "Params-Data";

    if (dir_prefix.compare("") == 0)
        filename = string(PREP_DIR "Params-Data");

#ifdef DEBUG_FILES
  cerr << "loading params from: " << filename << endl;
#endif
    ifstream inpf(filename.c_str());
    inpf >> p;
    inpf >> montgomery;

    if (inpf.fail())
    {
        if (lgp > 0)
        {
            if (OnlineOptions::singleton.verbose)
                cerr << "No modulus found in " << filename << ", generating "
                        << lgp << "-bit prime" << endl;
            T::init_default(lgp);
        }
        else
            throw file_error(filename.c_str());
    }
    else
        T::init_field(p, montgomery);

    inpf.close();

    if (OnlineOptions::singleton.verbose)
        cerr << "Using prime modulus " << T::pr() << endl;
}

#endif /* MATH_SETUP_HPP_ */
