/*
 * ShareInterface.h
 *
 */

#ifndef PROTOCOLS_SHAREINTERFACE_H_
#define PROTOCOLS_SHAREINTERFACE_H_

#include <vector>
#include <string>
#include <stdexcept>
using namespace std;

#include "Tools/Exceptions.h"

class Player;
class Instruction;
class ValueInterface;

template<class T> class StackedVector;

namespace GC
{
class NoShare;
class NoValue;
}

class ShareInterface
{
public:
    typedef GC::NoShare part_type;
    typedef GC::NoShare bit_type;

    typedef GC::NoValue mac_key_type;
    typedef GC::NoShare mac_type;
    typedef GC::NoShare mac_share_type;

    typedef void DefaultMC;

    static const bool needs_ot = false;
    static const bool expensive = false;
    static const bool expensive_triples = false;

    static const bool has_trunc_pr = false;
    static const bool has_split = false;
    static const bool has_mac = false;
    static const bool malicious = false;

    static const false_type triple_matmul;

    const static bool symmetric = true;

    static const bool is_real = true;

    static const bool randoms_for_opens = false;

    static const bool function_dependent = false;

    static const int bit_generation_threshold = 0;

    static const int default_length = 1;

    static const bool semi_honest_option = false;

    static string type_short() { throw runtime_error("shorthand undefined"); }

    static string alt() { return ""; }

    static bool real_shares(const Player&) { return true; }

    template<class T, class U>
    static void split(StackedVector<U>&, vector<int>, int, T*, int,
            typename U::Protocol&)
    { throw runtime_error("split not implemented"); }

    template<class T>
    static void shrsi(T&, const Instruction&)
    { throw runtime_error("shrsi not implemented"); }

    static bool get_rec_factor(int, int) { return false; }

    template<class T>
    static void read_or_generate_mac_key(const string&, const Player&, T&) {}

    template<class T, class U>
    static void generate_mac_key(T&, U&) {}

    static GC::NoValue get_mac_key();
    static void set_mac_key(GC::NoValue);

    static int threshold(int) { throw runtime_error("undefined threshold"); }

    template<class T>
    static string proto_fake_opts() { return T::fake_opts(); }
};

#endif /* PROTOCOLS_SHAREINTERFACE_H_ */
