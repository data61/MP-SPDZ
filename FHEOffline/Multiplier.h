/*
 * Multiplier.h
 *
 */

#ifndef FHEOFFLINE_MULTIPLIER_H_
#define FHEOFFLINE_MULTIPLIER_H_

#include "FHEOffline/SimpleEncCommit.h"
#include "FHE/AddableVector.h"
#include "Tools/MemoryUsage.h"
#include "OT/BaseOT.h"

template <class FD>
using PlaintextVector = AddableVector< Plaintext_<FD> >;

template <class FD>
class PairwiseGenerator;
class PairwiseMachine;

template <class FD>
class Multiplier
{
    PairwiseMachine& machine;
    OffsetPlayer P;
    int num_players, my_num;
    int key_index;
    map<string, Timer>& timers;

    // temporary
    Ciphertext C, mask;
    Plaintext_<FD> product_share;
    Random_Coins rc;

    size_t volatile_capacity;
    MemoryUsage memory_usage;

    octetStream o;

public:
    Multiplier(int offset, PairwiseGenerator<FD>& generator);
    Multiplier(int offset, PairwiseMachine& machine, Player& P,
            map<string, Timer>& timers);

    void multiply_and_add(Plaintext_<FD>& res, const Ciphertext& C,
            const Plaintext_<FD>& b);
    void multiply_and_add(Plaintext_<FD>& res, const Ciphertext& C,
            const Rq_Element& b, OT_ROLE role = BOTH);
    void add(Plaintext_<FD>& res, const Ciphertext& C, OT_ROLE role = BOTH,
            int n_summands = 1);
    void multiply_alpha_and_add(Plaintext_<FD>& res, const Rq_Element& b,
            OT_ROLE role = BOTH);
    int get_offset() { return P.get_offset(); }
    size_t report_size(ReportType type);
    void report_size(ReportType type, MemoryUsage& res);
    size_t report_volatile() { return volatile_capacity; }

    const vector<Ciphertext>& get_multiplicands(
            const vector<vector<Ciphertext>>& others_ct, const FHE_PK&);
};

#endif /* FHEOFFLINE_MULTIPLIER_H_ */
