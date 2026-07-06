/*
 * PairwiseSetup.h
 *
 */

#ifndef FHEOFFLINE_PAIRWISESETUP_H_
#define FHEOFFLINE_PAIRWISESETUP_H_

#include "FHE/FHE_Params.h"
#include "FHE/Plaintext.h"
#include "Networking/Player.h"

class PairwiseMachine;
class MachineBase;

template <class T, class U>
void secure_init(T& setup, Player& P, U& machine,
        int plaintext_length, int sec,
        FHE_Params& params, bool read_only = false);

template <class FD>
class PairwiseSetup
{
public:
    typedef typename FD::T T;

    FHE_Params params;
    FD FieldD;
    typename FD::T alphai;
    Plaintext_<FD> alpha;

    static string name()
    {
        return "PairwiseParams-" + FD::T::type_string();
    }

    static string protocol_name(bool covert)
    {
        if (covert)
            return "CowGear";
        else
            return "LowGear";
    }

    PairwiseSetup() : params(0), alpha(FieldD) {}
   
    void init(const Player& P, int sec, int plaintext_length, int& extra_slack);

    void secure_init(Player& P, PairwiseMachine& machine, int plaintext_length,
            int sec, bool read_only = false);
    void generate(Player& P, MachineBase& machine, int plaintext_length, int sec);
    void check(Player& P, PairwiseMachine& machine);
    void covert_key_generation(Player& P, PairwiseMachine& machine, int num_runs);
    void covert_mac_generation(Player& P, PairwiseMachine& machine, int num_runs);

    void key_and_mac_generation(Player& P, PairwiseMachine& machine,
            int num_runs, false_type);
    void key_and_mac_generation(Player& P, PairwiseMachine& machine,
            int num_runs, true_type);

    void pack(octetStream& os) const;
    void unpack(octetStream& os);

    void set_alphai(T alphai);
};

#endif /* FHEOFFLINE_PAIRWISESETUP_H_ */
