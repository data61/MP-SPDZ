/*
 * TemiSetup.h
 *
 */

#ifndef FHEOFFLINE_TEMISETUP_H_
#define FHEOFFLINE_TEMISETUP_H_

#include "FHE/FHE_Keys.h"
#include "FHEOffline/SimpleMachine.h"

template<class FD>
class TemiSetup : public PartSetup<FD>
{
public:
    static string name()
    {
        return "TemiParams";
    }

    static string protocol_name(int)
    {
        return "Temi";
    }

    TemiSetup();

    void secure_init(Player& P, MachineBase&, int plaintext_length, int, bool);
    void generate(Player& P, MachineBase&, int plaintext_length, int sec);

    void key_and_mac_generation(Player& P, MachineBase&, int, true_type);
};

#endif /* FHEOFFLINE_TEMISETUP_H_ */
