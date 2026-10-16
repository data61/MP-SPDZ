#ifndef _OTEXTENSION
#define _OTEXTENSION

#include "OT/BaseOT.h"

#include "Tools/Exceptions.h"

#include "Networking/Player.h"

#include "Tools/time-func.h"

#include <stdlib.h>
#include <assert.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>

using namespace std;

//#define OTEXT_TIMER
//#define OTEXT_DEBUG

class OTTripleSetup;

class OTExtension
{
public:
    map<string,long long> times;

    OTExtension(const BaseOT& baseOT, TwoPartyPlayer* player, bool passive);

    OTExtension(TwoPartyPlayer* player,
                OT_ROLE role=BOTH,
                bool passive=false)
        : passive_only(passive), nbaseOTs(-1),
          ot_role(role), player(player)
    {
    }

    void init(const OTTripleSetup& setup, int index);

    void init(const BitVector& baseReceiverInput,
            const vector< array<BitVector, 2> >& baseSenderInput,
            const vector<BitVector>& baseReceiverOutput)
    {
        nbaseOTs = baseReceiverInput.size();
        this->baseReceiverInput = baseReceiverInput;

        if (baseSenderInput.size() != baseReceiverOutput.size())
            throw runtime_error("mismatch in number of base OTs");
        assert(baseReceiverInput.size() == baseSenderInput.size());
        G_sender.resize(nbaseOTs, vector<PRNG>(2));
        G_receiver.resize(nbaseOTs);

        // set up PRGs for expanding the seed OTs
        for (int i = 0; i < nbaseOTs; i++)
        {
            assert(baseSenderInput.at(i).size() == 2);
            assert(baseSenderInput.at(i)[0].size_bytes() >= AES_BLK_SIZE);
            assert(baseSenderInput.at(i)[1].size_bytes() >= AES_BLK_SIZE);
            assert(baseReceiverOutput.at(i).size_bytes() >= AES_BLK_SIZE);

            if (ot_role & RECEIVER)
            {
                if (baseSenderInput[i][0].get_int128(0) == baseSenderInput[i][1].get_int128(0))
                    throw runtime_error("base sender outputs are the same");
                G_sender[i][0].SetSeed(baseSenderInput[i][0].get_ptr());
                G_sender[i][1].SetSeed(baseSenderInput[i][1].get_ptr());
            }
            if (ot_role & SENDER)
            {
                G_receiver[i].SetSeed(baseReceiverOutput[i].get_ptr());
            }

#ifdef OTEXT_DEBUG
            // sanity check for base OTs
            vector<octetStream> os(2);
            BitVector t0(128);

            if (ot_role & RECEIVER)
            {
                // send both inputs to test
                baseSenderInput[i][0].pack(os[0]);
                baseSenderInput[i][1].pack(os[0]);
            }
            send_if_ot_receiver(player, os, ot_role);

            if (ot_role & SENDER)
            {
                // sender checks results
                t0.unpack(os[1]);
                if (baseReceiverInput.get_bit(i) == 1)
                    t0.unpack(os[1]);
                if (!t0.equals(baseReceiverOutput[i]))
                {
                    cerr << "Incorrect base OT\n";
                    exit(1);
                }
            }
            

            os[0].reset_write_head();
            os[1].reset_write_head();
#endif
        }
    }

    void set_role(OT_ROLE role) { ot_role = role; }

protected:
    BitVector baseReceiverInput;
    bool passive_only;
    int nbaseOTs;
    OT_ROLE ot_role;
    TwoPartyPlayer* player;
    vector< vector<PRNG> > G_sender;
    vector<PRNG> G_receiver;
};

#endif
