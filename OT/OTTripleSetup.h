#ifndef OT_TRIPLESETUP_H_
#define OT_TRIPLESETUP_H_

#include "Networking/Player.h"
#include "OT/BaseOT.h"
#include "Tools/random.h"
#include "Tools/time-func.h"

#include <map>

/*
 * Class for creating and storing base OTs between every pair of parties.
 */
class OTTripleSetup
{
    typedef vector< array<BitVector, 2> > sender_type;
    typedef vector<BitVector> receiver_type;

    void run(int i);

    vector<BaseOT*> baseOTs;

    PRNG G;
    int nparties;
    int my_num;

public:
    class SetupJob
    {
        OTTripleSetup& setup;
        int i;

    public:
        pthread_t thread;

        SetupJob(OTTripleSetup& setup, int i) :
                setup(setup), i(i), thread(0)
        {
        }

        void run()
        {
            setup.run(i);
        }
    };

    map<string,Timer> timers;
    vector<TwoPartyPlayer*> players;
    vector<sender_type> baseSenderInputs;
    vector<receiver_type> baseReceiverOutputs;
    BitVector base_receiver_inputs;

    int get_nparties() const { return nparties; }
    int get_nbase() const { return base_receiver_inputs.size(); }
    int get_my_num() const { return my_num; }
    int get_base_receiver_input(int i) const { return base_receiver_inputs[i]; }

    OTTripleSetup() : nparties(0), my_num(0)
    {
    }

    OTTripleSetup(Player& N, bool real_OTs = true)
        : nparties(N.num_players()), my_num(N.my_num())
    {
        int nbase = 128;
        base_receiver_inputs.resize(nbase);
        baseOTs.resize(nparties - 1);
        baseSenderInputs.resize(nparties - 1);
        baseReceiverOutputs.resize(nparties - 1);

#ifdef VERBOSE_BASEOT
        if (real_OTs)
            cout << "Doing real base OTs\n";
        else
            cout << "Doing fake base OTs\n";
#endif

        for (int i = 0; i < nparties - 1; i++)
        {
            int other_player;
            // i for indexing, other_player is actual number
            if (i >= my_num)
                other_player = i + 1;
            else
                other_player = i;

            players.push_back(new VirtualTwoPartyPlayer(N, other_player));

            // sets up a pair of base OTs, playing both roles
            if (real_OTs)
            {
                baseOTs[i] = new BaseOT(nbase, players[i]);
            }
            else
            {
                baseOTs[i] = new FakeOT(nbase, players[i]);
            }
        }

        setup();
        close_connections();
    }

    // run the Base OTs
    void setup();
    // close down the sockets
    void close_connections();

    //template <class T>
    //T get_mac_key();

    OTTripleSetup get_fresh();

    int index_for(int other)
    {
        assert(other != my_num);
        if (other > my_num)
            return other - 1;
        else
            return other;
    }

    void pack(octetStream& os) const;
    void unpack(octetStream& os);

    void check(TwoPartyPlayer& P);
};

class OnDemandOTTripleSetup
{
    map<Player*, OTTripleSetup*> setups;

public:
    ~OnDemandOTTripleSetup()
    {
        for (auto& setup : setups)
            delete setup.second;
    }

    OTTripleSetup get_fresh(Player& P)
    {
        if (setups.find(&P) == setups.end())
            setups[&P] = new OTTripleSetup(P, true);
        return setups[&P]->get_fresh();
    }
};

#endif
