#ifndef OT_NPARTYTRIPLEGENERATOR_H_
#define OT_NPARTYTRIPLEGENERATOR_H_

#include "Networking/Player.h"
#include "OT/BaseOT.h"
#include "Tools/random.h"
#include "Tools/time-func.h"
#include "Processor/InputTuple.h"
#include "Protocols/dabit.h"
#include "Protocols/Share.h"

#include "OT/OTTripleSetup.h"
#include "OT/MascotParams.h"
#include "OT/OTMultiplier.h"
#include "MascotMacKey.h"

#include <map>
#include <vector>

#define N_AMPLIFY 3

template <class T, int N>
class ShareTriple;
template <class T, int N>
class PlainTriple;

class GeneratorThread
{
protected:
    pthread_mutex_t mutex;
    pthread_cond_t ready;

public:
    int nTriples;

    map<string,Timer> timers;

    bool multi_threaded;

    GeneratorThread() : nTriples(0), multi_threaded(true) {}
    virtual ~GeneratorThread() {};
    virtual void generate() = 0;

    void lock();
    void unlock();
    void signal();
    void wait();
};

template<class T>
class OTTripleGenerator : public GeneratorThread
{
    typedef typename T::open_type open_type;
    typedef typename T::mac_key_type mac_key_type;
    typedef MascotMacKey<typename T::mac_key_type> complete_mac_key_type;

    template<class> friend class OTTripleGenerator;

protected:
    static complete_mac_key_type mac_key;

    //OTTripleSetup* setup;
    Player& globalPlayer;
    Player* parentPlayer;

    int thread_num;
    int nbase;

    struct timeval last_lap;

    ofstream outputFile;

    SeededPRNG share_prg;

    void start_progress();
    void print_progress(int k);

    void signal_multipliers(MultJob job);
    void wait_for_multipliers();

    typename T::Multiplier* new_multiplier(int i);

public:
    // TwoPartyPlayer's for OTs, n-party Player for sacrificing
    vector<TwoPartyPlayer*> players;
    vector<typename T::Multiplier*> ot_multipliers;
    //vector<OTMachine*> machines;
    BitVector baseReceiverInput; // same for every set of OTs
    vector< vector< array<BitVector, 2> > > baseSenderInputs;
    vector< vector<BitVector> > baseReceiverOutputs;
    vector<BitVector> valueBits;
    BitVector b_padded_bits;

    int my_num;
    int nTriplesPerLoop;
    int nloops;
    int field_size;
    int nAmplify;
    int nPreampTriplesPerLoop;
    int repeat[3];
    int nparties;

    MascotParams& machine;

    vector<PlainTriple<open_type, N_AMPLIFY>> preampTriples;
    vector<array<open_type, 3>> plainTriples;
    vector<dabit<T>> plainBits;
    vector<array<open_type, 3>> mixedTriples;

    typename T::MAC_Check* MC;

    static complete_mac_key_type& get_mac_key() { return mac_key; }
    static mac_key_type get_mac_key(Player& P, bool = false);
    static void reset_mac_key();

    OTTripleGenerator(const OTTripleSetup& setup, const Names& names,
            int thread_num, int nTriples, int nloops, MascotParams& machine,
            Player* parentPlayer = 0);
    ~OTTripleGenerator();

    void set_batch_size(int nTriples);

    void generate() { throw not_implemented(); }

    void generatePlainTriples();
    void plainTripleRound(int k = 0);

    void generatePlainBits();
    void generateMixedTriples();

    void run_multipliers(MultJob job);

    Player& get_player() { return globalPlayer; }
};

template<class T>
class NPartyTripleGenerator : public OTTripleGenerator<T>
{
    typedef typename T::open_type open_type;
    typedef typename T::mac_key_type mac_key_type;

    virtual void generateTriples() { throw not_implemented(); }
    virtual void generateBits() { throw not_implemented(); }

public:
    vector<InputTuple<typename T::input_type>> inputs;

    NPartyTripleGenerator(const OTTripleSetup& setup, const Names& names,
            int thread_num, int nTriples, int nloops, MascotParams& machine,
            Player* parentPlayer = 0);
    virtual ~NPartyTripleGenerator() {}

    void generate();
    void generateInputs(int player);
};

template<class T>
typename OTTripleGenerator<T>::complete_mac_key_type OTTripleGenerator<T>::mac_key;

template<class T>
class SimpleMascotTripleGenerator : public NPartyTripleGenerator<T>
{
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::MAC_Check MAC_Check;

    virtual void sacrifice(typename T::MAC_Check&, PRNG&) { throw not_implemented(); }

public:
    vector< ShareTriple<T, 2> > uncheckedTriples;

    SimpleMascotTripleGenerator(const OTTripleSetup& setup, const Names& names,
            int thread_num, int nTriples, int nloops, MascotParams& machine,
            Player* parentPlayer = 0);
    virtual ~SimpleMascotTripleGenerator() {}

    void generateTriples();
};

template<class T>
class MascotTripleGenerator : public SimpleMascotTripleGenerator<T>
{
    typedef typename T::open_type open_type;
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::MAC_Check MAC_Check;

    void generateBits();
    void generateBitsGf2n();
    template <int X, int L>
    void generateBitsFromTriples(MAC_Check& MC, ofstream& outputFile, gfp_<X, L>);
    template <class U>
    void generateBitsFromTriples(MAC_Check& MC, ofstream& outputFile, U);

    void sacrifice(typename T::MAC_Check& MC, PRNG& G);

public:
    vector<T> bits;

    MascotTripleGenerator(const OTTripleSetup& setup, const Names& names,
            int thread_num, int nTriples, int nloops, MascotParams& machine,
            Player* parentPlayer = 0);
};

template<class T>
class Spdz2kTripleGenerator : public NPartyTripleGenerator<T>
{
    typedef typename T::open_type open_type;
    typedef typename T::mac_key_type mac_key_type;
    typedef typename T::sacri_type sacri_type;

    void generateBits() { throw not_implemented(); }

    template<class U>
    void sacrificeZ2k(U& MC, PRNG& G);

public:
    vector< ShareTriple<Share<sacri_type>, 2> > uncheckedTriples;

    Spdz2kTripleGenerator(const OTTripleSetup& setup, const Names& names,
            int thread_num, int nTriples, int nloops, MascotParams& machine,
            Player* parentPlayer = 0);

    void generateTriples();
};

#endif
