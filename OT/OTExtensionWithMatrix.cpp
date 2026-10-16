/*
 * OTExtensionWithMatrix.cpp
 *
 */

#include "OTExtensionWithMatrix.h"
#include "Tools/Bundle.h"
#include "Tools/CodeLocations.h"
#include "Tools/WaitQueue.h"
#include "Processor/ThreadQueues.h"

#ifndef USE_KOS
#ifdef USE_LIBOTE1
#include "Networking/PlayerCtSocket.h"

#include <libOTe/TwoChooseOne/SoftSpokenOT/TwoOneMalicious.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>

osuCrypto::IOService ot_extension_ios;
#else
#include "Networking/PlayerCoSocket.h"
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtSender.h>
#endif
#endif

#include "OTCorrelator.hpp"

namespace osuCrypto {
class Channel;
}

class SoftState
{
#ifdef USE_LIBOTE1
    array<osuCrypto::Channel*, 2> channels;
    array<PlayerCtSocket*, 2> sockets;
#else
    array<PlayerCoSocket*, 2> co_sockets;
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> sendMessages;
    osuCrypto::AlignedUnVector<osuCrypto::block> messages;
#endif

    OTExtensionWithMatrix& ext;

    typedef pair<const BitVector*, bool> job_type;
    WaitQueue<job_type> job_queue, res_queue;

    pthread_t thread;

    static void* run_thread(void* state);

    void run();

public:
    SoftState(OTExtensionWithMatrix& ext);
    ~SoftState();

    void generate(const BitVector& newReceiverInput, bool just_bits);

    void soft_sender(size_t n, bool just_bits);
    void soft_receiver(size_t n, const BitVector& newReceiverInput,
            bool just_bits);
};

OTExtensionWithMatrix OTExtensionWithMatrix::setup(TwoPartyPlayer& player,
        int128 delta, OT_ROLE role, bool passive)
{
    BaseOT baseOT(128, &player, INV_ROLE(role));
    PRNG G;
    G.ReSeed();
    baseOT.set_receiver_inputs(delta);
    baseOT.exec_base(false);
    return OTExtensionWithMatrix(baseOT, &player, passive);
}

OTExtensionWithMatrix::OTExtensionWithMatrix(const BaseOT& baseOT, TwoPartyPlayer* player,
        bool passive) : OTCorrelator(baseOT, player, passive)
{
    init_me();
}

OTExtensionWithMatrix::OTExtensionWithMatrix(Player& P, bool passive) :
        OTExtensionWithMatrix(BaseMachine::fresh_ot_setup(P).get_base(0),
                new VirtualTwoPartyPlayer(P, 1 - P.my_num()), passive)
{
    assert(P.num_players() == 2);
    init_me();
    delete_player = true;
}

void OTExtensionWithMatrix::init_me()
{
    G.ReSeed();
    nsubloops = 1;
    agreed = false;
    softspoken_k = 2;
    state = 0;
    delete_player = false;
}

OTExtensionWithMatrix::~OTExtensionWithMatrix()
{
    if (state)
        delete state;
    if (delete_player)
        delete player;
}

SoftState::SoftState(OTExtensionWithMatrix& ext) : ext(ext)
{
    assert(ext.player);

#ifdef USE_LIBOTE1
    sockets[0] = new PlayerCtSocket(*ext.player);
    sockets[1] = new PlayerCtSocket(*ext.player->fork("soft"));

    for (int i = 0; i < 2; i++)
        channels[i] = new osuCrypto::Channel(ot_extension_ios, sockets[i]);
#else
    co_sockets[0] = new PlayerCoSocket(*ext.player);
    co_sockets[1] = new PlayerCoSocket(*ext.player->fork("soft"));
#endif

    pthread_create(&thread, 0, run_thread, this);
}

SoftState::~SoftState()
{
    job_queue.stop();
    pthread_join(thread, 0);

#ifndef USE_KOS
#ifdef USE_LIBOTE1
    for (auto& channel : channels)
        delete channel;
#else
    for (auto& x : co_sockets)
        delete x;
#endif
#endif
}

void* SoftState::run_thread(void* state)
{
    ((SoftState*) state)->run();
    return 0;
}

void SoftState::run()
{
    job_type job;
    while (job_queue.pop(job))
    {
        soft_receiver(job.first->size(), *job.first, job.second);
        res_queue.push(job);
    }
}

bool OTExtensionWithMatrix::use_kos()
{
#ifdef USE_KOS
    return true;
#else
    return OnlineOptions::singleton.has_option("use_kos");
#endif
}

void OTExtensionWithMatrix::protocol_agreement()
{
    if (agreed)
        return;

    Bundle<octetStream> bundle(*player);
    if (use_kos())
        bundle.mine = string("KOS15");
    else
        bundle.mine = string("SoftSpokenOT");

    if (OnlineOptions::singleton.has_option("high_softspoken"))
        softspoken_k = 8;

    if (OnlineOptions::singleton.has_param("softspoken"))
        softspoken_k = OnlineOptions::singleton.get_param("softspoken");

    int needed = DIV_CEIL(nbaseOTs, softspoken_k) * softspoken_k;

    baseReceiverInput.resize_zero(needed);

    for (int i = nbaseOTs; i < needed; i++)
    {
        auto zero = string(SEED_SIZE, '\0');
        G_receiver.push_back(zero);
        G_sender.push_back({});
        for (int j = 0; j < 2; j++)
            G_sender.back().push_back(zero);
    }

    bundle.mine.store(softspoken_k);

    player->unchecked_broadcast(bundle);

    try
    {
        bundle.compare(*player);
        agreed = true;
    }
    catch (mismatch_among_parties&)
    {
        cerr << "Parties compiled with different OT extensions" << endl;
        cerr << "Set \"USE_KOS\" to the same value on all parties" << endl;
        cerr << "and make sure that the SoftSpokenOT parameter is the same" << endl;
        exit(1);
    }
}

void OTExtensionWithMatrix::transfer(int nOTs,
        const BitVector& receiverInput, int nloops)
{
#ifdef OTEXT_TIMER
    timeval totalstartv, totalendv;
    gettimeofday(&totalstartv, NULL);
#endif
    cout << "\tDoing " << nOTs << " extended OTs as " << role_to_str(ot_role) << endl;

    // resize to account for extra k OTs that are discarded
    BitVector newReceiverInput(nOTs);
    for (unsigned int i = 0; i < receiverInput.size_bytes(); i++)
    {
        newReceiverInput.set_byte(i, receiverInput.get_byte(i));
    }

    for (int loop = 0; loop < nloops; loop++)
    {
        extend(nOTs, newReceiverInput);
#ifdef OTEXT_TIMER
        gettimeofday(&totalendv, NULL);
        double elapsed = timeval_diff(&totalstartv, &totalendv);
        cout << "\t\tTotal thread time: " << elapsed/1000000 << endl << flush;
#endif
    }

#ifdef OTEXT_TIMER
    gettimeofday(&totalendv, NULL);
    times["Total thread"] +=  timeval_diff(&totalstartv, &totalendv);
#endif
}

void OTExtensionWithMatrix::extend(int nOTs_requested,
        const BitVector& newReceiverInput, bool hash, bool just_bits)
{
    CODE_LOCATION
    protocol_agreement();

    if (use_kos())
    {
        extend_correlated(nOTs_requested, newReceiverInput);
        if (hash)
            hash_outputs(nOTs_requested);
        return;
    }

#ifdef USE_KOS
    assert(use_kos());
#else

    if (not just_bits)
        resize(nOTs_requested);

    if (nOTs_requested == 0)
        return;

    if (not state)
        state = new SoftState(*this);

    assert(newReceiverInput.size() == unsigned(nOTs_requested));

    state->generate(newReceiverInput, just_bits);
}

void SoftState::generate(const BitVector& newReceiverInput, bool just_bits)
{
    auto nOTs_requested = newReceiverInput.size();
    job_type job(&newReceiverInput, just_bits);
    job_queue.push(job);
    try
    {
        soft_sender(nOTs_requested, just_bits);
    }
    catch (exception& e)
    {
        ext.state = 0;
        throw;
    }
    assert(res_queue.pop() == job);

#ifdef USE_LIBOTE1
    channels[0]->send("hello", 6);
    char buf[6];
    channels[0]->recv(buf, 6);
    assert(string(buf, 5) == string("hello"));
#endif
#endif
}

#ifndef USE_KOS
void SoftState::soft_sender(size_t n, bool just_bits)
{
    if (not (ext.ot_role & SENDER))
        return;

    if (OnlineOptions::singleton.has_option("verbose_ot"))
        fprintf(stderr, "%zu OTs as sender (%s)\n", n,
                ext.passive_only ? "semi-honest" : "malicious");

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    vector<osuCrypto::block> outputs;
    for (auto& x : ext.G_receiver)
    {
        outputs.push_back(x.get_doubleword());
    }

#ifdef USE_LIBOTE1
    auto& channel = *channels[ext.player->my_num()];
    auto& tamper = sockets[ext.player->my_num()]->tamper;
    osuCrypto::SoftSpokenOT::TwoOneMaliciousSender sender(ext.softspoken_k);
    sender.malicious = not ext.passive_only;
    tamper = OnlineOptions::singleton.has_option("tamper_libote_sender_base");
    sender.setBaseOts(outputs,
            {ext.baseReceiverInput.get_ptr(), sender.baseOtCount()}, prng,
            channel);

    // Choose which messages should be sent.
    auto sendMessages = osuCrypto::allocAlignedBlockArray<std::array<osuCrypto::block, 2>>(n);

    // Send the messages.
    tamper = OnlineOptions::singleton.has_option("tamper_libote_sender");
    sender.send(gsl::span(sendMessages.get(), n), prng, channel);
#else
    osuCrypto::OtExtSender* sender_;
    if (OnlineOptions::singleton.has_option("silentot"))
    {
        auto sender = new osuCrypto::SilentOtExtSender;
        sender_ = sender;
        if (ext.passive_only)
            sender->mSecurityType = osuCrypto::SilentSecType::SemiHonest;
        else
            sender->mSecurityType = osuCrypto::SilentSecType::Malicious;
    }
    else if(ext.passive_only)
        sender_ = new osuCrypto::SoftSpokenShOtSender(ext.softspoken_k);
    else
        sender_ = new osuCrypto::SoftSpokenMalOtSender(ext.softspoken_k);

    auto& sender = *sender_;
    sender.setBaseOts(outputs,
            {ext.baseReceiverInput.get_ptr(), sender.baseOtCount()});
    auto& co_socket = *co_sockets[ext.player->my_num()];
    coproto::Socket socket({}, co_socket);
    co_socket.tamper = OnlineOptions::singleton.has_option("tamper_libote_sender");
    sendMessages.resize(n);
    osuCrypto::cp::sync_wait(sender.send(sendMessages, prng, socket));
    osuCrypto::cp::sync_wait(socket.flush());
    delete sender_;
#endif

    if (just_bits)
    {
        assert(n % 64 == 0);
        for (auto& x : ext.ot_lsbs.first)
            x.resize(n);
        for (size_t i = 0; i < n; i += 64)
            for (int j = 0; j < 2; j++)
            {
                word tmp = 0;
#ifdef USE_LIBOTE1
                auto it = sendMessages.get() + i;
#else
                auto it = sendMessages.begin() + i;
#endif
                for (int k = 0; k < 64; k++)
                    tmp ^= word((*it++)[j].data()[0] & 1) << k;
                ext.ot_lsbs.first[j].set_word(i / 64, tmp);
            }
    }
    else
    {
        for (int j = 0; j < 2; j++)
            for (int i = 0; i < DIV_CEIL(n, 128); i++)
            {
                auto& square = ext.senderOutputMatrices[j].squares.at(i);
                for (size_t k = 0; k < min(128lu, n - 128 * i); k++)
                    square.rows[k] = sendMessages[i * 128 + k][j];
            }
    }
}


void SoftState::soft_receiver(size_t n, const BitVector& newReceiverInput,
        bool just_bits)
{
    if (not (ext.ot_role & RECEIVER))
        return;

    if (OnlineOptions::singleton.has_option("verbose_ot"))
        fprintf(stderr, "%zu OTs as receiver\n", n);

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    vector<array<osuCrypto::block, 2>> inputs;
    for (auto& x : ext.G_sender)
    {
        inputs.push_back({});
        for (int i = 0; i < 2; i++)
            inputs.back()[i] = x[i].get_doubleword();
    }

    // Choose which messages should be received.
    BitVector tmp(newReceiverInput);
    osuCrypto::BitVector choices(tmp.get_ptr(), n);
    assert (n == newReceiverInput.size());

#ifdef USE_LIBOTE1
    auto& channel = *channels[1 - ext.player->my_num()];
    auto& tamper = sockets[1 - ext.player->my_num()]->tamper;
    osuCrypto::SoftSpokenOT::TwoOneMaliciousReceiver recver(ext.softspoken_k);
    recver.malicious = not ext.passive_only;
    tamper = OnlineOptions::singleton.has_option("tamper_libote_base");
    recver.setBaseOts(inputs, prng, channel);

    // Receive the messages
    std::vector<osuCrypto::block, osuCrypto::AlignedBlockAllocator> messages(n);
    tamper = OnlineOptions::singleton.has_option("tamper_libote");
    recver.receive(choices, messages, prng, channel);
#else
    osuCrypto::OtExtReceiver* recver_;
    if (OnlineOptions::singleton.has_option("silentot"))
    {
        auto recver = new osuCrypto::SilentOtExtReceiver;
        recver_ = recver;
        if (ext.passive_only)
            recver->mSecurityType = osuCrypto::SilentSecType::SemiHonest;
        else
            recver->mSecurityType = osuCrypto::SilentSecType::Malicious;
    }
    else if(ext.passive_only)
        recver_ = new osuCrypto::SoftSpokenShOtReceiver(ext.softspoken_k);
    else
        recver_ = new osuCrypto::SoftSpokenMalOtReceiver(ext.softspoken_k);

    auto& recver = *recver_;
    recver.setBaseOts(inputs);
    messages.resize(n);
    auto& co_socket = *co_sockets[1 - ext.player->my_num()];
    coproto::Socket socket({}, co_socket);
    co_socket.tamper = OnlineOptions::singleton.has_option("tamper_libote");
    osuCrypto::cp::sync_wait(recver.receive(choices, messages, prng, socket));
    osuCrypto::cp::sync_wait(socket.flush());
    delete recver_;
#endif

    if (just_bits)
    {
        ext.ot_lsbs.second.resize(n);
        assert(n % 64 == 0);
        for (size_t i = 0; i < n; i += 64)
        {
            word tmp = 0;
            auto it = messages.begin() + i;
            for (int j = 0; j < 64; j++)
                tmp ^= word((*it++).data()[0] & 1) << j;
            ext.ot_lsbs.second.set_word(i / 64, tmp);
         }
    }
    else
        for (int i = 0; i < DIV_CEIL(n, 128); i++)
        {
            auto& square = ext.receiverOutputMatrix.squares.at(i);
            for (size_t j = 0; j < min(128lu, n - 128 * i); j++)
                square.rows[j] = messages[128 * i + j];
        }
}
#endif

void OTExtensionWithMatrix::extend_correlated(const BitVector& newReceiverInput)
{
    extend_correlated(newReceiverInput.size(), newReceiverInput);
}

void OTExtensionWithMatrix::extend_correlated(int nOTs_requested, const BitVector& newReceiverBits)
{
    CODE_LOCATION
//    if (nOTs % nbaseOTs != 0)
//        throw invalid_length(); //"nOTs must be a multiple of nbaseOTs\n");
    if (nOTs_requested == 0)
        return;
    // local copy
    auto newReceiverInput = newReceiverBits;
    if ((ot_role & RECEIVER) and (size_t)nOTs_requested != newReceiverInput.size())
        throw runtime_error("wrong number of choice bits");
    int nOTs_requested_rounded = (nOTs_requested + 127) / 128 * 128;
    // add k + s to account for discarding k OTs
    int nOTs = nOTs_requested_rounded + 2 * 128;

    int slice = nOTs / nsubloops / 128;
    nOTs = slice * nsubloops * 128;
    resize(nOTs);
    newReceiverInput.resize_zero(nOTs);

    // randomize last 128 + 128 bits that will be discarded
    for (int i = 0; i < 4; i++)
        newReceiverInput.set_word(nOTs/64 - i - 1, G.get_word());

    // subloop for first part to interleave communication with computation
    for (int start = 0; start < nOTs / 128; start += slice)
    {
        expand(start, slice);
        this->correlate(start, slice, newReceiverInput, true);
        transpose(start, slice);
    }

#ifdef OTEXT_TIMER
    double elapsed;
#endif
    // correlation check
    if (!passive_only)
    {
#ifdef OTEXT_TIMER
        timeval startv, endv;
        gettimeofday(&startv, NULL);
#endif
        check_correlation(nOTs, newReceiverInput);
#ifdef OTEXT_TIMER
        gettimeofday(&endv, NULL);
        elapsed = timeval_diff(&startv, &endv);
        cout << "\t\tTotal correlation check time: " << elapsed/1000000 << endl << flush;
        times["Total correlation check"] += timeval_diff(&startv, &endv);
#endif
    }

    receiverOutputMatrix.resize(nOTs_requested_rounded);
    senderOutputMatrices[0].resize(nOTs_requested_rounded);
    senderOutputMatrices[1].resize(nOTs_requested_rounded);
    newReceiverInput.resize(nOTs_requested);
}

void OTExtensionWithMatrix::expand_transposed()
{
    for (int i = 0; i < nbaseOTs; i++)
    {
        if (ot_role & RECEIVER)
        {
            receiverOutputMatrix.squares[i/128].randomize(i % 128, G_sender[i][0]);
            t1.squares[i/128].randomize(i % 128, G_sender[i][1]);
        }
        if (ot_role & SENDER)
        {
            senderOutputMatrices[0].squares[i/128].randomize(i % 128, G_receiver[i]);
        }
    }
}

void OTExtensionWithMatrix::transpose(int start, int slice)
{
    if (slice < 0)
        slice = receiverOutputMatrix.squares.size();

    BitMatrixSlice receiverOutputSlice(receiverOutputMatrix, start, slice);
    BitMatrixSlice senderOutputSlices[2] = {
            BitMatrixSlice(senderOutputMatrices[0], start, slice),
            BitMatrixSlice(senderOutputMatrices[1], start, slice)
    };

    // transpose t0[i] onto receiverOutput and tmp (q[i]) onto senderOutput[i][0]

    //cout << "Starting matrix transpose\n" << flush << endl;
#ifdef OTEXT_TIMER
    timeval transt1, transt2;
    gettimeofday(&transt1, NULL);
#endif
    // transpose in 128-bit chunks
    if (ot_role & RECEIVER)
        receiverOutputSlice.transpose();
    if (ot_role & SENDER)
        senderOutputSlices[0].transpose();

#ifdef OTEXT_TIMER
    gettimeofday(&transt2, NULL);
    double transtime = timeval_diff(&transt1, &transt2);
    cout << "\t\tMatrix transpose took time " << transtime/1000000 << endl << flush;
    times["Matrix transpose"] += timeval_diff(&transt1, &transt2);
#endif
}

/*
 * Hash outputs to make into random OT
 */
void OTExtensionWithMatrix::hash_outputs(int nOTs)
{
    hash_outputs(nOTs, senderOutputMatrices, receiverOutputMatrix);
}

octet* OTExtensionWithMatrix::get_receiver_output(int i)
{
    return (octet*)&receiverOutputMatrix.squares[i/128].rows[i%128];
}

octet* OTExtensionWithMatrix::get_sender_output(int choice, int i)
{
    return (octet*)&senderOutputMatrices[choice].squares[i/128].rows[i%128];
}

OTExtensionWithMatrix::OtBits OTExtensionWithMatrix::bit_extension(
        const BitVector& choices, bool multithread)
{
    assert(choices.size() % 128 == 0);
    OtBits res(choices.size());
    if (multithread and BaseMachine::has_singleton()
            and not OnlineOptions::singleton.has_option("no_multithread_ot"))
    {
        auto& queues = BaseMachine::s().queues;
        OtLsbJob job(&res, choices);
        auto dist_state = queues.distribute_multi(job, choices.size(), 0, 128);
        auto start = dist_state.first;
        bit_extension(res, choices, start, choices.size());
        if (start)
            queues.wrap_up(job, dist_state.second);
    }
    else
        bit_extension(res, choices, 0, choices.size());
    return res;
}

void OTExtensionWithMatrix::bit_extension(OtBits& res, const BitVector& choices, size_t start, size_t end)
{
    size_t budget = 1 << 20;
    for (size_t i = start; i < end; i += budget)
    {
        auto part = choices.part(i, min(budget, end - i));
        extend(part.size(), part, true, true);
        if (ot_lsbs.second.size())
        {
            assert(ot_lsbs.second.size() == ot_lsbs.first[0].size());
            if (ot_lsbs.second.size() == choices.size())
            {
                res = ot_lsbs;
                return;
            }

            res.second.set_part(i, ot_lsbs.second);
            for (int j = 0; j < 2; j++)
                res.first[j].set_part(i, ot_lsbs.first[j]);
        }
        else
        {
            res.second.set_part(i, receiverOutputMatrix.lsbs());
            for (int j = 0; j < 2; j++)
                res.first[j].set_part(i, senderOutputMatrices[j].lsbs());
        }
    }
    ot_lsbs.clear();
}

void OTExtensionWithMatrix::print(BitVector& newReceiverInput, int i)
{
    if (player->my_num() == 0)
    {
        print_receiver<gf2n_long>(newReceiverInput, receiverOutputMatrix, i);
        print_sender(senderOutputMatrices[0].squares[i], senderOutputMatrices[1].squares[i]);
    }
    else
    {
        print_sender(senderOutputMatrices[0].squares[i], senderOutputMatrices[1].squares[i]);
        print_receiver<gf2n_long>(newReceiverInput, receiverOutputMatrix, i);
    }
}

template <class T>
void OTExtensionWithMatrix::print_receiver(BitVector& newReceiverInput, BitMatrix& matrix, int k, int offset)
{
    if (ot_role & RECEIVER)
    {
        for (int i = 0; i < 16; i++)
        {
            if (newReceiverInput.get_bit((offset + k) * 128 + i))
            {
                for (int j = 0; j < 33; j++)
                    cout << " ";
                cout << T(matrix.squares[k].rows[i]);
            }
            else
                cout << int128(matrix.squares[k].rows[i]);
            cout << endl;
        }
        cout << endl;
    }
}

void OTExtensionWithMatrix::print_sender(square128& square0, square128& square1)
{
    if (ot_role & SENDER)
    {
        for (int i = 0; i < 16; i++)
        {
            cout << int128(square0.rows[i]) << " ";
            cout << int128(square1.rows[i]) << " ";
            cout << endl;
        }
        cout << endl;
    }
}

template <class T>
void OTExtensionWithMatrix::print_post_correlate(BitVector& newReceiverInput, int j, int offset, int sender)
{
   cout << "post correlate, sender" << sender << endl;
   if (player->my_num() == sender)
   {
       T delta = newReceiverInput.get_int128(offset + j);
       for (int i = 0; i < 16; i++)
       {
           cout << (int128(receiverOutputMatrix.squares[j].rows[i]));
           cout << " ";
           cout << (T(receiverOutputMatrix.squares[j].rows[i]) - delta);
           cout << endl;
       }
       cout << endl;
   }
   else
   {
       print_receiver<T>(baseReceiverInput, senderOutputMatrices[0], j);
   }
}

void OTExtensionWithMatrix::print_pre_correlate(int i)
{
    cout << "pre correlate" << endl;
    if (player->my_num() == 0)
        print_sender(receiverOutputMatrix.squares[i], t1.squares[i]);
    else
        print_receiver<gf2n_long>(baseReceiverInput, senderOutputMatrices[0], i);
}

void OTExtensionWithMatrix::print_post_transpose(BitVector& newReceiverInput, int i, int sender)
{
    cout << "post transpose, sender " << sender << endl;
    if (player->my_num() == sender)
    {
        print_receiver<gf2n_long>(newReceiverInput, receiverOutputMatrix);
    }
    else
    {
        square128 tmp = senderOutputMatrices[0].squares[i];
        tmp ^= baseReceiverInput;
        print_sender(senderOutputMatrices[0].squares[i], tmp);
    }
}

void OTExtensionWithMatrix::print_pre_expand()
{
    cout << "pre expand" << endl;
    if (player->my_num() == 0)
    {
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 2; j++)
                cout << int128(_mm_loadu_si128((__m128i*)G_sender[i][j].get_seed())) << " ";
            cout << endl;
        }
        cout << endl;
    }
    else
    {
        for (int i = 0; i < 16; i++)
        {
            if (baseReceiverInput.get_bit(i))
            {
                for (int j = 0; j < 33; j++)
                    cout << " ";
            }
            cout << int128(_mm_loadu_si128((__m128i*)G_receiver[i].get_seed())) << endl;
        }
        cout << endl;
    }
}
