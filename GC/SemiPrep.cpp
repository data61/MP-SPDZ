/*
 * SemiPrep.cpp
 *
 */

#include "SemiPrep.h"
#include "Semi.h"
#include "ThreadMaster.h"
#include "OT/NPartyTripleGenerator.h"
#include "OT/BitDiagonal.h"

#ifndef USE_LIBOTE1
#ifdef USE_TUNGSTEN
#include "LiboteState.h"
#endif

#include "Networking/PlayerCoSocket.h"
#include <libOTe/Triple/SilentOtTriple/SilentOtTriple.h>
#endif

#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/Replicated.hpp"
#include "OT/NPartyTripleGenerator.hpp"

namespace GC
{

SemiPrep::SemiPrep(DataPositions& usage, bool) :
        BufferPrep<SemiSecret>(usage), triple_generator(0), state(0),
        rot_ext(0)
{
}

void SemiPrep::set_protocol(SemiSecret::Protocol& protocol)
{
    if (triple_generator)
    {
        assert(&triple_generator->get_player() == &protocol.P);
        return;
    }

    (void) protocol;
    params.set_passive();
    triple_generator = new SemiSecret::TripleGenerator(
            BaseMachine::fresh_ot_setup(protocol.P),
            protocol.P.N, -1, OnlineOptions::singleton.batch_size,
            1, params, &protocol.P);
    triple_generator->multi_threaded = false;
    this->P = &protocol.P;
}

void SemiPrep::buffer_triples()
{
    CODE_LOCATION
    int batch_size = BaseMachine::batch_size<SemiSecret>(DATA_TRIPLE,
            this->buffer_size);

#ifdef USE_TUNGSTEN
    if (P->num_players() == 2
            and not OnlineOptions::singleton.has_option("nosilent")
            and (batch_size > (1 << 10)
                    or OnlineOptions::singleton.has_option("silent")))
    {
        if (OnlineOptions::singleton.has_option("ot_variant"))
            fprintf(stderr, "using SemiSecureTripleState\n");

        bool one_way = OnlineOptions::singleton.has_option("one_way_triples");
        int batch_size = BaseMachine::batch_size<SemiSecret>(DATA_TRIPLE,
                this->buffer_size, one_way ? 1 << 24 : 1 << 25);

        if (not state)
            state = new SemiSecureTripleState(*P);

        SemiSecureTripleState::job_type job;
        job.first = batch_size + 64;

        if (one_way)
        {
            job.first *= 2;
            state->generate_role(job, P->my_num());
            auto& triples = job.second[P->my_num()];
            this->triples.insert(this->triples.end(), triples.begin(), triples.end());
        }
        else
        {
            state->generate(&job);

            for (int i = 0; i < 2; i++)
            {
                int j = i ^ P->my_num();
                this->triples.insert(this->triples.end(), job.second[j].begin(),
                        job.second[j].end());
            }
        }

        if (OnlineOptions::singleton.has_option("debug_batch_size"))
            fprintf(stderr, "now have %zu binary triple chunks "
                    "after asking for %d triples\n", this->triples.size(), batch_size);

        return;
    }
#endif

#ifndef USE_LIBOTE1
    if (P->num_players() == 2
            and OnlineOptions::singleton.has_option("silent_triples"))
    {
        osuCrypto::SilentOtTriple triple_generator;
        triple_generator.init(P->my_num(), batch_size);
        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        auto base_count = triple_generator.baseCount(prng);
        int n_base = max(base_count.mSendCount, base_count.mRecvChoice.size());
        VirtualTwoPartyPlayer player(*P, 1 - P->my_num());
        OTExtensionWithMatrix ot_ext(&player);//, P->my_num() ? RECEIVER : SENDER);
        ot_ext.init(BaseMachine::fresh_ot_setup(*P), 0);
        BitVector bits(base_count.mRecvChoice.data(), base_count.mRecvChoice.size());
        bits.resize(n_base);
        ot_ext.extend(n_base, bits);
        vector<array<osuCrypto::block, 2>> sent;
        vector<osuCrypto::block> received;
        for (int i = 0; i < n_base; i++)
        {
            int i_square = i / 128;
            int i_part = i % 128;
            if (P->my_num())
                sent.push_back({ot_ext.senderOutputMatrices[0].squares.at(i_square).rows[i_part],
                ot_ext.senderOutputMatrices[1].squares.at(i_square).rows[i_part]});
            else
                received.push_back(ot_ext.receiverOutputMatrix.squares.at(i_square).rows[i_part]);
        }
        triple_generator.setBaseOts(sent, received);
        size_t n = DIV_CEIL(triple_generator.mN, 256);
        vector<osuCrypto::block> A(n), B(n), C(n);
        PlayerCoSocket co_socket(*P);
        osuCrypto::Socket socket({}, co_socket);
        macoro::sync_wait(triple_generator.expand(A, B, C, prng, socket));
        macoro::sync_wait(socket.flush());
        for (size_t i = 0; i < n; i++)
        {
            int128 a(A[i]), b(B[i]), c(C[i]);
            this->triples.push_back({a.get_lower(), b.get_lower(), c.get_lower()});
            this->triples.push_back({a.get_upper(), b.get_upper(), c.get_upper()});
        }
        return;
    }
#endif

    if (P->num_players() == 2
            and not OnlineOptions::singleton.has_option("no_direct_triples"))
    {
        assert(SemiSecret::default_length == 64);
        batch_size = multiple_minimum(batch_size, 128);
        if (not rot_ext)
            rot_ext = new OTExtensionWithMatrix(*P, true);
        SeededPRNG G;
        BitVector a_bits(batch_size);
        a_bits.randomize(G);
        auto bits = rot_ext->bit_extension(a_bits);
        size_t n_chunks = bits.second.size() / 64;
        for (size_t i = 0; i < n_chunks; i++)
        {
            auto a = a_bits.get_word(i);
            word b = 0;
            for (int k = 0; k < 2; k++)
                b ^= bits.first[k].get_word(i);
            auto c = (a & b) ^ bits.second.get_word(i)
                    ^ bits.first[0].get_word(i);
            this->triples.push_back({a, b, c});
        }

        return;
    }

    assert(this->triple_generator);
    this->triple_generator->set_batch_size(DIV_CEIL(batch_size, 64));
    this->triple_generator->generatePlainTriples();
    for (auto& x : this->triple_generator->plainTriples)
    {
        this->triples.push_back({{x[0], x[1], x[2]}});
    }
    this->triple_generator->unlock();
}

SemiPrep::~SemiPrep()
{
    if (triple_generator)
        delete triple_generator;
    if (rot_ext)
        delete rot_ext;

    (void) state;
#ifdef USE_TUNGSTEN
    if (state)
        delete state;
#endif

    this->print_left("mixed triples", mixed_triples.size(),
            SemiSecret::type_string(),
            this->usage.files.at(DATA_GF2N).at(DATA_MIXED));
}

void SemiPrep::buffer_bits()
{
    word r = secure_prng.get_word();
    for (size_t i = 0; i < sizeof(word) * 8; i++)
    {
        this->bits.push_back((r >> i) & 1);
    }
}

array<SemiSecret, 3> SemiPrep::get_mixed_triple(int n)
{
    assert(n < 128);

    if (mixed_triples.empty())
    {
        assert(this->triple_generator);
        this->triple_generator->set_batch_size(
                BaseMachine::batch_size<SemiSecret>(DATA_MIXED,
                        this->buffer_size));
        this->triple_generator->generateMixedTriples();
        for (auto& x : this->triple_generator->mixedTriples)
        {
            this->mixed_triples.push_back({{x[0], x[1], x[2]}});
        }
        this->triple_generator->unlock();
    }

    this->count(DATA_MIXED);
    auto res = mixed_triples.back();
    mixed_triples.pop_back();
    return res;
}

} /* namespace GC */
