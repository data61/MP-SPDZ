/*
 * LowGearKeyGen.cpp
 *
 */

#include "LowGearKeyGen.h"
#include "FHE/Rq_Element.h"

#include "Tools/benchmarking.h"

#include "Machines/SPDZ.hpp"
#include "ShareVector.hpp"
#include "MascotPrep.hpp"

template<int L>
LowGearKeyGen<L>::LowGearKeyGen(Player& P, PairwiseMachine& machine,
        FHE_Params& params) :
        KeyGenProtocol<1, L>(P, params), P(P), machine(machine)
{
}

template<int X, int L>
KeyGenProtocol<X, L>::KeyGenProtocol(Player& P, const FHE_Params& params,
        int level) :
        P(P), params(params), fftd(params.FFTD().at(level)), usage(P)
{
    open_type::init_field(params.FFTD().at(level).get_prD().pr, false);
    typename share_type::mac_key_type alphai;

    auto& batch_size = OnlineOptions::singleton.batch_size;
    backup_batch_size = batch_size;
    batch_size = min(100, batch_size);

    if (OnlineOptions::singleton.live_prep)
    {
        prep = new MascotDabitOnlyPrep<share_type>(0, usage);
        alphai = MascotDabitOnlyPrep<share_type>::get_mac_key(P);
    }
    else
    {
        prep = new Sub_Data_Files<share_type>(P.N,
                get_prep_sub_dir<share_type>(P.num_players()), usage);
        read_mac_key(get_prep_sub_dir<share_type>(P.num_players()), P.N, alphai);
    }

    MC = new MAC_Check_<share_type>(alphai);
    proc = new SubProcessor<share_type>(*MC, *prep, P);

    MC->setup(P);
}

template<int X, int L>
KeyGenProtocol<X, L>::~KeyGenProtocol()
{
    MC->Check(P);

    if (OnlineOptions::singleton.verbose)
        usage.print_cost();

    delete proc;
    delete prep;
    delete MC;

    MC->teardown();
    MascotDabitOnlyPrep<share_type>::teardown();

    OnlineOptions::singleton.batch_size = backup_batch_size;
    open_type::reset();
}

template<int X, int L>
void KeyGenProtocol<X, L>::input(vector<vector_type>& shares, const Rq_Element& secret)
{
    assert(secret.level() == 0);
    auto s = secret.get(0);
    s.change_rep(evaluation);
    auto& FFTD = s.get_FFTD();
    auto& inputter = this->proc->input;
    inputter.reset_all(P);
    for (int i = 0; i < FFTD.num_slots(); i++)
        inputter.add_from_all(s.get_element(i));
    inputter.exchange();
    shares.clear();
    shares.resize(P.num_players());
    for (int i = 0; i < FFTD.num_slots(); i++)
        for (int j = 0; j < P.num_players(); j++)
            shares[j].push_back(inputter.finalize(j));
}

/**
 * Binomial secret generation from random bits
 */
template<int X, int L>
template<class T>
void KeyGenProtocol<X, L>::binomial(vector_type& shares, T& prep)
{
    shares.resize(params.phi_m());
    RunningTimer timer, total;
    for (int i = 0; i < params.phi_m(); i++)
    {
#ifdef VERBOSE
        if (timer.elapsed() > 10)
        {
            cerr << i << "/" << params.phi_m() << ", throughput " <<
                    i / total.elapsed() << endl;
            timer.reset();
        }
#endif

        auto& share = shares[i];
        share = {};
        for (int i = 0; i < params.get_DG().get_NewHopeB(); i++)
        {
            share += prep.get_bit();
            share -= prep.get_bit();
        }
    }
    shares.fft(fftd);
}

template<int X, int L>
template<class T>
void KeyGenProtocol<X, L>::secret_key(vector_type& shares, T& prep)
{
    cerr << "Generate secret key by ";
    cerr << "binomial" << endl;
    binomial(shares, prep);
}

template<int X, int L>
typename KeyGenProtocol<X, L>::vector_type KeyGenProtocol<X, L>::schur_product(
        const vector_type& x, const vector_type& y)
{
    vector_type res;
    assert(x.size() == y.size());
    auto& protocol = proc->protocol;
    protocol.init_mul();
    for (size_t i = 0; i < x.size(); i++)
        protocol.prepare_mul(x[i], y[i]);
    protocol.exchange();
    for (size_t i = 0; i < x.size(); i++)
        res.push_back(protocol.finalize_mul());
    return res;
}

template<int X, int L>
void KeyGenProtocol<X, L>::output_to(int player, vector<open_type>& opened,
        vector<share_type>& shares)
{
    PrivateOutput<share_type> po(*proc);
    for (auto& share : shares)
        po.prepare_sending(share, player);
    po.exchange();
    opened.resize(shares.size());
    for (auto& x : opened)
        x = po.finalize(player);
}

template<int L>
void LowGearKeyGen<L>::generate_keys(FHE_Params& params)
{
    RunningTimer timer;
    auto& pk = machine.pk;

    GlobalPRNG global_prng(P);
    auto& FFTD = pk.get_params().FFTD()[0];

    for (int i = 0; i < P.num_players(); i++)
    {
        vector_type sk;
        this->secret_key(sk, *this);
        vector<open_type> open_sk;
        this->output_to(i, open_sk, sk);
        if (P.my_num() == i)
            machine.sk.assign(Ring_Element(FFTD, evaluation, open_sk));
        vector_type e0;
        this->binomial(e0, *this);
        AddableVector<open_type> a0(pk.get_params().phi_m());
        a0.randomize(global_prng);
        vector<open_type> b0;
        assert(machine.sk.p() != 0);
        this->MC->POpen(b0, sk * a0 + e0 * machine.sk.p(), P);
        machine.other_pks[i] = FHE_PK(params, machine.sk.p());
        machine.other_pks[i].assign(Ring_Element(FFTD, evaluation, a0),
                Ring_Element(FFTD, evaluation, b0));
    }

    this->MC->Check(P);

    cerr << "Key generation took " << timer.elapsed() << " seconds" << endl;
}

template<int L>
template<class FD>
void LowGearKeyGen<L>::run(PairwiseSetup<FD>& setup)
{
    CODE_LOCATION
    generate_keys(setup.params);
    machine.sk.check(machine.pk, setup.FieldD);

    RunningTimer timer;

    typename FD::T mac_key;

    bool fresh = setup.alphai == 0;

    if (fresh)
        mac_key = SeededPRNG().get<typename FD::T>();
    else
        mac_key = setup.alphai;

    PairwiseGenerator<FD> generator(0, machine, &P);
    map<string, Timer> timers;
    MultiEncCommit<FD> EC(P, machine.other_pks, setup.FieldD,
            timers, machine, generator, true);
    assert(EC.proof.get_diagonal());
    vector<Plaintext_<FD>> m(EC.proof.U, setup.FieldD);
    for (auto& mm : m)
        mm.assign_constant(mac_key);

    AddableVector<Ciphertext> C;
    octetStream ciphertexts, cleartexts;
    EC.generate_proof(C, m, ciphertexts, cleartexts);

    AddableVector<Ciphertext> others_ciphertexts;
    others_ciphertexts.resize(EC.proof.U, machine.pk.get_params());
    Verifier<FD> verifier(EC.proof, setup.FieldD);
    verifier.NIZKPoK(others_ciphertexts, ciphertexts,
            cleartexts, machine.pk);

    machine.enc_alphas.clear();
    for (int i = 0; i < P.num_players(); i++)
        machine.enc_alphas.push_back(machine.other_pks[i]);

    for (int i = 1; i < P.num_players(); i++)
    {
        int player = P.get_player(-i);
#ifdef VERBOSE_HE
        cerr << "Sending proof with " << 1e-9 * ciphertexts.get_length() << "+"
                << 1e-9 * cleartexts.get_length() << " GB" << endl;
#endif
        timers["Sending"].start();
        P.pass_around(ciphertexts);
        P.pass_around(cleartexts);
        timers["Sending"].stop();
#ifdef VERBOSE_HE
        cerr << "Checking proof of player " << i << endl;
#endif
        timers["Verifying"].start();
        verifier.NIZKPoK(others_ciphertexts, ciphertexts,
                cleartexts, machine.other_pks[player]);
        timers["Verifying"].stop();
        machine.enc_alphas.at(player) = others_ciphertexts.at(0);
    }

    setup.set_alphai(mac_key);
    machine.enc_alphas.at(P.my_num()) = C.at(0);

    auto test = machine.sk.decrypt(C[0], setup.FieldD);
    for (int i = 0; i < setup.FieldD.num_slots(); i++)
        assert(test.element(i) == mac_key);

    cerr << "MAC key generation took " << timer.elapsed() << " seconds" << endl;
}
