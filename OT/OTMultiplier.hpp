/*
 * OTMultiplier.cpp
 *
 */

#ifndef OT_OTMULTIPLIER_HPP_
#define OT_OTMULTIPLIER_HPP_

#include "OT/config.h"

#include "OT/OTMultiplier.h"
#include "OT/NPartyTripleGenerator.h"
#include "OT/BaseOT.h"

#include "OT/OTVole.hpp"
#include "OT/Row.hpp"
#include "OT/Rectangle.hpp"
#include "OT/OTCorrelator.hpp"

#include <math.h>

//#define OTCORR_TIMER

template<class T>
OTMultiplier<T>::OTMultiplier(OTTripleGenerator<T>& generator,
        int thread_num) :
        generator(generator), thread_num(thread_num),
        rot_ext(generator.players[thread_num], BOTH,
                !generator.machine.correlation_check),
        otCorrelator(generator.players[thread_num], BOTH, true)
{
    this->thread = 0;
    rot_ext.init(generator.baseReceiverInput,
            generator.baseSenderInputs[thread_num],
            generator.baseReceiverOutputs[thread_num]);
}

template<class T>
MascotMultiplier<T>::MascotMultiplier(OTTripleGenerator<T>& generator,
        int thread_num) :
        OTMultiplier<T>(generator, thread_num),
		auth_ot_ext(generator.players[thread_num], BOTH, true)
{
    c_output.resize(generator.nTriplesPerLoop);
}

template<class T>
TinyMultiplier<T>::TinyMultiplier(OTTripleGenerator<T>& generator,
        int thread_num) :
        OTMultiplier<T>(generator, thread_num),
        mac_vole(T::part_type::mac_key_type::N_BITS,
                generator.players[thread_num],
                BOTH, false)
{
    c_output.resize(generator.nTriplesPerLoop);
}

template<class T>
TinierMultiplier<T>::TinierMultiplier(OTTripleGenerator<T>& generator,
        int thread_num) :
        OTMultiplier<T>(generator, thread_num),
        auth_ot_ext(generator.players[thread_num], BOTH, true)
{
    c_output.resize(generator.nTriplesPerLoop);
}

template <int K, int S>
Spdz2kMultiplier<K, S>::Spdz2kMultiplier(OTTripleGenerator<Spdz2kShare<K, S>>& generator, int thread_num) :
        OTMultiplier<Spdz2kShare<K, S>>
        (generator, thread_num)
{
#ifdef USE_OPT_VOLE
		mac_vole = new OTVole<Z2<MAC_BITS>>(S, generator.players[thread_num], BOTH, false);
		input_mac_vole = new OTVole<Z2<K + S>>(S, generator.players[thread_num], BOTH, false);
#else
		mac_vole = new OTVoleBase<Z2<MAC_BITS>>(S, generator.players[thread_num], BOTH, false);
		input_mac_vole = new OTVoleBase<Z2<K + S>>(S, generator.players[thread_num], BOTH, false);
#endif
}

template<int K, int S>
Spdz2kMultiplier<K, S>::~Spdz2kMultiplier()
{
    delete mac_vole;
    delete input_mac_vole;
}

template<class T>
OTMultiplier<T>::~OTMultiplier()
{
}

template<class U>
void OTMultiplierBase::init(U& key, Player& P, int other, OTTripleSetup& ot_setup)
{
    VirtualTwoPartyPlayer player(P, other);
    OTExtensionWithMatrix rot_ext(&player);
    int index = key.ot.index_for(other);
    rot_ext.init(ot_setup.base_receiver_inputs,
            ot_setup.baseSenderInputs.at(index),
            ot_setup.baseReceiverOutputs.at(index));
    auto& keyBits = key.ot.base_receiver_inputs;
    rot_ext.extend(keyBits.size(), keyBits);
    auto& senderOutput = key.ot.baseSenderInputs.at(index);
    auto& receiverOutput = key.ot.baseReceiverOutputs.at(index);
    senderOutput.resize(keyBits.size());
    for (size_t j = 0; j < keyBits.size(); j++)
    {
        for (int i = 0; i < 2; i++)
        {
            senderOutput[j][i].resize(128);
            senderOutput[j][i].set_int128(0, rot_ext.senderOutputMatrices[i].squares[0].rows[j]);
        }
    }
    rot_ext.receiverOutputMatrix.vertical_to(receiverOutput);
    assert(receiverOutput.size() >= keyBits.size());
    receiverOutput.resize(keyBits.size());

    if (OnlineOptions::singleton.has_option("debug_mac"))
        key.ot.check(player);
}

template<class T>
void OTMultiplier<T>::init()
{
    if (not T::has_mac)
        return;

    keyBits.set(generator.get_mac_key());
    auto& ot_setup = generator.get_mac_key().ot;
    if (OnlineOptions::singleton.has_option("debug_mac"))
        cerr << "key bits: " << keyBits.str() << "/"
                << ot_setup.base_receiver_inputs.str() << endl;
    assert(keyBits == ot_setup.base_receiver_inputs);
    senderOutput = ot_setup.baseSenderInputs.at(thread_num);
    receiverOutput = ot_setup.baseReceiverOutputs.at(thread_num);

    if (OnlineOptions::singleton.has_option("debug_mac"))
    {
        cerr << "MAC key: " << generator.get_mac_key() << endl;
        ot_setup.check(*generator.players.at(thread_num));
    }

    init_authenticator(keyBits, senderOutput, receiverOutput);
}

template<class T>
void OTMultiplier<T>::multiply()
{
    this->outbox.push({});
    MultJob job;
    while (this->inbox.pop(job))
    {
        if (receiverOutput.empty())
            init();

        if (job.input)
        {
            if (job.player == generator.my_num
                    or job.player == generator.players[thread_num]->other_player_num())
                multiplyForInputs(job);
            else
                this->outbox.push(job);
        }
        else
        {
            switch (job.type)
            {
            case DATA_BIT:
                multiplyForBits();
                break;
            case DATA_TRIPLE:
                multiplyForTriples();
                break;
            case DATA_MIXED:
                multiplyForMixed();
                break;
            default:
                throw not_implemented();
            }
        }
    }
}

template<class T>
void SemiMultiplier<T>::multiplyForBits()
{
    CODE_LOCATION
    auto& rot_ext = this->rot_ext;
    auto& otCorrelator = this->otCorrelator;

    OT_ROLE role;

    if (this->generator.players[0]->my_num())
        role = SENDER;
    else
        role = RECEIVER;

    rot_ext.set_role(INV_ROLE(role));
    otCorrelator.set_role(role);

    BitVector aBits = this->generator.valueBits[0];
    rot_ext.extend(aBits.size(), aBits, not rot_ext.use_kos());

    typedef typename T::Rectangle X;
    vector<Matrix<X> >& baseSenderOutputs = otCorrelator.matrices;
    Matrix<X>& baseReceiverOutput = otCorrelator.senderOutputMatrices[0];

    rot_ext.hash_outputs(aBits.size(), baseSenderOutputs, baseReceiverOutput,
            rot_ext.use_kos());

    int n_squares = otCorrelator.receiverOutputMatrix.squares.size();
    otCorrelator.setup_for_correlation(aBits, baseSenderOutputs,
            baseReceiverOutput);
    otCorrelator.correlate(0, n_squares, aBits, false, -1);

    c_output.clear();

    for (unsigned j = 0; j < aBits.size(); j++)
    {
        int outer = j / X::n_rows_allocated();
        int inner = j % X::n_rows_allocated();

        if (role == RECEIVER)
            c_output.push_back(
                    typename T::open_type()
                            - otCorrelator.receiverOutputMatrix.squares.at(
                                    outer).rows[inner]);
        else
            c_output.push_back(
                    otCorrelator.senderOutputMatrices[0].squares.at(outer).rows[inner]);
    }

    rot_ext.set_role(BOTH);
    otCorrelator.set_role(BOTH);

    this->outbox.push({});
}

template<class T>
void SemiMultiplier<T>::multiplyForMixed()
{
    CODE_LOCATION
    auto& rot_ext = this->rot_ext;

    typedef Square<BitVec> X;
    OTCorrelator<Matrix<X>> otCorrelator(
            this->generator.players[this->thread_num], BOTH, true);

    BitVector aBits = this->generator.valueBits[0];
    rot_ext.extend(aBits.size(), aBits, not rot_ext.use_kos());

    auto& baseSenderOutputs = otCorrelator.matrices;
    auto& baseReceiverOutput = otCorrelator.senderOutputMatrices[0];

    rot_ext.hash_outputs(aBits.size(), baseSenderOutputs, baseReceiverOutput,
            rot_ext.use_kos());

    if (this->generator.get_player().num_players() == 2)
    {
        c_output.clear();

        for (unsigned j = 0; j < aBits.size(); j++)
        {
            this->generator.valueBits[1].set_portion(j,
                    BitVec(baseSenderOutputs[0][j] ^ baseSenderOutputs[1][j]));
            c_output.push_back(baseReceiverOutput[j] ^ baseSenderOutputs[0][j]);
        }

        this->outbox.push({});
        return;
    }

    otCorrelator.setup_for_correlation(aBits, baseSenderOutputs,
            baseReceiverOutput);
    otCorrelator.correlate(0, otCorrelator.receiverOutputMatrix.squares.size(),
            this->generator.valueBits[1], false, -1);

    c_output.clear();

    for (unsigned j = 0; j < aBits.size(); j++)
    {
        c_output.push_back(
                otCorrelator.receiverOutputMatrix[j]
                        ^ otCorrelator.senderOutputMatrices[0][j]);
    }

    this->outbox.push({});
}

template<class W>
void OTMultiplier<W>::multiplyForTriples()
{
    CODE_LOCATION
    typedef typename W::Rectangle X;

    otCorrelator.resize(X::n_columns() * generator.nPreampTriplesPerLoop);

    rot_ext.resize(X::n_rows() * generator.nPreampTriplesPerLoop + 2 * 128);
    
    vector<Matrix<X> >& baseSenderOutputs = otCorrelator.matrices;
    Matrix<X>& baseReceiverOutput = otCorrelator.senderOutputMatrices[0];

    MultJob job;
    auto& outbox = this->outbox;
    outbox.push(job);

    bool corr_hash = generator.machine.use_extension;

    for (int i = 0; i < generator.nloops; i++)
    {
        this->inbox.pop(job);
        BitVector aBits = generator.valueBits[0];
        //timers["Extension"].start();
        if (generator.machine.use_extension)
        {
            if (rot_ext.use_kos())
                rot_ext.extend_correlated(aBits);
            else
            {
                rot_ext.extend(aBits.size(), aBits);
                corr_hash = false;
            }
        }
        else
        {
            BaseOT bot(aBits.size(), generator.players[thread_num]);
            bot.set_receiver_inputs(aBits);
            bot.exec_base(false);
            for (size_t i = 0; i < aBits.size(); i++)
            {
                rot_ext.receiverOutputMatrix[i] =
                        bot.receiver_outputs[i].get_int128(0).a;
                for (int j = 0; j < 2; j++)
                    rot_ext.senderOutputMatrices[j][i] =
                            bot.sender_inputs[i][j].get_int128(0).a;
            }
        }

        rot_ext.hash_outputs(aBits.size(), baseSenderOutputs,
                baseReceiverOutput, corr_hash);
        //timers["Extension"].stop();

        //timers["Correlation"].start();
        otCorrelator.setup_for_correlation(aBits, baseSenderOutputs,
                baseReceiverOutput);
        otCorrelator.correlate(0, generator.nPreampTriplesPerLoop,
                generator.valueBits[1], false, generator.nAmplify);
        //timers["Correlation"].stop();

        //timers["Triple computation"].start();

        this->after_correlation();
    }
}

template <class T>
void MascotMultiplier<T>::init_authenticator(const BitVector& keyBits,
		const vector< array<BitVector, 2> >& senderOutput,
		const vector<BitVector>& receiverOutput) {
	this->auth_ot_ext.init(keyBits, senderOutput, receiverOutput);
}

template<class T>
void TinyMultiplier<T>::init_authenticator(const BitVector& keyBits,
        const vector<array<BitVector, 2> >& senderOutput,
        const vector<BitVector>& receiverOutput)
{
    mac_vole.init(keyBits, senderOutput, receiverOutput);
}

template <class T>
void TinierMultiplier<T>::init_authenticator(const BitVector& keyBits,
        const vector< array<BitVector, 2> >& senderOutput,
        const vector<BitVector>& receiverOutput)
{
    auto tmpBits = keyBits;
    tmpBits.resize_zero(128);
    auto tmpSenderOutput = senderOutput;
    tmpSenderOutput.resize(128);
    SeededPRNG G;
    for (auto& x : tmpSenderOutput)
    {
        for (auto& y : x)
            if (y.size() == 0)
            {
                y.resize(128);
                y.randomize(G);
            }
    }
    auto tmpReceiverOutput = receiverOutput;
    tmpReceiverOutput.resize(128);
    for (auto& y : tmpReceiverOutput)
    {
        if (y.size() == 0)
        {
            y.resize(128);
            y.randomize(G);
        }
    }
    auth_ot_ext.init(tmpBits, tmpSenderOutput, tmpReceiverOutput);
}

template <int K, int S>
void Spdz2kMultiplier<K, S>::init_authenticator(const BitVector& keyBits,
		const vector< array<BitVector, 2> >& senderOutput,
		const vector<BitVector>& receiverOutput) {
	this->mac_vole->init(keyBits, senderOutput, receiverOutput);
	input_mac_vole->init(keyBits, senderOutput, receiverOutput);
}

template<class T>
void SemiMultiplier<T>::after_correlation()
{
    this->otCorrelator.reduce_squares(this->generator.nPreampTriplesPerLoop,
            this->c_output);

    this->outbox.push({});
}

template <class U>
void MascotMultiplier<U>::after_correlation()
{
	typedef typename U::open_type T;

	this->auth_ot_ext.set_role(BOTH);

    this->otCorrelator.reduce_squares(this->generator.nPreampTriplesPerLoop,
            this->c_output);

    this->outbox.push({});

    if (this->generator.machine.generateMACs)
    {
        this->macs.resize(3);
        MultJob job;
        this->inbox.pop(job);
        auto& generator = this->generator;
        array<int, 3> n_vals;
        for (int j = 0; j < 3; j++)
        {
            n_vals[j] = generator.nTriplesPerLoop;
            if (this->generator.machine.check && (j % 2 == 0))
                n_vals[j] *= 2;
        }
        if (generator.machine.fewer_rounds)
        {
            BitVector bits;
            int total = 0;
            for (int j = 0; j < 3; j++)
            {
                bits.append(generator.valueBits[j],
                        n_vals[j] * T::Square::n_columns());
                total += n_vals[j];
            }
            this->auth_ot_ext.resize(bits.size());
            this->auth_ot_ext.expand(0, total);
            this->auth_ot_ext.correlate(0, total, bits, true);
            total = 0;
            for (int j = 0; j < 3; j++)
            {
                this->auth_ot_ext.reduce_squares(n_vals[j], this->macs[j], total);
                total += n_vals[j];
            }
        }
        else
        {
            this->auth_ot_ext.resize(n_vals[0] * T::Square::n_columns());
            for (int j = 0; j < 3; j++)
            {
                int nValues = n_vals[j];
                this->auth_ot_ext.expand(0, nValues);
                this->auth_ot_ext.correlate(0, nValues,
                        this->generator.valueBits[j], true);
                this->auth_ot_ext.reduce_squares(nValues, this->macs[j]);
            }
        }
        this->outbox.push(job);
    }
}

template <class T>
void TinyMultiplier<T>::after_correlation()
{
    this->otCorrelator.reduce_squares(this->generator.nTriplesPerLoop,
            this->c_output);

    this->outbox.push({});

    this->macs.resize(3);
    MultJob job;
    this->inbox.pop(job);
    for (int j = 0; j < 3; j++)
    {
        int nValues = this->generator.nTriplesPerLoop * T::default_length;
        auto& bits = this->generator.valueBits[j];
        vector<typename T::part_type::sacri_type> values(nValues);
        for (int i = 0; i < nValues; i++)
            values[i] = bits.get_bit(i);
        mac_vole.evaluate(this->macs[j], values);
    }
    this->outbox.push(job);
}

template <class T>
void TinierMultiplier<T>::after_correlation()
{
    this->auth_ot_ext.set_role(BOTH);

    this->otCorrelator.reduce_squares(this->generator.nTriplesPerLoop,
            this->c_output);

    this->outbox.push({});

    this->macs.resize(3);
    MultJob job;
    this->inbox.pop(job);
    for (int j = 0; j < 3; j++)
    {
        auth_ot_ext.expand_correlate_unchecked(this->generator.valueBits[j]);
        auth_ot_ext.transpose();
        this->macs[j].clear();
        for (size_t i = 0; i < this->generator.valueBits[j].size(); i++)
            this->macs[j].push_back(
                    int128(
                            auth_ot_ext.receiverOutputMatrix[i]
                                    ^ auth_ot_ext.senderOutputMatrices[0][i]).get_lower());
    }
    this->outbox.push(job);
}

template <int K, int S>
void Spdz2kMultiplier<K, S>::after_correlation()
{
    this->otCorrelator.reduce_squares(this->generator.nTriplesPerLoop,
            this->c_output);

    this->outbox.push({});
    this->inbox.pop();

    this->macs.resize(3);
#ifdef OTCORR_TIMER
        timeval totalstartv, totalendv;
        gettimeofday(&totalstartv, NULL);
#endif
    for (int j = 0; j < 3; j++)
    {
        int nValues = this->generator.nTriplesPerLoop;
        BitVector* bits; 
        if (//this->generator.machine.check &&
                (j % 2 == 0)){
            nValues *= 2;
            bits = &(this->generator.valueBits[j]);
        }
        else {
            // piggy-backing mask after the b's
            nValues++;
            bits = &(this->generator.b_padded_bits);
        }
        this->mac_vole->evaluate(this->macs[j], nValues, *bits);
    }
#ifdef OTCORR_TIMER
        gettimeofday(&totalendv, NULL);
        double elapsed = timeval_diff(&totalstartv, &totalendv);
        cout << "\t\tCorrelated OT time: " << elapsed/1000000 << endl << flush;
#endif
    this->outbox.push({});
}

template<class T>
void MascotMultiplier<T>::multiplyForBits()
{
    multiplyForBits(T::clear::characteristic_two);
}

template<class T>
template<int>
void MascotMultiplier<T>::multiplyForBits(false_type)
{
    throw runtime_error("should not be called");
}

template<class T>
template<int>
void MascotMultiplier<T>::multiplyForBits(true_type)
{
    CODE_LOCATION
    auto& macs = this->macs;
    auto& outbox = this->outbox;
    auto& generator = this->generator;

    int nBits = generator.nTriplesPerLoop + generator.field_size;
    int nBlocks = ceil(1.0 * nBits / 128);
    BitVector extKeyBits = this->keyBits;
    if (OnlineOptions::singleton.has_option("debug_mac"))
        cerr << "key bits: " << extKeyBits.str() << endl;
    extKeyBits.resize_zero(128);
    auto extSenderOutput = this->senderOutput;
    extSenderOutput.resize(128, {{2, BitVector(128)}});
    SeededPRNG G;
    for (auto& x : extSenderOutput)
        for (auto& y : x)
            if (y.size() < 128)
            {
                y.resize(128);
                y.randomize(G);
            }
    auto extReceiverOutput = this->receiverOutput;
    extReceiverOutput.resize(128, 128);
    OTExtensionWithMatrix auth_ot_ext(generator.players[this->thread_num], BOTH,
            true);
    auth_ot_ext.init(extKeyBits, extSenderOutput, extReceiverOutput);
    auth_ot_ext.set_role(BOTH);
    auth_ot_ext.resize(nBlocks * 128);
    macs.resize(1);
    macs[0].resize(nBits);

    MultJob job;
    outbox.push(job);

    for (int i = 0; i < generator.nloops; i++)
    {
        auth_ot_ext.expand(0, nBlocks);
        this->inbox.pop(job);
        auth_ot_ext.correlate(0, nBlocks, generator.valueBits[0], true);
        auth_ot_ext.transpose(0, nBlocks);

        for (int j = 0; j < nBits; j++)
        {
            int128 r = auth_ot_ext.receiverOutputMatrix.squares[j/128].rows[j%128];
            int128 s = auth_ot_ext.senderOutputMatrices[0].squares[j/128].rows[j%128];
            macs[0][j] = T::clear::cut(r ^ s);
        }

        outbox.push(job);
    }
}

template<class U>
void MascotMultiplier<U>::multiplyForInputs(MultJob job)
{
    CODE_LOCATION
    assert(job.input);
    auto& generator = this->generator;
    bool mine = job.player == generator.my_num;
    auth_ot_ext.set_role(mine ? RECEIVER : SENDER);
    int nOTs = job.n_inputs * generator.field_size;
    auth_ot_ext.resize(nOTs);
    auth_ot_ext.expand(0, job.n_inputs);
    if (mine)
        this->inbox.pop();
    auth_ot_ext.correlate(0, job.n_inputs, generator.valueBits[0], true);
    auto& input_macs = this->input_macs;
    input_macs.resize(job.n_inputs);
    if (mine)
        for (int j = 0; j < job.n_inputs; j++)
            auth_ot_ext.receiverOutputMatrix.squares[j].to(input_macs[j]);
    else
        for (int j = 0; j < job.n_inputs; j++)
        {
            auth_ot_ext.senderOutputMatrices[0].squares[j].to(input_macs[j]);
            input_macs[j].negate();
        }
    this->outbox.push(job);
}

template<int K, int S>
void Spdz2kMultiplier<K, S>::multiplyForInputs(MultJob job)
{
    CODE_LOCATION
    assert(job.input);
    bool mine = job.player == this->generator.my_num;
    input_mac_vole->set_role(mine ? SENDER : RECEIVER);
    if (mine)
        this->inbox.pop();
    input_mac_vole->evaluate(this->input_macs, job.n_inputs, this->generator.valueBits[0]);
    this->outbox.push(job);
}

template<class U>
void TinierMultiplier<U>::multiplyForInputs(MultJob job)
{
    CODE_LOCATION
    assert(job.input);
    auto& generator = this->generator;
    bool mine = job.player == generator.my_num;
    auth_ot_ext.set_role(mine ? RECEIVER : SENDER);
    if (mine)
        this->inbox.pop();
    assert(not mine or job.n_inputs <= (int)generator.valueBits.at(0).size());
    auth_ot_ext.expand_correlate_unchecked(generator.valueBits[0], job.n_inputs);
    auth_ot_ext.transpose();
    auto& input_macs = this->input_macs;
    input_macs.resize(job.n_inputs);
    if (mine)
        for (int j = 0; j < job.n_inputs; j++)
            input_macs[j] = int128(auth_ot_ext.receiverOutputMatrix[j]).get_lower();
    else
        for (int j = 0; j < job.n_inputs; j++)
            input_macs[j] = int128(auth_ot_ext.senderOutputMatrices[0][j]).get_lower();
    this->outbox.push(job);
}

template<class T>
void OTMultiplier<T>::multiplyForBits()
{
    throw runtime_error("bit generation not implemented in this case");
}

template<class T>
void OTMultiplier<T>::multiplyForMixed()
{
    throw runtime_error("mixed generation not implemented in this case");
}

#endif
