/*
 * ProtocolSet.h
 *
 */

#ifndef PROTOCOLS_PROTOCOLSET_H_
#define PROTOCOLS_PROTOCOLSET_H_

#include "Processor/Processor.h"
#include "Processor/Machine.h"
#include "GC/ShareThread.h"
#include "ProtocolSetup.h"

#include <assert.h>
#include <type_traits>

/**
 * Input, multiplication, and output protocol instance
 * for an arithmetic share type
 */
template<class T>
class ProtocolSet
{
    DataPositions usage;

public:
    typename T::MAC_Check output;
    typename T::LivePrep preprocessing;
    SubProcessor<T> processor;
    typename T::Protocol& protocol;
    typename T::Input& input;

    ProtocolSet(Player& P, typename T::mac_key_type mac_key) :
            usage(P.num_players()), output(mac_key), preprocessing(0, usage), processor(
                    output, preprocessing, P), protocol(processor.protocol), input(
                    processor.input)
    {
    }

    /**
     * @param P communication instance
     * @param setup one-time setup instance
     */
    ProtocolSet(Player& P, const ProtocolSetup<T>& setup) :
            ProtocolSet(P, setup.get_mac_key())
    {
    }

    /**
     * @param P communication instance
     * @param machine virtual machine instance
     */
    template<class sgf2n>
    ProtocolSet(Player& P, const Machine<T, sgf2n>& machine) :
            ProtocolSet(P, machine.get_sint_mac_key())
    {
    }

    /**
     * Run all protocol checks
     */
    void check()
    {
        protocol.check();
        output.Check(processor.P);
    }
};

/**
 * Input, multiplication, and output protocol instance
 * for a binary share type
 */
template<class T>
class BinaryProtocolSet
{
    DataPositions usage;
    typename T::LivePrep prep;
    GC::ShareThread<T> thread;

public:
    typename T::MAC_Check& output;
    typename T::Protocol& protocol;
    typename T::Input input;
    typename T::LivePrep& preprocessing;

    /**
     * @param P communication instance
     * @param setup one-time setup instance
     */
    BinaryProtocolSet(Player& P, const BinaryProtocolSetup<T>& setup) :
            BinaryProtocolSet(P, setup.get_mac_key())
    {
    }

    /**
     * @param P communication instance
     * @param machine virtual machine instance
     */
    template<class sint, class sgf2n>
    BinaryProtocolSet(Player& P, const Machine<sint, sgf2n>& machine) :
            BinaryProtocolSet(P, machine.get_bit_mac_key())
    {
        assert((is_same<typename sint::bit_type, T>()));
    }

    BinaryProtocolSet(Player& P, const typename T::mac_key_type mac_key) :
            usage(P.num_players()), prep(usage), thread(prep, P,
                    mac_key), output(*thread.MC), protocol(
                    *thread.protocol), input(output, prep, P),
                    preprocessing(prep)
    {
    }

    /**
     * Run all protocol checks
     */
    void check()
    {
        protocol.check();
        output.Check(protocol.P);
    }
};

/**
 * Input, multiplication, and output protocol instance
 * for an arithmetic share type and the corresponding binary one
 */
template<class T>
class MixedProtocolSet
{
    ProtocolSet<T> arithmetic;

public:
    BinaryProtocolSet<typename T::bit_type> binary;

    typename T::MAC_Check& output;
    typename T::LivePrep& preprocessing;
    typename T::Protocol& protocol;
    typename T::Input& input;

    /**
     * @param P communication instance
     * @param setup one-time setup instance
     */
    MixedProtocolSet(Player& P, const MixedProtocolSetup<T>& setup) :
            arithmetic(P, setup), binary(P, setup.binary), output(
                    arithmetic.output), preprocessing(arithmetic.preprocessing), protocol(
                    arithmetic.protocol), input(arithmetic.input)
    {
    }

    /**
     * @param P communication instance
     * @param machine virtual machine instance
     */
    template<class sgf2n>
    MixedProtocolSet(Player& P, const Machine<T, sgf2n>& machine) :
            arithmetic(P, machine), binary(P, machine), output(
                    arithmetic.output), preprocessing(arithmetic.preprocessing), protocol(
                    arithmetic.protocol), input(arithmetic.input)
    {
    }

    MixedProtocolSet(Player& P, typename T::mac_key_type arithmetic_mac_key,
            typename T::bit_type::mac_key_type binary_mac_key) :
            arithmetic(P, arithmetic_mac_key), binary(P, binary_mac_key), output(
                    arithmetic.output), preprocessing(arithmetic.preprocessing), protocol(
                    arithmetic.protocol), input(arithmetic.input)
    {
    }

    /**
     * Run all protocol checks
     */
    void check()
    {
        arithmetic.check();
        binary.check();
    }
};

#endif /* PROTOCOLS_PROTOCOLSET_H_ */
