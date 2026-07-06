#include "OT/BaseOT.h"
#include "Tools/random.h"
#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"
#include "Tools/CodeLocations.h"
#include "Processor/OnlineOptions.h"

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <pthread.h>

#if defined(__linux__) and defined(__x86_64__)
#include <cpuid.h>
#endif

extern "C" {
#ifndef NO_AVX_OT
#include "SimpleOT/ot_sender.h"
#include "SimpleOT/ot_receiver.h"
#endif
#include "SimplestOT_C/ref10/ot_sender.h"
#include "SimplestOT_C/ref10/ot_receiver.h"
}

using namespace std;

const char* role_to_str(OT_ROLE role)
{
    if (role == RECEIVER)
        return "RECEIVER";
    if (role == SENDER)
        return "SENDER";
    return "BOTH";
}

OT_ROLE INV_ROLE(OT_ROLE role)
{
    if (role == RECEIVER)
        return SENDER;
    if (role == SENDER)
        return RECEIVER;
    else
        return BOTH;
}

void send_if_ot_sender(TwoPartyPlayer* P, vector<octetStream>& os, OT_ROLE role)
{
    if (role == SENDER)
    {
        P->send(os[0]);
    }
    else if (role == RECEIVER)
    {
        P->receive(os[1]);
    }
    else
    {
        // both sender + receiver
        P->send_receive_player(os);
    }
}

void send_if_ot_receiver(TwoPartyPlayer* P, vector<octetStream>& os, OT_ROLE role)
{
    if (role == RECEIVER)
    {
        P->send(os[0]);
    }
    else if (role == SENDER)
    {
        P->receive(os[1]);
    }
    else
    {
        // both
        P->send_receive_player(os);
    }
}

// type-dependent redirection

void sender_genS(ref10_SENDER* s, unsigned char* S_pack)
{
    ref10_sender_genS(s, S_pack);
}

void sender_keygen(ref10_SENDER* s, unsigned char* Rs_pack,
        unsigned char (*keys)[4][HASHBYTES])
{
    ref10_sender_keygen(s, Rs_pack, keys);
}

void receiver_maketable(ref10_RECEIVER* r)
{
    ref10_receiver_maketable(r);
}

void receiver_procS(ref10_RECEIVER* r)
{
    ref10_receiver_procS(r);
}

void receiver_rsgen(ref10_RECEIVER* r, unsigned char* Rs_pack,
        unsigned char* cs)
{
    ref10_receiver_rsgen(r, Rs_pack, cs);
}

void receiver_keygen(ref10_RECEIVER* r, unsigned char (*keys)[HASHBYTES])
{
    ref10_receiver_keygen(r, keys);
}

void BaseOT::allocate()
{
    for (int i = 0; i < nOT; i++)
    {
        sender_inputs[i][0] = BitVector(8 * AES_BLK_SIZE);
        sender_inputs[i][1] = BitVector(8 * AES_BLK_SIZE);
        receiver_outputs[i] = BitVector(8 * AES_BLK_SIZE);
    }
}

int BaseOT::avx = -1;

bool BaseOT::use_avx()
{
    if (avx == -1)
    {
        avx = cpu_has_avx(true);
#if defined(__linux__) and defined(__x86_64__)
        int info[4];
        __cpuid(0x80000003, info[0], info[1], info[2], info[3]);
        string str((char*) info, 16);
        if (OnlineOptions::singleton.has_option("debug_cpu"))
            cerr << "CPU: " << str << endl;
        if (str.find("Gold 63") != string::npos)
            avx = 0;
#endif
    }

    return avx;
}

void BaseOT::exec_base(bool new_receiver_inputs)
{
#ifndef NO_AVX_OT
    if (use_avx())
        exec_base<SIMPLEOT_SENDER, SIMPLEOT_RECEIVER>(new_receiver_inputs);
    else
#endif
        exec_base<ref10_SENDER, ref10_RECEIVER>(new_receiver_inputs);
}

// See https://eprint.iacr.org/2015/267.pdf
template<class T, class U>
void BaseOT::exec_base(bool new_receiver_inputs)
{
    CODE_LOCATION
    int i, j, k;
    size_t len;
    PRNG G;
    G.ReSeed();
    vector<octetStream> os(2);
    T sender;
    U receiver;

    unsigned char S_pack[ PACKBYTES ];
    unsigned char Rs_pack[ 2 ][ 4 * PACKBYTES ];
    unsigned char sender_keys[ 2 ][ 4 ][ HASHBYTES ];
    unsigned char receiver_keys[ 4 ][ HASHBYTES ];
    unsigned char cs[ 4 ];

    if (ot_role & SENDER)
    {
        // Sample a and compute A=g^a
        sender_genS(&sender, S_pack);
        // Send A
        os[0].store_bytes(S_pack, sizeof(S_pack));
    }
    send_if_ot_sender(P, os, ot_role);

    if (ot_role & RECEIVER)
    {
        // Receive A
        len = sizeof(receiver.S_pack);
        os[1].get_bytes((octet*) receiver.S_pack, len);
        if (len != HASHBYTES)
        {
            cerr << "Received invalid length in base OT\n";
            exit(1);
        }

        // Process A
        receiver_procS(&receiver);
        receiver_maketable(&receiver);
    }

    os[0].reset_write_head();
    allocate();

    for (i = 0; i < nOT; i += 4)
    {
        if (ot_role & RECEIVER)
        {
            for (j = 0; j < 4 and (i + j) < nOT; j++)
            {
                // Process choice bits
                if (new_receiver_inputs)
                    receiver_inputs[i + j] = G.get_uchar()&1;
                cs[j] = receiver_inputs[i + j].get();
            }
            // Compute B
            receiver_rsgen(&receiver, Rs_pack[0], cs);
            // Send B
            os[0].store_bytes(Rs_pack[0], sizeof(Rs_pack[0]));
            // Compute k_R
            receiver_keygen(&receiver, receiver_keys);

            // Copy keys to receiver_outputs
            for (j = 0; j < 4 and (i + j) < nOT; j++)
            {
                for (k = 0; k < AES_BLK_SIZE; k++)
                {
                    receiver_outputs[i + j].set_byte(k, receiver_keys[j][k]);
                }
            }

#ifdef BASE_OT_DEBUG
            for (j = 0; j < 4; j++)
                for (k = 0; k < AES_BLK_SIZE; k++)
                {
                    printf("%4d-th receiver key:", i+j);
                    for (k = 0; k < HASHBYTES; k++) printf("%.2X", receiver_keys[j][k]);
                    printf("\n");
                }

            printf("\n");
#endif
        }
    }

    send_if_ot_receiver(P, os, ot_role);
        
    for (i = 0; i < nOT; i += 4)
    {
        if (ot_role & SENDER)
        {
            // Receive B
            len = sizeof(Rs_pack[1]);
            os[1].get_bytes((octet*) Rs_pack[1], len);
            if (len != sizeof(Rs_pack[1]))
            {
                cerr << "Received invalid length in base OT\n";
                exit(1);
            }
            // Compute k_0 and k_1
            sender_keygen(&sender, Rs_pack[1], sender_keys);

            // Copy 128 bits of keys to sender_inputs
            for (j = 0; j < 4 and (i + j) < nOT; j++)
            {
                for (k = 0; k < AES_BLK_SIZE; k++)
                {
                    sender_inputs[i + j][0].set_byte(k, sender_keys[0][j][k]);
                    sender_inputs[i + j][1].set_byte(k, sender_keys[1][j][k]);
                }
            }
        }
        #ifdef BASE_OT_DEBUG
        for (j = 0; j < 4; j++)
        {
            if (ot_role & SENDER)
            {
                printf("%4d-th sender keys:", i+j);
                for (k = 0; k < HASHBYTES; k++) printf("%.2X", sender_keys[0][j][k]);
                printf(" ");
                for (k = 0; k < HASHBYTES; k++) printf("%.2X", sender_keys[1][j][k]);
                printf("\n");
            }
        }

        printf("\n");
        #endif
    }

    if (ot_role & SENDER)
        for (int i = 0; i < nOT; i++)
        {
            if(sender_inputs.at(i).at(0) == sender_inputs.at(i).at(1))
            {
                string error = "Sender outputs are the same at " + to_string(i)
                        + ": " + sender_inputs[i][0].str();
#ifdef NO_AVX_OT
                error += "This is a known problem with some Xeon CPUs. ";
                error += "We would appreciate if you report the output of "
                        "'cat /proc/cpuinfo | grep name'. ";
                error += "Try compiling with 'AVX_SIMPLEOT = 0' in CONFIG.mine";
#endif
                throw runtime_error(error);
            }
        }

    // Hash with counter to avoid collisions
    for (int i = 0; i < nOT; i++)
    {
        if (ot_role & RECEIVER)
            hash_with_id(receiver_outputs.at(i), i);
        if (ot_role & SENDER)
            for (int j = 0; j < 2; j++)
                hash_with_id(sender_inputs.at(i).at(j), i);
    }

    if (ot_role & SENDER)
        for (int i = 0; i < nOT; i++)
            assert(sender_inputs.at(i).at(0) != sender_inputs.at(i).at(1));

    // Set PRG seeds
    set_seeds();

    if (ot_role & SENDER)
        for (int i = 0; i < nOT; i++)
            assert(sender_inputs.at(i).at(0) != sender_inputs.at(i).at(1));
}

void BaseOT::hash_with_id(BitVector& bits, long id)
{
    assert(bits.size_bytes() >= AES_BLK_SIZE);
    Hash hash;
    hash.update(bits.get_ptr(), bits.size_bytes());
    hash.update(&id, sizeof(id));
    hash.final(bits.get_ptr(), bits.size_bytes());
}

void BaseOT::set_seeds()
{
    assert(size_t(nOT) == sender_inputs.size());

    G_sender.clear();
    G_receiver.clear();

    PRNG G[2];

    for (int i = 0; i < nOT; i++)
    {
        // Set PRG seeds
        if (ot_role & SENDER)
        {
            for (int j = 0; j < 2; j++)
            {
                G[j].SetSeed(sender_inputs[i][j].get_ptr());
            }

            G_sender.push_back({G[0], G[1]});
        }
        if (ot_role & RECEIVER)
        {
            G[0].SetSeed(receiver_outputs[i].get_ptr());
            G_receiver.push_back(G[0]);
        }
    }
    extend_length();
}

void BaseOT::extend_length()
{
    for (int i = 0; i < nOT; i++)
    {
        if (ot_role & SENDER)
        {
            sender_inputs.at(i)[0].randomize(G_sender[i][0]);
            sender_inputs.at(i)[1].randomize(G_sender[i][1]);
        }
        if (ot_role & RECEIVER)
        {
            receiver_outputs.at(i).randomize(G_receiver[i]);
        }
    }
}


void BaseOT::check()
{
    vector<octetStream> os(2);
    BitVector tmp_vector(8 * AES_BLK_SIZE);


    for (int i = 0; i < nOT; i++)
    {
        if (ot_role == SENDER)
        {
            // send both inputs over
            sender_inputs[i][0].pack(os[0]);
            sender_inputs[i][1].pack(os[0]);
            P->send(os[0]);
        }
        else if (ot_role == RECEIVER)
        {
            P->receive(os[1]);
        }
        else
        {
            // both sender + receiver
            sender_inputs[i][0].pack(os[0]);
            sender_inputs[i][1].pack(os[0]);
            P->send_receive_player(os);
        }
        if (ot_role & RECEIVER)
        {
            tmp_vector.unpack(os[1]);
        
            if (receiver_inputs[i] == 1)
            {
                tmp_vector.unpack(os[1]);
            }
            if (!tmp_vector.equals(receiver_outputs[i]))
            {
                cerr << "Incorrect OT\n";
                exit(1);
            }
        }
        os[0].reset_write_head();
        os[1].reset_write_head();
    }
}


void FakeOT::exec_base(bool new_receiver_inputs)
{
    insecure("base OTs");
    PRNG G;
    G.ReSeed();
    vector<octetStream> os(2);
    vector<BitVector> bv(2, 128);

    allocate();

    if ((ot_role & RECEIVER) && new_receiver_inputs)
    {
        for (int i = 0; i < nOT; i++)
            // Generate my receiver inputs
            receiver_inputs[i] = G.get_uchar()&1;
    }

    if (ot_role & SENDER)
        for (int i = 0; i < nOT; i++)
            for (int j = 0; j < 2; j++)
            {
                sender_inputs[i][j].randomize(G);
                sender_inputs[i][j].pack(os[0]);
            }

    send_if_ot_sender(P, os, ot_role);

    if (ot_role & RECEIVER)
        for (int i = 0; i < nOT; i++)
        {
            for (int j = 0; j < 2; j++)
                bv[j].unpack(os[1]);
            receiver_outputs[i] = bv[receiver_inputs[i].get()];
        }

    set_seeds();
}
