/*
 * PlayerSocket.h
 *
 */

#ifndef NETWORKING_PLAYERCTSOCKET_H_
#define NETWORKING_PLAYERCTSOCKET_H_

#include "Player.h"
#include "Tools/Lock.h"
#include "Processor/OnlineOptions.h"

#include <cryptoTools/Network/SocketAdapter.h>

class PlayerCtSocket : public osuCrypto::SocketInterface
{
    class Pack
    {
    public:
        deque<PlayerBuffer> buffers;
        osuCrypto::io_completion_handle fn;
        size_t total;

        Pack() :
            total(0)
        {
        }

        Pack(osuCrypto::io_completion_handle& fn,
                gsl::span<boost::asio::mutable_buffer> buffers) :
                fn(fn),
                total(0)
        {
            for (auto& buffer : buffers)
            {
                auto data = (octet*) buffer.data();
                auto size = boost::asio::buffer_size(buffer);
                this->buffers.push_back({data, size});
            }
        }
    };

    TwoPartyPlayer& P;
    WaitQueue<Pack> send_packs, receive_packs;
    pthread_t send_thread, receive_thread;

    static void* run_send(void* socket)
    {
        ((PlayerCtSocket*) socket)->send();
        return 0;
    }

    static void* run_receive(void* socket)
    {
        ((PlayerCtSocket*) socket)->receive();
        return 0;
    }

    void debug(const char* msg)
    {
        (void) msg;
#ifdef DEBUG_CT
        printf("%p %lx %s\n", this, pthread_self(), msg);
#endif
    }

    void debug(const char* msg, size_t n)
    {
        (void) msg, (void) n;
#ifdef DEBUG_CT
        printf("%p %lx %s %lu\n", this, pthread_self(), msg, n);
#endif
    }

public:
    bool tamper;

    PlayerCtSocket(TwoPartyPlayer& P) :
            P(P), tamper(false)
    {
        pthread_create(&send_thread, 0, run_send, this);
        pthread_create(&receive_thread, 0, run_receive, this);
    }

    ~PlayerCtSocket()
    {
        send_packs.stop();
        receive_packs.stop();
        pthread_join(send_thread, 0);
        pthread_join(receive_thread, 0);
    }

    void async_send(gsl::span<boost::asio::mutable_buffer> buffers,
            osuCrypto::io_completion_handle&& fn) override
    {
        debug("async send");
        send_packs.push(Pack(fn, buffers));
    }

    void async_recv(gsl::span<boost::asio::mutable_buffer> buffers,
            osuCrypto::io_completion_handle&& fn) override
    {
        debug("async recv");
        receive_packs.push(Pack(fn, buffers));
    }

    void send()
    {
        Pack pack;
        while (send_packs.pop(pack))
        {
#ifdef DEBUG_CT
            debug("got to send", send_packs.size());
#endif
            while (not pack.buffers.empty())
            {
                auto& buffer = pack.buffers.front();
                auto sent = P.send(buffer, true);
                buffer.data += sent;
                buffer.size -= sent;
                pack.total += sent;
#ifdef DEBUG_CT
                printf("%p %lx sent %lu total %lu left %lu\n", this, pthread_self(), sent, pack.total, buffer.size);
                if (sent == 4)
                    debug("content", *(word*)(buffer.data - sent));
#endif
                if (buffer.size == 0)
                    pack.buffers.pop_front();
            }
            {
                boost::system::error_code ec;
                auto total = pack.total;
                auto fn = pack.fn;
                debug("send callback", total);
                fn(ec, total);
            }
        }
    }

    void receive()
    {
        Pack pack;
        while (receive_packs.pop(pack))
        {
            debug("got to receive");
            while (not pack.buffers.empty())
            {
                auto& buffer = pack.buffers.front();
                auto sent = P.recv(buffer, true);
                if (tamper and sent > 100)
                {
                    fprintf(stderr, "changing last byte of %zu\n", sent);
                    buffer.data[sent - 1] ^= 1;
                }
                buffer.data += sent;
                buffer.size -= sent;
                pack.total += sent;
#ifdef DEBUG_CT
                printf("%p %lx received %lu total %lu left %lu\n", this, pthread_self(), sent, pack.total, buffer.size);
                if (sent == 4)
                    debug("content", *(word*)(buffer.data - sent));
#endif
                if (buffer.size == 0)
                    pack.buffers.pop_front();
            }
            {
                boost::system::error_code ec;
                auto total = pack.total;
                auto fn = pack.fn;
                debug("recv callback", total);
                fn(ec, total);
            }
        }
    }
};

#endif /* NETWORKING_PLAYERCTSOCKET_H_ */
