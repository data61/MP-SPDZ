/*
 * PlayerSocket.h
 *
 */

#ifndef NETWORKING_PLAYERCOSOCKET_H_
#define NETWORKING_PLAYERCOSOCKET_H_

#include "Player.h"
#include "Tools/pprint.h"
#include "Processor/OnlineOptions.h"

#include <span>

#include <coproto/coproto.h>

class PlayerCoSocket;

class Awaiter
{
    PlayerBuffer buffer;
    std::error_code x;

    bool debug;

    bool send;
    PlayerCoSocket& socket;

public:
    typedef std::coroutine_handle<macoro::detail::task_promise<void, true>> handle_type;

    Awaiter(span<octet> buffer, bool send, PlayerCoSocket& socket) :
            buffer(buffer.data(), buffer.size()), send(send), socket(socket)
    {
        debug = OnlineOptions::singleton.has_option("debug_co");
    }

    bool await_ready()
    {;
        return false;
    }

    void await_suspend(handle_type h);

    tuple<std::error_code &, unsigned long &>  await_resume()
    {
        if (debug)
            cout << "resume " << buffer.size << endl;
        return tuple<std::error_code &, unsigned long &>(x, buffer.size);
    }
};

class PlayerCoSocket
{
    typedef pair<PlayerBuffer, Awaiter::handle_type> queue_type;

    class HandleThread
    {
    public:
        PlayerCoSocket& socket;
        pthread_t thread;
        WaitQueue<Awaiter::handle_type> queue;

        static void* run_thread(void* obj)
        {
            ((HandleThread*) obj)->run();
            return 0;
        }

        HandleThread(PlayerCoSocket& socket) : socket(socket)
        {
            pthread_create(&thread, 0, run_thread, this);
        }

        ~HandleThread()
        {
            queue.stop();
            pthread_join(thread, 0);
        }

        void run()
        {
            Awaiter::handle_type handle;
            while (queue.pop(handle))
            {
                handle.resume();
            }
        }
    };

    TwoPartyPlayer& P;
    pthread_t send_thread, receive_thread;
    bool debug;

    HandleThread handle_thread;

    TwoPartyPlayer* to_delete;

    static void* run_send(void* socket)
    {
        ((PlayerCoSocket*) socket)->send();
        return 0;
    }

    static void* run_receive(void* socket)
    {
        auto s = ((PlayerCoSocket*) socket);
        auto other = s->P.other_player_num();
        try
        {
            s->receive();
        }
        catch (...)
        {
            fprintf(stderr, "Fatal error in receiving from party %d\n", other);
            pthread_cancel(s->send_thread);
            exit(1);
        }
        return 0;
    }

public:
    WaitQueue<queue_type> send_queue, receive_queue;

    bool tamper;

    PlayerCoSocket(TwoPartyPlayer& P) :
            P(P), handle_thread(*this), to_delete(0), tamper(false)
    {
        debug = OnlineOptions::singleton.has_option("debug_co");
        pthread_create(&send_thread, 0, run_send, this);
        pthread_create(&receive_thread, 0, run_receive, this);
    }

    PlayerCoSocket(Player& P) :
            PlayerCoSocket(*(new VirtualTwoPartyPlayer(P, 1 - P.my_num())))
    {
        to_delete = &this->P;
    }

    ~PlayerCoSocket()
    {
        send_queue.stop();
        receive_queue.stop();
        pthread_join(send_thread, 0);
        pthread_join(receive_thread, 0);
        if (to_delete)
            delete to_delete;
    }

    template<class T>
    Awaiter send(span<octet> buffer, const T&)
    {
        if (debug)
        {
            cout << pthread_self() << " send " << buffer.size() << " on "
                    << P.get_full_player().get_id() << endl;
#if DEBUG_CO
            pprint_bytes("to send", buffer.data(), buffer.size());
#endif
        }

        Awaiter res(buffer, true, *this);
        return res;
    }

    template<class T>
    Awaiter recv(span<octet> buffer, const T&)
    {
        if (debug)
            cout << "recv " << buffer.size() << " on "
                    << P.get_full_player().get_id() << endl;

        Awaiter res(buffer, false, *this);
        return res;
    }

    void close()
    {
        if (debug)
            cout << "close" << endl;
    }

    void send()
    {
        queue_type entry;
        while (send_queue.pop(entry))
        {
            if (debug)
                printf("got to send\n");

            auto buffer = entry.first;
            while (buffer.size)
            {
#ifdef DEBUG_CO
                pprint_bytes("to send", buffer.data, buffer.size);
#endif

                auto sent = P.send(buffer, true);
                buffer.data += sent;
                buffer.size -= sent;

                if (debug)
                {
                    printf("%p %lx sent %lu left %lu\n", this, long(pthread_self()), sent, buffer.size);
#ifdef DEBUG_CO
                    pprint_bytes("sent", buffer.data - sent, sent);
                    if (sent == 4)
                        debug("content", *(word*)(buffer.data - sent));
#endif
                }
            }
            handle_thread.queue.push(entry.second);
        }
    }

    void receive()
    {
        queue_type entry;
        while (receive_queue.pop(entry))
        {
            auto buffer = entry.first;
            if (debug)
                printf("got to receive\n");

            while (buffer.size)
            {
                auto sent = P.recv(buffer, true);

                if (tamper and sent > 100)
                {
                    fprintf(stderr, "changing last bytes of %zu\n", sent);
                    buffer.data[sent - 1] ^= 1;
                }

                buffer.data += sent;
                buffer.size -= sent;

                if (debug)
                    printf("%p %lx received %lu left %lu\n", this, long(pthread_self()), sent, buffer.size);
#ifdef DEBUG_CO
                pprint_bytes("received", buffer.data - sent, sent);

                if (sent == 4)
                    debug("content", *(word*)(buffer.data - sent));
#endif
            }
            handle_thread.queue.push(entry.second);
        }
    }

    string get_id()
    {
        return P.get_full_player().get_id();
    }
};

inline void Awaiter::await_suspend(Awaiter::handle_type h)
{
    if (debug)
        cout << "suspend " << buffer.size << endl;
    if (send)
        socket.send_queue.push({buffer, h});
    else
        socket.receive_queue.push({buffer, h});
}

#endif /* NETWORKING_PLAYERCOSOCKET_H_ */
