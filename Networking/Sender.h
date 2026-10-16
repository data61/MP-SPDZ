/*
 * Sender.h
 *
 */

#ifndef NETWORKING_SENDER_H_
#define NETWORKING_SENDER_H_

#include <pthread.h>

#include "Receiver.h"

#include "Tools/octetStream.h"
#include "Tools/WaitQueue.h"
#include "Tools/time-func.h"

template<class T>
class Sender : CommunicationThread
{
    T socket;
    WaitQueue<const octetStream*> in;
    WaitQueue<const octetStream*> out;
    pthread_t thread;

    static void* run_thread(void* sender);

    // prevent copying
    Sender(const Sender& other);

    void start();
    void stop();
    void run_with_error();
    void fail();

public:
    Timer timer;

    Sender(T socket, int other);
    ~Sender();

    T get_socket()
    {
        return socket;
    }

    void request(const octetStream& os);
    void wait(const octetStream& os);
};

#endif /* NETWORKING_SENDER_H_ */
