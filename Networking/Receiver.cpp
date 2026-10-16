/*
 * Receiver.cpp
 *
 */

#include "Receiver.h"
#include "ssl_sockets.h"
#include "Processor/OnlineOptions.h"

#include <iostream>
using namespace std;

template<class T>
void* Receiver<T>::run_thread(void* receiver)
{
    ((Receiver<T>*)receiver)->run();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_thread_stop();
#endif
    return 0;
}

CommunicationThread::CommunicationThread(int other) :
        other(other)
{
}

template<class T>
Receiver<T>::Receiver(T socket, int other) :
        CommunicationThread(other), socket(socket), thread(0)
{
    start();
}

template<class T>
Receiver<T>::~Receiver()
{
    stop();
}

template<class T>
void Receiver<T>::start()
{
    pthread_create(&thread, 0, run_thread, this);
}

template<class T>
void Receiver<T>::stop()
{
    in.stop();
    pthread_join(thread, 0);
}

void CommunicationThread::run()
{
    if (OnlineOptions::singleton.has_option("throw_exceptions"))
        run_with_error();
    else
    {
        try
        {
            run_with_error();
        }
        catch (exception& e)
        {
            fprintf(stderr, "Fatal error in communication: %s. ", e.what());
            fprintf(stderr, "This is probably because party %d"
                    " encountered a problem.\n", other);
            fail();
        }
    }
}

template<class T>
void Receiver<T>::run_with_error()
{
    octetStream* os = 0;
    while (in.pop(os))
    {
        os->reset_write_head();
#ifdef VERBOSE_SSL
        timer.start();
        RunningTimer mytimer;
#endif
        os->Receive(socket);
#ifdef VERBOSE_SSL
        cout << "receiving " << os->get_length() * 1e-6 << " MB on " << socket
                << " took " << mytimer.elapsed() << ", total "
                << timer.elapsed() << endl;
        timer.stop();
#endif
        out.push(os);
    }
}

template<class T>
void Receiver<T>::request(octetStream& os)
{
    in.push(&os);
}

template<class T>
void Receiver<T>::wait(octetStream& os)
{
    octetStream* queued = 0;
    out.pop(queued);
    if (queued != &os)
      throw runtime_error("error in receive thread");
}

template<class T>
void Receiver<T>::fail()
{
    out.push(0);
}

template class Receiver<int>;
template class Receiver<ssl_socket*>;
