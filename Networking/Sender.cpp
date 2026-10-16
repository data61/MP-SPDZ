/*
 * Sender.cpp
 *
 */

#include "Sender.h"
#include "ssl_sockets.h"

template<class T>
void* Sender<T>::run_thread(void* sender)
{
    ((Sender<T>*)sender)->run();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_thread_stop();
#endif
    return 0;
}

template<class T>
Sender<T>::Sender(T socket, int other) :
        CommunicationThread(other), socket(socket), thread(0)
{
    start();
}

template<class T>
Sender<T>::~Sender()
{
    stop();
}

template<class T>
void Sender<T>::start()
{
    pthread_create(&thread, 0, run_thread, this);
}

template<class T>
void Sender<T>::stop()
{
    in.stop();
    pthread_join(thread, 0);
}

template<class T>
void Sender<T>::run_with_error()
{
    const octetStream* os = 0;
    while (in.pop(os))
    {
#ifdef VERBOSE_SSL
        timer.start();
        RunningTimer mytimer;
#endif
        os->Send(socket);
#ifdef VERBOSE_SSL
        cout << "sending " << os->get_length() * 1e-6 << " MB on " << socket
                << " took " << mytimer.elapsed() << ", total "
                << timer.elapsed() << endl;
        timer.stop();
#endif
        out.push(os);
    }
}

template<class T>
void Sender<T>::request(const octetStream& os)
{
    in.push(&os);
}

template<class T>
void Sender<T>::wait(const octetStream& os)
{
    const octetStream* queued = 0;
    out.pop(queued);
    if (queued != &os)
      throw runtime_error("error in send thread");
}

template<class T>
void Sender<T>::fail()
{
    out.push(0);
}

template class Sender<int>;
template class Sender<ssl_socket*>;
