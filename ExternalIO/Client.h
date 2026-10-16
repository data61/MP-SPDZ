/*
 * Client.h
 *
 */

#ifndef EXTERNALIO_CLIENT_H_
#define EXTERNALIO_CLIENT_H_

#include "Networking/ssl_sockets.h"

#ifdef NO_CLIENT_TLS
class client_ctx
{
public:
    client_ctx(string)
    {
    }
};

class client_socket
{
public:
    int socket;

    client_socket(ssl_service&,
            client_ctx&, int plaintext_socket, string,
            string, bool) : socket(plaintext_socket)
    {
    }

    ~client_socket()
    {
        close(socket);
    }
};

inline void send(client_socket* socket, octet* data, size_t len)
{
    send(socket->socket, data, len);
}

inline void receive(client_socket* socket, octet* data, size_t len)
{
    receive(socket->socket, data, len);
}

#else

typedef ssl_ctx client_ctx;
typedef ssl_socket client_socket;

#endif

/**
 * Client-side interface
 */
class Client
{
    vector<int> plain_sockets;
    client_ctx ctx;
    ssl_service io_service;

public:
    /**
     * Sockets for cleartext communication
     */
    vector<client_socket*> sockets;

    /**
     * Specification of computation domain
     */
    octetStream specification;

    /**
     * Start a new set of connections to computing parties.
     * @param hostnames location of computing parties
     * @param port_base port base
     * @param my_client_id client identifier
     */
    Client(const vector<string>& hostnames, int port_base, int my_client_id);
    ~Client();

    /**
     * Securely input private values.
     * @param values vector of integer-like values
     */
    template<class T>
    void send_private_inputs(const vector<T>& values);

    /**
     * Securely receive output values.
     * @param n number of values
     * @returns vector of integer-like values
     */
    template<class T, class U = T>
    vector<U> receive_outputs(int n);
};

#endif /* EXTERNALIO_CLIENT_H_ */
