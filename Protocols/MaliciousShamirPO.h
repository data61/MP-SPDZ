/*
 * MaliciousShamirPO.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSSHAMIRPO_H_
#define PROTOCOLS_MALICIOUSSHAMIRPO_H_

template<class T>
class MaliciousShamirPO
{
protected:
    Player& P;

    octetStream to_send;
    vector<octetStream> to_receive;

    vector<typename T::open_type> shares;
    typename T::Direct_MC MC;

    int n_relevant_players();

public:
    MaliciousShamirPO(Player& P);

    void prepare_sending(const T& secret, int player);
    void send(int player);
    void receive();
    typename T::clear finalize(const T& secret);
};

#endif /* PROTOCOLS_MALICIOUSSHAMIRPO_H_ */
