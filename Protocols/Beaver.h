/*
 * Beaver.h
 *
 */

#ifndef PROTOCOLS_BEAVER_H_
#define PROTOCOLS_BEAVER_H_

#include <vector>
#include <array>
using namespace std;

#include "Replicated.h"
#include "Processor/Data_Files.h"
#include "Tools/CodeLocations.h"

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;

/**
 * Beaver multiplication
 */
template<class T>
class Beaver : public ProtocolBase<T>
{
    typedef typename T::open_type open_type;

protected:
    vector<T> shares;
    vector<typename T::open_type> opened;
    vector<array<T, 3>> triples;
    vector<int> lengths;
    vector<array<T, 2>> multiplicands;
    PointerVector<T> results;
    typename vector<typename T::open_type>::iterator it;
    typename vector<array<T, 3>>::iterator triple;
    Preprocessing<T>* prep;
    typename T::MAC_Check* MC;
    bool fast_mode;

    void pre_fast_exchange();
    void post_fast_exchange();

    T finalize(array<T, 3>& triple, const open_type& eps,
            const open_type& delta, int my_num);

public:
    static const bool uses_triples = true;

    Player& P;

    Beaver(Player& P) : prep(0), MC(0), fast_mode(false), P(P) {}

    typename T::Protocol branch();

    void set_fast_mode(bool change);

    void init(Preprocessing<T>& prep, typename T::MAC_Check& MC);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare_mul_fast(const T& x, const T& y);
    void exchange();
    T finalize_mul(int n = -1);
    T finalize_mul_fast();

    void check();

    void start_exchange();
    void stop_exchange();

    int get_n_relevant_players() { return 1 + T::threshold(P.num_players()); }

    int get_buffer_size() { return triples.size(); }
};

#endif /* PROTOCOLS_BEAVER_H_ */
