/*
 * Atla.h
 *
 */

#ifndef PROTOCOLS_ATLAS_H_
#define PROTOCOLS_ATLAS_H_

#include "Replicated.h"

#include "Tools/Bundle.h"

/**
 * ATLAS protocol (simple version).
 * Uses double sharings to reduce degree of Shamir secret sharing.
 */
template<class T>
class Atlas : public ProtocolBase<T>
{
    Shamir<T> shamir, shamir2;

    Bundle<octetStream> oss, oss2;
    PointerVector<T> masks;

    vector<array<T, 2>> double_sharings;

    vector<typename T::open_type> reconstruction;

    int next_king, base_king;

    ShamirInput<T> resharing;

    typename T::open_type dotprod_share;

    array<T, 2> get_double_sharing();

public:
    static const bool uses_triples = false;

    Player& P;

    Atlas(Player& P) :
            shamir(P), shamir2(P, 2 * ShamirMachine::s().threshold), oss(P),
            oss2(P), next_king(0), base_king(0), resharing(0, P), P(P)
    {
        this->buffer_size = 0;
    }

    ~Atlas();

    Atlas branch()
    {
        return P;
    }

    int get_n_relevant_players()
    {
        return shamir.get_n_relevant_players();
    }

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void prepare(const typename T::open_type& product);
    void exchange();
    T finalize_mul(int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    T get_random();
};

#endif /* PROTOCOLS_ATLAS_H_ */
