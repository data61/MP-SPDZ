/*
 * ReplicatedInput.h
 *
 */

#ifndef PROTOCOLS_REPLICATEDINPUT_H_
#define PROTOCOLS_REPLICATEDINPUT_H_

#include <span>

#include "Processor/Input.h"
#include "Processor/Processor.h"
#include "Replicated.h"

template<class T> class Beaver;
template<class T> class AstraOnlineBase;
template<class T> class AstraPrepProtocol;

/**
 * Base class for input protocols without preprocessing
 */
template <class T>
class PrepLessInput : public InputBase<T>
{
protected:
    IteratorVector<T> shares;

public:
    PrepLessInput(SubProcessor<T>* proc) :
            InputBase<T>(proc ? proc->Proc : 0) {}
    virtual ~PrepLessInput() {}

    virtual void reset(int player) = 0;
    virtual void add_mine(const typename T::open_type& input,
            int n_bits = -1) = 0;
    virtual void add_other(int player, int n_bits = - 1) = 0;
    virtual void finalize_other(int player, T& target, octetStream& o,
            int n_bits = -1) = 0;

    T finalize_mine() final;
};

/**
 * Replicated three-party input protocol
 */
template <class T>
class ReplicatedInput : public PrepLessInput<T>
{
    SubProcessor<T>* proc;
    Player& P;
    vector<octetStream> os;
    SeededPRNG secure_prng;
    ReplicatedBase protocol;
    vector<bool> expect;
    octetStream dest;
    octetStream* to_send;

public:
    ReplicatedInput(SubProcessor<T>& proc) :
            ReplicatedInput(&proc, proc.P)
    {
    }
    ReplicatedInput(SubProcessor<T>& proc, ReplicatedMC<T>& MC) :
            ReplicatedInput(proc)
    {
        (void) MC;
    }
    ReplicatedInput(typename T::MAC_Check& MC, Preprocessing<T>& prep, Player& P,
            typename T::Protocol* = 0) :
            ReplicatedInput(P)
    {
        (void) MC, (void) prep;
    }
    ReplicatedInput(Player& P) :
            ReplicatedInput(0, P)
    {
    }
    ReplicatedInput(SubProcessor<T>* proc, const ReplicatedBase& protocol) :
            PrepLessInput<T>(proc), proc(proc), P(protocol.P),
            protocol(protocol.branch()), to_send(0)
    {
        assert(T::vector_length == 2);
        expect.resize(P.num_players());
        this->reset_all(P);
    }
    template<class U>
    ReplicatedInput(SubProcessor<T>*, const Beaver<U>& protocol) :
            ReplicatedInput(protocol.P)
    {
        throw runtime_error("should not be called");
    }
    template<class U>
    ReplicatedInput(SubProcessor<T>*, const AstraOnlineBase<U>& protocol) :
            ReplicatedInput(protocol.P)
    {
        throw runtime_error("should not be called");
    }
    template<class U>
    ReplicatedInput(SubProcessor<T>* proc, const AstraPrepProtocol<U>& protocol);

    void reset(int player);
    void prepare(size_t n_inputs);
    void add_mine(const typename T::open_type& input, int n_bits = -1) final;
    void add_mine_prepared(T& share, const typename T::open_type& input);
    void add_other(int player, int n_bits = -1);
    void send_mine();
    void exchange();
    void finalize_other(int player, T& target, octetStream& o, int n_bits = -1);
    T finalize_offset(int offset);

    void add_mine(const span<T>& shares,
            const span<const typename T::clear>& inputs);
    void finalize_vector_sum(const vector<int>& players, const span<T>& target);

    double randomness_time()
    {
        return protocol.randomness_time();
    }
};

#endif /* PROTOCOLS_REPLICATEDINPUT_H_ */
