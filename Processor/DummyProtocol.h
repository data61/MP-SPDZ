/*
 * DummyProtocol.h
 *
 */

#ifndef PROCESSOR_DUMMYPROTOCOL_H_
#define PROCESSOR_DUMMYPROTOCOL_H_

#include <vector>
using namespace std;

#include "Math/BitVec.h"
#include "Data_Files.h"
#include "Protocols/Replicated.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"

class Player;
class DataPositions;
class ThreadQueues;

template<class T> class SubProcessor;

namespace GC
{
class NoShare;

template<class T> class ShareThread;
}

template<class T>
class DummyMC : public MAC_Check_Base<T>
{
public:
    DummyMC()
    {
    }

    template<class U>
    DummyMC(U, int = 0, int = 0)
    {
    }

    void exchange(const Player&)
    {
        throw not_implemented();
    }
    void CheckFor(const typename T::open_type&, const vector<T>&, const Player&)
    {
    }

    DummyMC<typename T::part_type>& get_part_MC()
    {
        return *new DummyMC<typename T::part_type>;
    }

    typename T::mac_key_type get_alphai()
    {
        throw not_implemented();
        return {};
    }

    int number()
    {
        return 0;
    }
};

template<class T>
class DummyProtocol : public ProtocolBase<T>
{
public:
    Player& P;
    int counter;

    static int get_n_relevant_players()
    {
        throw not_implemented();
    }

    static void multiply(vector<T>, vector<pair<T, T>>, int, int, SubProcessor<T>)
    {
    }

    DummyProtocol(Player& P) :
            P(P)
    {
    }

    void init_mul()
    {
    }
    void prepare_mul(const T&, const T&, int = 0)
    {
        throw not_implemented();
    }
    void exchange()
    {
        throw not_implemented();
    }
    T finalize_mul(int = 0)
    {
        throw not_implemented();
        return {};
    }
    void check()
    {
    }
};

template<class T>
class DummyLivePrep : public BufferPrep<T>
{
public:
    static const bool homomorphic = true;

    static void basic_setup(Player&)
    {
    }
    static void teardown()
    {
    }

    static void fail()
    {
        throw runtime_error(
                "live preprocessing not implemented for " + T::type_string());
    }

    static bool bits_from_dabits()
    {
        return false;
    }

    DummyLivePrep(DataPositions& usage, GC::ShareThread<T>&) :
            BufferPrep<T>(usage)
    {
    }
    DummyLivePrep(DataPositions& usage, bool = true) :
            BufferPrep<T>(usage)
    {
    }

    DummyLivePrep(SubProcessor<T>*, DataPositions& usage) :
            BufferPrep<T>(usage)
    {
    }

    void set_protocol(typename T::Protocol&)
    {
    }
    void get_three_no_count(Dtype, T&, T&, T&)
    {
        fail();
    }
    void get_two_no_count(Dtype, T&, T&)
    {
        fail();
    }
    void get_one_no_count(Dtype, T&)
    {
        fail();
    }
    void get_input_no_count(T&, typename T::open_type&, int)
    {
        fail();
    }
    void get_no_count(StackedVector<T>&, DataTag, const ArgVector&, int)
    {
        fail();
    }
    void buffer_personal_triples(vector<array<T, 3>>&, size_t, size_t)
    {
        fail();
    }
    void buffer_personal_triples(size_t, ThreadQueues*)
    {
        fail();
    }
    void shrink_to_fit()
    {
        fail();
    }
};

template<class V>
class NotImplementedInput
{
public:
    template<class T, class U>
    NotImplementedInput(const T& proc, const U& MC)
    {
        (void) proc, (void) MC;
    }
    template<class T, class U, class W>
    NotImplementedInput(const T&, const U&, const W&)
    {
    }
    template<class T>
    NotImplementedInput(const T&)
    {
    }
    void start(int n, ArgVector regs)
    {
        (void) n, (void) regs;
        throw not_implemented();
    }
    void stop(int n, ArgVector regs)
    {
        (void) n, (void) regs;
        throw not_implemented();
    }
    void start(int n, int m)
    {
        (void) n, (void) m;
        throw not_implemented();
    }
    void stop(int n, int m)
    {
        (void) n, (void) m;
        throw not_implemented();
    }
    template<class T>
    static void input(SubProcessor<V>& proc, ArgVector regs, int)
    {
        (void) proc, (void) regs;
        throw not_implemented();
    }
    static void input_mixed(SubProcessor<V>, ArgVector, int, int)
    {
    }
    void reset_all(Player& P)
    {
        (void) P;
        throw not_implemented();
    }
    template<class U>
    void add_mine(U a, int b = 0)
    {
        (void) a, (void) b;
        throw not_implemented();
    }
    void add_other(int)
    {
        throw not_implemented();
    }
    template<class U>
    void add_from_all(U)
    {
        throw not_implemented();
    }
    void exchange()
    {
        throw not_implemented();
    }
    V finalize(int a, int b = 0)
    {
        (void) a, (void) b;
        throw not_implemented();
    }
    static void raw_input(SubProcessor<V>&, ArgVector, int)
    {
        throw not_implemented();
    }
    static void input_mixed(SubProcessor<V>&, ArgVector, int, bool)
    {
        throw not_implemented();
    }
};

class NotImplementedOutput
{
public:
    template<class T>
    NotImplementedOutput(SubProcessor<T>& proc)
    {
        (void) proc;
    }

    void start(int player, int target, int source)
    {
        (void) player, (void) target, (void) source;
        throw not_implemented();
    }
    void stop(int player, int source, int)
    {
        (void) player, (void) source;
    }
};

#endif /* PROCESSOR_DUMMYPROTOCOL_H_ */
