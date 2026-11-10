/*
 * SimpleThread.h
 *
 */

#ifndef FHEOFFLINE_SIMPLEGENERATOR_H_
#define FHEOFFLINE_SIMPLEGENERATOR_H_

#include "Networking/CryptoPlayer.h"
#include "FHEOffline/SimpleEncCommit.h"
#include "FHEOffline/DataSetup.h"
#include "FHEOffline/Producer.h"
#include "FHEOffline/SimpleDistDecrypt.h"
#include "Processor/Data_Files.h"

class SimpleMachine;
class MultiplicativeMachineParams;

class GeneratorBase
{
    Player* player;

protected:
    int thread_num;

public:
    Player& P;
    pthread_t thread;
    long long total;

    map<string, Timer> timers;

    GeneratorBase(int thread_num, const Names& N, Player* player = 0) :
            player(player ? 0 : new CryptoPlayer(N, to_string(thread_num))),
            thread_num(thread_num),
            P(player ? *player : *this->player), thread(0), total(0)
    {
    }
    virtual ~GeneratorBase()
    {
        if (player)
            delete player;
    }
    virtual void run() = 0;
    virtual size_t report_size(ReportType type) = 0;
    virtual void report_size(ReportType type, MemoryUsage& res) = 0;
    virtual size_t report_sent() = 0;

    int get_thread_num() const { return thread_num; }
};

template <template <class FD> class T, class FD>
class SimpleGenerator : public GeneratorBase
{
    const PartSetup<FD>& setup;
    const MultiplicativeMachineParams& machine;

    size_t volatile_memory;

public:
    SimpleDistDecrypt<FD> dd;
    T<FD> EC;
    Producer<FD>* producer;

    SimpleGenerator(const Names& N, const PartSetup<FD>& setup,
            const MultiplicativeMachineParams& machine, int thread_num,
            Dtype data_type = DATA_TRIPLE, Player* player = 0);
    ~SimpleGenerator();

    void run() { run(true); }
    void run(bool exhaust);
    size_t report_size(ReportType type);
    void report_size(ReportType type, MemoryUsage& res);
    size_t report_sent() { return P.total_comm().sent; }
};

#endif /* FHEOFFLINE_SIMPLEGENERATOR_H_ */
