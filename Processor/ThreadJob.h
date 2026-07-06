/*
 * ThreadJob.h
 *
 */

#ifndef PROCESSOR_THREADJOB_H_
#define PROCESSOR_THREADJOB_H_

#include "Data_Files.h"
#include "Math/modp.h"

enum ThreadJobType
{
    TAPE_JOB,
    BITADD_JOB,
    DABIT_JOB,
    MULT_JOB,
    EDABIT_JOB,
    PERSONAL_JOB,
    SANITIZE_JOB,
    EDABIT_SACRIFICE_JOB,
    PERSONAL_TRIPLE_JOB,
    TRIPLE_SACRIFICE_JOB,
    CHECK_JOB,
    FFT_JOB,
    CIPHER_PLAIN_MULT_JOB,
    MATRX_RAND_MULT_JOB,
    SHUFFLE_JOB,
    NO_JOB
};

class ThreadJob
{
public:
    ThreadJobType type;

    int prognum;

    // rownums for triples, bits, squares, and inverses etc
    DataPositions pos;
    // Integer arg (optional)
    int arg;

    void* output;
    void* output2;
    const void* input;
    int begin, end, length;
    const void* supply;

    ThreadJob() :
            type(NO_JOB), prognum(0), arg(0), output(0), output2(0), input(0),
            begin(0), end(0), length(0), supply(0)
    {
    }

    ThreadJob(int prognum, int arg = 0) :
            ThreadJob()
    {
        type = TAPE_JOB;
        this->prognum = prognum;
        this->arg = arg;
    }

    ThreadJob(DataPositions pos) :
            ThreadJob()
    {
        this->pos = pos;
    }

    ThreadJob(int prognum, int arg, DataPositions pos) :
            ThreadJob(prognum, arg)
    {
        this->pos = pos;
    }

    ThreadJob(void* sums, const void* summands, int length, int player) :
            ThreadJob()
    {
        type = BITADD_JOB;
        output = sums;
        input = summands;
        this->length = length;
        arg = player;
    }

    ThreadJob(void* dabits) :
            ThreadJob()
    {
        type = DABIT_JOB;
        output = dabits;
    }

    ThreadJob(void* products, const void* multiplicands) :
            ThreadJob()
    {
        type = MULT_JOB;
        output = products;
        input = multiplicands;
    }

    ThreadJob(int n_bits, void* sums, void* bits) :
            ThreadJob()
    {
        type = EDABIT_JOB;
        length = n_bits;
        output = sums;
        output2 = bits;
    }

    ThreadJob(int n_bits, void* sums, void* bits, int input_player) :
            ThreadJob()
    {
        type = PERSONAL_JOB;
        length = n_bits;
        output = sums;
        output2 = bits;
        arg = input_player;
    }
};

class SanitizeJob : public ThreadJob
{
public:
    SanitizeJob(void* edabits, int n_bits, int player)
    {
        type = SANITIZE_JOB;
        output = edabits;
        length = n_bits;
        arg = player;
    }
};

class EdabitSacrificeJob : public ThreadJob
{
public:
    EdabitSacrificeJob(void* edabits, int n_bits, bool strict, int player)
    {
        type = EDABIT_SACRIFICE_JOB;
        output = edabits;
        length = n_bits;
        arg = player;
        prognum = strict;
    }
};

class PersonalTripleJob : public ThreadJob
{
public:
    PersonalTripleJob(void* triples, int player)
    {
        type = PERSONAL_TRIPLE_JOB;
        output = triples;
        arg = player;
    }
};

class TripleSacrificeJob : public ThreadJob
{
public:
    TripleSacrificeJob(void* triples, const void* check_triples)
    {
        type = TRIPLE_SACRIFICE_JOB;
        output = triples;
        input = check_triples;
    }
};

class CheckJob : public ThreadJob
{
public:
    CheckJob()
    {
        type = CHECK_JOB;
    }
};

class FftJob : public ThreadJob
{
public:
    FftJob(vector<modp>& ioput, vector<modp>& alpha2, int m, const Zp_Data& PrD)
    {
        type = FFT_JOB;
        output = &ioput;
        input = &alpha2;
        length = m;
        supply = &PrD;
    }
};

template<class T> class ShuffleTuple;

class ShuffleJob : public ThreadJob
{
public:
    template<class T>
    ShuffleJob(typename T::Protocol::Shuffler* shuffler, StackedVector<T>& a,
            vector<ShuffleTuple<T>>& shuffles)
    {
        type = SHUFFLE_JOB;
        output = shuffler;
        output2 = &a;
        supply = &shuffles;
    }
};

#endif /* PROCESSOR_THREADJOB_H_ */
