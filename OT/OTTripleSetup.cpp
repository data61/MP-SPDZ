#include "OTTripleSetup.h"

void* run_ot(void* job)
{
    ((OTTripleSetup::SetupJob*)job)->run();
    return 0;
}

void OTTripleSetup::setup()
{
    timeval baseOTstart, baseOTend;
    gettimeofday(&baseOTstart, NULL);

    G.ReSeed();
    for (int i = 0; i < nbase; i++)
    {
        base_receiver_inputs[i] = G.get_uchar() & 1;
    }
    //baseReceiverInput.randomize(G);

    vector<SetupJob> threads;
    for (int i = 0; i < nparties - 1; i++)
        threads.push_back({*this, i});
    for (int i = 0; i < nparties - 1; i++)
        pthread_create(&threads[i].thread, 0, run_ot, &threads[i]);
    for (int i = 0; i < nparties - 1; i++)
        pthread_join(threads[i].thread, 0);
    gettimeofday(&baseOTend, NULL);
#ifdef VERBOSE_BASEOT
    double basetime = timeval_diff(&baseOTstart, &baseOTend);
    cout << "\t\tBaseTime: " << basetime/1000000 << endl << flush;
#endif

    for (size_t i = 0; i < baseOTs.size(); i++)
    {
        delete baseOTs[i];
    }

    // Receiver send something to force synchronization
    // (since Sender finishes baseOTs before Receiver)
}

void OTTripleSetup::run(int i)
{
    baseOTs[i]->set_receiver_inputs(base_receiver_inputs);
    baseOTs[i]->exec_base(false);
    baseSenderInputs[i] = baseOTs[i]->sender_inputs;
    baseReceiverOutputs[i] = baseOTs[i]->receiver_outputs;
}

void OTTripleSetup::close_connections()
{
    for (size_t i = 0; i < players.size(); i++)
    {
        delete players[i];
    }
}

OTTripleSetup OTTripleSetup::get_fresh()
{
    OTTripleSetup res = *this;
    for (int i = 0; i < nparties - 1; i++)
    {
        BaseOT bot(nbase, 0);
        bot.sender_inputs = baseSenderInputs[i];
        bot.receiver_outputs = baseReceiverOutputs[i];
        bot.set_seeds();
        bot.extend_length();
        baseSenderInputs[i] = bot.sender_inputs;
        baseReceiverOutputs[i] = bot.receiver_outputs;
        bot.extend_length();
        res.baseSenderInputs[i] = bot.sender_inputs;
        res.baseReceiverOutputs[i] = bot.receiver_outputs;
    }
    return res;
}
