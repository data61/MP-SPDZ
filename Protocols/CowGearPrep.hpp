/*
 * CowGearPrep.cpp
 *
 */

#include "CowGearPrep.h"
#include "FHEOffline/PairwiseMachine.h"
#include "Tools/Bundle.h"

#include "Protocols/ReplicatedPrep.hpp"
#include "FHEOffline/DataSetup.hpp"

template<class T>
PairwiseMachine* CowGearPrep<T>::pairwise_machine = 0;
template<class T>
Lock CowGearPrep<T>::lock;

template<class T>
CowGearPrep<T>::~CowGearPrep()
{
    if (pairwise_generator)
        delete pairwise_generator;
}

template<class T>
void CowGearPrep<T>::teardown()
{
    if (pairwise_machine)
        delete pairwise_machine;
}

template<class T>
void CowGearPrep<T>::basic_setup(Player& P)
{
    Timer timer;
    timer.start();
    assert(pairwise_machine == 0);
    pairwise_machine = new PairwiseMachine(P);
    auto& machine = *pairwise_machine;
    auto& setup = machine.setup<FD>();
    int lowgear_security = OnlineOptions::singleton.security_parameter;
#ifdef VERBOSE
    auto& options = CowGearOptions::singleton;
    if (T::covert)
        cerr << "Covert security parameter for key and MAC generation: "
                << options.covert_security << endl;
    cerr << "LowGear security parameter: " << lowgear_security << endl;
#endif
    secure_init(setup, P, machine, typename T::clear(), lowgear_security);
    T::clear::template init<typename FD::T>();
#ifdef VERBOSE
    cerr << T::type_string() << " parameter setup took " << timer.elapsed()
            << " seconds" << endl;
#endif
}

template<class T>
void CowGearPrep<T>::setup(Player& P, mac_key_type alphai)
{
    basic_setup(P);
    key_setup(P, alphai);
}

template<class T>
void CowGearPrep<T>::key_setup(Player& P, mac_key_type alphai)
{
    CODE_LOCATION
    Timer timer;
    timer.start();
    auto& machine = *pairwise_machine;
    auto& setup = machine.setup<FD>();
    auto& options = CowGearOptions::singleton;
    read_or_generate_secrets(setup, P, machine,
            options.covert_security, T::covert);

    // adjust mac key
    mac_key_type diff = alphai - setup.alphai;
    setup.set_alphai(alphai);
    Bundle<octetStream> bundle(P);
    diff.pack(bundle.mine);
    P.unchecked_broadcast(bundle);
    for (int i = 0; i < P.num_players(); i++)
    {
        Plaintext_<FD> mess(setup.FieldD);
        mess.assign_constant(bundle[i].get<mac_key_type>(), Polynomial);
        machine.enc_alphas[i] += mess;
    }

    // generate minimal number of items
    machine.nTriplesPerThread = 1;
#ifdef VERBOSE
    cerr << T::type_string() << " key setup took " << timer.elapsed()
            << " seconds" << endl;
#endif
}

template<class T>
PairwiseGenerator<typename T::clear::FD>& CowGearPrep<T>::get_generator()
{
    auto& proc = this->proc;
    assert(proc != 0);
    lock.lock();
    if (pairwise_machine == 0 or pairwise_machine->enc_alphas.empty())
    {
        PlainPlayer P(proc->P.N, "CowGear" + T::type_string());
        if (pairwise_machine == 0)
            setup(P, proc->MC.get_alphai());
        else
            key_setup(P, proc->MC.get_alphai());
        BaseMachine::add_one_off(P.total_comm());
    }
    lock.unlock();
    if (pairwise_generator == 0)
    {
        auto& machine = *pairwise_machine;
        typedef typename T::open_type::FD FD;
        pairwise_generator = new PairwiseGenerator<FD>(0, machine, &proc->P);
    }
    return *pairwise_generator;
}

template<class T>
void CowGearPrep<T>::buffer_triples()
{
    CODE_LOCATION
    auto& generator = get_generator();
    generator.run();
    auto& producer = generator.producer;
    assert(not producer.triples.empty());
    for (auto& triple : producer.triples)
        this->triples.push_back({{triple[0], triple[1], triple[2]}});
#ifdef VERBOSE_HE
    cerr << "generated " << producer.triples.size() << " triples, now got "
            << this->triples.size() << endl;
#endif
}

template<class T>
void CowGearPrep<T>::buffer_inputs(int player)
{
    CODE_LOCATION
    auto& generator = get_generator();
    generator.generate_inputs(player);
    assert(not generator.inputs.empty());
    this->inputs.resize(this->proc->P.num_players());
    for (auto& input : generator.inputs)
        this->inputs[player].push_back(input);
#ifdef VERBOSE_HE
    cerr << "generated " << generator.inputs.size() << " inputs, now got "
            << this->inputs[player].size() << endl;
#endif
}

template<class T>
inline void CowGearPrep<T>::buffer_bits()
{
    buffer_bits<0>(T::clear::characteristic_two);
}

template<class T>
template<int>
void CowGearPrep<T>::buffer_bits(false_type)
{
    buffer_bits_from_squares(*this);
}

template<class T>
template<int>
void CowGearPrep<T>::buffer_bits(true_type)
{
    this->buffer_bits_without_check();
    assert(not this->bits.empty());
    for (auto& bit : this->bits)
        bit.force_to_bit();
}
