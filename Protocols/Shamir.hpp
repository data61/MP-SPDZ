/*
 * Shamir.cpp
 *
 */

#ifndef PROTOCOLS_SHAMIR_HPP_
#define PROTOCOLS_SHAMIR_HPP_

#include "Shamir.h"
#include "ShamirInput.h"
#include "ShamirOptions.h"
#include "ShamirShare.h"
#include "Tools/benchmarking.h"

template<class T>
typename T::open_type::Scalar Shamir<T>::get_rec_factor(int i, int n)
{
    vector<int> points(n);
    for (int j = 0; j < n; j++)
        points[j] = j;
    return get_rec_factor(i, points);
}

template<class T>
typename T::open_type::Scalar Shamir<T>::get_rec_factor(int i,
        const vector<int>& points, int target)
{
    assert(find(points.begin(), points.end(), i) != points.end());
    U res = 1;
    for (auto& other : points)
    {
        if (i != other)
        {
            res *= (U(other + 1) - U(target + 1)) / (U(other + 1) - U(i + 1));
#ifdef DEBUG_SHAMIR
            cout << "res=" << res << " other+1=" << (other + 1) << " target="
                    << target << " i+1=" << (i + 1) << endl;
#endif
        }
    }
    return res;
}

template<class T>
vector<typename T::open_type::Scalar> Shamir<T>::get_rec_factors(
        const vector<int>& points, int target)
{
    vector<U> res;
    for (auto& point : points)
        res.push_back(get_rec_factor(point, points, target));
    return res;
}

template<class T>
Shamir<T>::Shamir(Player& P, int t) :
        resharing(0), random_input(0), P(P)
{
    if (not P.is_encrypted())
        insecure("unencrypted communication");
    if (t > 0)
        threshold = t;
    else
        threshold = ShamirMachine::s().threshold;
    n_mul_players = 2 * threshold + 1;
    resharing = new ShamirInput<T>(0, P);
    reset();
}

template<class T>
Shamir<T>::~Shamir()
{
    if (resharing != 0)
        delete resharing;
    if (random_input != 0)
        delete random_input;
}

template<class T>
Shamir<T> Shamir<T>::branch()
{
    return P;
}

template<class T>
int Shamir<T>::get_n_relevant_players()
{
    return threshold + 1;
}

template<class T>
void Shamir<T>::reset()
{
    for (int i = 0; i < P.num_players(); i++)
        resharing->reset(i);

    for (int i = 0; i < n_mul_players; i++)
        resharing->add_sender(i);
}

template<class T>
void Shamir<T>::init_mul()
{
    reset();
    if (rec_factor == 0 and P.my_num() < n_mul_players)
        rec_factor = get_rec_factor(P.my_num(), n_mul_players);
}

template<class T>
void Shamir<T>::prepare_mul(const T& x, const T& y, int n)
{
    (void) n;
    if (P.my_num() < n_mul_players)
        resharing->add_mine(x * y * rec_factor);
}

template<class T>
void Shamir<T>::exchange()
{
    CODE_LOCATION
    assert(resharing);
    resharing->exchange();
}

template<class T>
void Shamir<T>::start_exchange()
{
    resharing->start_exchange();
}

template<class T>
void Shamir<T>::stop_exchange()
{
    resharing->stop_exchange();
}

template<class T>
T Shamir<T>::finalize_mul(int n)
{
    (void) n;
    return finalize(n_mul_players);
}

template<class T>
T Shamir<T>::finalize(int n_relevant_players)
{
    ShamirShare<U> res = U(0);
    for (int i = 0; i < n_relevant_players; i++)
        res += resharing->finalize(i);
    return res;
}

template<class T>
void Shamir<T>::init_dotprod()
{
    init_mul();
    dotprod_share = 0;
}

template<class T>
void Shamir<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share += x * y * rec_factor;
}

template<class T>
void Shamir<T>::next_dotprod()
{
    if (P.my_num() < n_mul_players)
        resharing->add_mine(dotprod_share);
    dotprod_share = 0;
}

template<class T>
T Shamir<T>::finalize_dotprod(int)
{
    return finalize_mul();
}

template<class T>
void Shamir<T>::buffer_random()
{
    this->random = get_randoms(secure_prng, threshold);
}

template<class T>
vector<vector<typename T::open_type>>& Shamir<T>::get_hyper(int t)
{
    auto& hyper = hypers[t];
    if (int(hyper.size()) != P.num_players() - t)
    {
        get_hyper(hyper, t, P.num_players());
    }
    return hyper;
}

template<class T>
string Shamir<T>::hyper_filename(int t, int n)
{
    return PREP_DIR "/Hyper-" + to_string(t) + "-" + to_string(n) + "-"
            + to_string(T::clear::pr());
}

template<class T>
void Shamir<T>::get_hyper(vector<vector<typename T::open_type> >& hyper,
        int t, int n)
{
    assert(hyper.empty());

    try
    {
        octetStream os;
        string filename = hyper_filename(t, n);
        ifstream in(filename);
#ifdef VERBOSE_HYPER
        cerr << "Trying to load hyper-invertable matrix from " << filename << endl;
#endif
        os.input(in);
        os.get(hyper);
        if (int(hyper.size()) != n - t)
            throw exception();
#ifdef VERBOSE_HYPER
        cerr << "Loaded hyper-invertable matrix from " << filename << endl;
#endif
        return;
    }
    catch (...)
    {
#ifdef VERBOSE_HYPER
        cerr << "Failed to load hyper-invertable" << endl;
#endif
    }

    map<int, U> inverses, dividends;
    for (int i = -n; i < n; i++)
        if (i != 0)
            inverses[i] = U(i).invert();
    for (int i = 0; i < 2 * n; i++)
        dividends[i] = i;
    for (int i = 0; i < n - t; i++)
    {
        hyper.push_back({});
        for (int j = 0; j < n; j++)
        {
            hyper.back().push_back({1});
            for (int k = 0; k < n; k++)
                if (k != j)
                    hyper.back().back() *= dividends.at(n + i - k)
                    * inverses.at(j - k);
        }
    }
}

template<class T>
vector<T> Shamir<T>::get_randoms(PRNG& G, int t)
{
    CODE_LOCATION
    auto& hyper = get_hyper(t);
    if (random_input == 0)
        random_input = new ShamirInput<T>(0, P, threshold);
    auto& input = *random_input;
    input.reset_all(P);
    auto buffer_size = BaseMachine::batch_size<T>(DATA_RANDOM, this->buffer_size);
    assert(buffer_size > 0);
    if (OnlineOptions::singleton.has_option("verbose_random"))
        fprintf(stderr, "generating %d random elements\n", buffer_size);
    for (int i = 0; i < buffer_size; i += hyper.size())
        input.add_from_all(G.get<U>());
    input.exchange();
    vector<U> inputs;
    vector<T> random;
    random.reserve(buffer_size + hyper.size());
    for (int i = 0; i < buffer_size; i += hyper.size())
    {
        inputs.clear();
        for (int j = 0; j < P.num_players(); j++)
            inputs.push_back(input.finalize(j));
        for (size_t j = 0; j < hyper.size(); j++)
        {
            random.push_back({});
            for (int k = 0; k < P.num_players(); k++)
                random.back() += hyper[j][k] * inputs[k];
        }
    }
    if (OnlineOptions::singleton.has_option("verbose_random"))
        fprintf(stderr, "generated %zu random elements in %zu batches of %zu\n",
                random.size(), random.size() / hyper.size(), hyper.size());
    return random;
}

#endif
