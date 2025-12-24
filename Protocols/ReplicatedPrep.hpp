/*
 * ReplicatedPrep.cpp
 *
 */

#ifndef PROTOCOlS_REPLICATEDPREP_HPP_
#define PROTOCOlS_REPLICATEDPREP_HPP_

#include "ReplicatedPrep.h"

#include "BufferScope.h"
#include "SemiRep3Prep.h"
#include "DabitSacrifice.h"
#include "Spdz2kPrep.h"
#include "GC/BitAdder.h"
#include "Processor/OnlineOptions.h"
#include "Protocols/Rep3Share.h"

#include "MaliciousRingPrep.hpp"
#include "ShuffleSacrifice.hpp"
#include "GC/ShareThread.hpp"
#include "GC/BitAdder.hpp"

class InScope
{
    bool& variable;
    bool backup;
    TimerWithComm& timer;
    bool running;
    Player* P;

public:
    template<class T>
    InScope(bool& variable, bool value, BufferPrep<T>& prep) :
            variable(variable), timer(prep.prep_timer),
            P(prep.proc ? &prep.proc->P : (prep.P ? prep.P : 0))
    {
        backup = variable;
        variable = value;
        running = timer.is_running();
        if (not running)
        {
            if (P)
                timer.start(P->total_comm());
            else
                timer.start({});
        }
    }
    ~InScope()
    {
        variable = backup;
        if (not running)
        {
            if (P)
                timer.stop(P->total_comm());
            else
                timer.stop({});
        }
    }
};

template<class T>
BufferPrep<T>::BufferPrep(DataPositions& usage) :
        Preprocessing<T>(usage), n_bit_rounds(0),
		proc(0), P(0)
{
}

template<class T>
BufferPrep<T>::~BufferPrep()
{
    string type_string = T::type_string();

#ifdef VERBOSE
    if (n_bit_rounds > 0)
        cerr << n_bit_rounds << " rounds of random " << type_string
                << " bit generation" << endl;
#endif

    auto field_type = T::clear::field_type();
    auto& my_usage = this->usage.files.at(field_type);

    this->print_left("triples", triples.size() * T::default_length, type_string,
            this->usage.files.at(T::clear::field_type()).at(DATA_TRIPLE)
                    * T::default_length,
            T::LivePrep::homomorphic or T::expensive_triples);

    size_t used_bits = my_usage.at(DATA_BIT);
    size_t used_dabits = my_usage.at(DATA_DABIT);
    if (T::LivePrep::bits_from_dabits())
    {
        if (field_type == DATA_INT and not T::has_mac)
            // add dabits with computation modulo power of two but without MAC
            used_dabits += my_usage.at(DATA_BIT);
    }
    else
        used_bits += used_dabits;

    this->print_left("bits", bits.size(), type_string, used_bits);
    this->print_left("dabits", dabits.size(), type_string, used_dabits);

#define X(KIND, TYPE) \
    this->print_left(#KIND, KIND.size(), type_string, \
            this->usage.files.at(T::clear::field_type()).at(TYPE));
    X(squares, DATA_SQUARE)
    X(inverses, DATA_INVERSE)
#undef X

    for (auto& x : this->edabits)
    {
        this->print_left_edabits(x.second.size(), x.second[0].size(),
                x.first.first, x.first.second, this->usage.edabits[x.first],
                T::malicious);
    }

#ifdef VERBOSE
    if (OnlineOptions::singleton.verbose and this->prep_timer.elapsed())
    {
        cerr << type_string << " preprocessing time = "
                << this->prep_timer.elapsed();
        if (this->prep_timer.mb_sent())
            cerr << " (" << this->prep_timer.mb_sent() << " MB)";
        cerr << endl;
    }
#endif
}

template<class T>
BitPrep<T>::BitPrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage), base_player(0), protocol(0)
{
    this->proc = proc;
}

template<class T>
RingPrep<T>::RingPrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage), BitPrep<T>(proc, usage), bit_part_proc(0)
{
}

template<class T>
RingPrep<T>::~RingPrep()
{
    if (bit_part_proc)
        delete bit_part_proc;
}

template<class T>
void BitPrep<T>::set_protocol(typename T::Protocol& protocol)
{
    if (not this->protocol)
        this->protocol = new typename T::Protocol(protocol.branch());
    this->protocol->init_mul();
    auto proc = this->proc;
    if (proc and proc->Proc)
        this->base_player = proc->Proc->thread_num;
}

template<class T>
BitPrep<T>::~BitPrep()
{
    if (protocol)
    {
        protocol->check();
        delete protocol;
    }
}

template<class T>
void BufferPrep<T>::clear()
{
    triples.clear();
    inverses.clear();
    bits.clear();
    squares.clear();
    inputs.clear();
}

template<class T>
void ReplicatedRingPrep<T>::buffer_triples()
{
    assert(this->protocol != 0);
    try
    {
        // independent instance to avoid conflicts
        typename T::Protocol protocol(this->protocol->branch());
        generate_triples(this->triples, BaseMachine::batch_size<T>(DATA_TRIPLE),
                &protocol);
    }
    catch (not_implemented&)
    {
        generate_triples(this->triples, BaseMachine::batch_size<T>(DATA_TRIPLE),
                this->protocol);
    }
}

template<class T, class U>
void generate_triples(vector<array<T, 3>>& triples, int n_triples,
        U* protocol, int n_bits = -1)
{
    protocol->init_mul();
    generate_triples_initialized(triples, n_triples, protocol, n_bits);
}

template<class T, class U>
void generate_triples_initialized(vector<array<T, 3>>& triples, int n_triples,
        U* protocol, int n_bits = -1)
{
    CODE_LOCATION
    triples.resize(n_triples);
    BufferScope scope(*protocol, 2 * triples.size());
    for (size_t i = 0; i < triples.size(); i++)
    {
        auto& triple = triples[i];
        triple[0] = protocol->get_random();
        triple[1] = protocol->get_random();
        protocol->prepare_mul(triple[0], triple[1], n_bits);
    }
    protocol->exchange();
    for (size_t i = 0; i < triples.size(); i++)
        triples[i][2] = protocol->finalize_mul(n_bits);
}

template<class T>
void BufferPrep<T>::get_three_no_count(Dtype dtype, T& a, T& b, T& c)
{
    if (dtype != DATA_TRIPLE)
        throw not_implemented();

    if (triples.empty())
    {
        if (OnlineOptions::singleton.has_option("verbose_triples"))
            fprintf(stderr, "out of %s triples\n", T::type_string().c_str());
        InScope in_scope(this->do_count, false, *this);
        buffer_triples();
        assert(not triples.empty());
    }

    a = triples.back()[0];
    b = triples.back()[1];
    c = triples.back()[2];
    triples.pop_back();
}

template<class T>
void BitPrep<T>::buffer_squares()
{
    CODE_LOCATION
    auto proc = this->proc;
    auto buffer_size = BaseMachine::batch_size<T>(DATA_SQUARE,
            this->buffer_size);
    BufferScope scope(*this, buffer_size);
    assert(proc != 0);
    vector<T> a_plus_b(buffer_size), as(buffer_size), cs(buffer_size);
    T b;
    for (int i = 0; i < buffer_size; i++)
    {
        this->get_three_no_count(DATA_TRIPLE, as[i], b, cs[i]);
        a_plus_b[i] = as[i] + b;
    }
    vector<typename T::open_type> opened(buffer_size);
    proc->MC.POpen(opened, a_plus_b, proc->P);
    for (int i = 0; i < buffer_size; i++)
        this->squares.push_back({{as[i], as[i] * opened[i] - cs[i]}});
}

template<class T>
void ReplicatedRingPrep<T>::buffer_squares()
{
    generate_squares(this->squares, this->buffer_size,
            this->protocol);
}

template<class T, class U>
void generate_squares(vector<array<T, 2>>& squares, int n_squares,
        U* protocol)
{
    CODE_LOCATION
    n_squares = BaseMachine::batch_size<T>(DATA_SQUARE, n_squares);
    assert(protocol != 0);
    squares.resize(n_squares);
    if (OnlineOptions::singleton.has_option("verbose_square"))
        fprintf(stderr, "generating %d random squares\n", n_squares);
    BufferScope scope(*protocol, n_squares);
    protocol->init_mul();
    for (size_t i = 0; i < squares.size(); i++)
    {
        auto& square = squares[i];
        square[0] = protocol->get_random();
        protocol->prepare_mul(square[0], square[0]);
    }
    protocol->exchange();
    for (size_t i = 0; i < squares.size(); i++)
        squares[i][1] = protocol->finalize_mul();
}

template<class T>
void BufferPrep<T>::buffer_inverses()
{
    buffer_inverses<0>(T::clear::invertible);
}

template<class T>
template<int>
void BufferPrep<T>::buffer_inverses(true_type)
{
    CODE_LOCATION
    assert(proc != 0);
    auto& P = proc->P;
    auto& MC = proc->MC;
    auto& prep = *this;
    int buffer_size = BaseMachine::batch_size<T>(DATA_INVERSE);
    vector<array<T, 3>> triples(buffer_size);
    vector<T> c;
    for (int i = 0; i < buffer_size; i++)
    {
        prep.get_three_no_count(DATA_TRIPLE, triples[i][0], triples[i][1],
                triples[i][2]);
        c.push_back(triples[i][2]);
    }
    vector<typename T::open_type> c_open;
    MC.POpen(c_open, c, P);
    proc->protocol.sync(c_open, P);
    for (size_t i = 0; i < c.size(); i++)
        if (c_open[i] != 0)
            inverses.push_back({{triples[i][0], triples[i][1] / c_open[i]}});
    triples.clear();
    if (inverses.empty())
        throw runtime_error("products were all zero");
    MC.Check(P);
}

template<class T>
void BufferPrep<T>::get_two_no_count(Dtype dtype, T& a, T& b)
{
    switch (dtype)
    {
    case DATA_SQUARE:
    {
        if (squares.empty())
        {
            InScope in_scope(this->do_count, false, *this);
            buffer_squares();
        }

        a = squares.back()[0];
        b = squares.back()[1];
        squares.pop_back();
        return;
    }
    case DATA_INVERSE:
    {
        while (inverses.empty())
        {
            InScope in_scope(this->do_count, false, *this);
            buffer_inverses();
        }

        a = inverses.back()[0];
        b = inverses.back()[1];
        inverses.pop_back();
        return;
    }
    default:
        throw not_implemented();
    }
}

template<class T>
void XOR(vector<T>& res, vector<T>& x, vector<T>& y,
		typename T::Protocol& prot)
{
    assert(x.size() == y.size());
    int buffer_size = x.size();
    res.resize(buffer_size);

    if (T::clear::field_type() == DATA_GF2N)
    {
        for (int i = 0; i < buffer_size; i++)
            res[i] = x[i] + y[i];
        return;
    }

    prot.init_mul();
    for (int i = 0; i < buffer_size; i++)
        prot.prepare_mul(x[i], y[i]);
    prot.exchange();
    typename T::open_type two = typename T::open_type(1) + typename T::open_type(1);
    for (int i = 0; i < buffer_size; i++)
        res[i] = x[i] + y[i] - prot.finalize_mul() * two;
}

template<class T>
void buffer_bits_from_squares(RingPrep<T>& prep)
{
    CODE_LOCATION
    auto proc = prep.get_proc();
    assert(proc != 0);
    auto& bits = prep.get_bits();
    vector<array<T, 2>> squares(
            BaseMachine::batch_size<T>(DATA_BIT, prep.buffer_size));
    int bak = prep.buffer_size;
    prep.buffer_size = squares.size();
    vector<T> s;
    for (size_t i = 0; i < squares.size(); i++)
    {
        prep.get_two(DATA_SQUARE, squares[i][0], squares[i][1]);
        s.push_back(squares[i][1]);
    }
    prep.buffer_size = bak;
    vector<typename T::clear> open;
    proc->MC.POpen(open, s, proc->P);
    auto one = T::constant(1, proc->P.my_num(), proc->MC.get_alphai());
    for (size_t i = 0; i < s.size(); i++)
        if (open[i] != 0)
            bits.push_back((squares[i][0] / open[i].sqrRoot() + one) / 2);
    squares.clear();
    if (bits.empty())
        throw runtime_error("squares were all zero");
}

template<class T>
template<int>
void SemiHonestRingPrep<T>::buffer_bits(true_type, false_type)
{
    if (this->protocol->get_n_relevant_players() > T::bit_generation_threshold
            or OnlineOptions::singleton.bits_from_squares
            or T::dishonest_majority)
        buffer_bits_from_squares(*this);
    else
        this->buffer_bits_without_check();
}

template<class T>
void BitPrep<T>::buffer_bits_without_check()
{
    SeededPRNG G;
    buffer_ring_bits_without_check(this->bits, G,
            BaseMachine::batch_size<T>(DATA_BIT, this->buffer_size));
}

template<class T>
void MaliciousRingPrep<T>::buffer_personal_dabits(int input_player)
{
    buffer_personal_dabits<0>(input_player, T::clear::characteristic_two,
            T::clear::prime_field);
}

template<class T>
template<int>
void MaliciousRingPrep<T>::buffer_personal_dabits(int, true_type, false_type)
{
    throw runtime_error("only implemented for integer-like domains");
}

template<class T>
template<int>
void MaliciousRingPrep<T>::buffer_personal_dabits(int input_player, false_type,
        false_type)
{
    assert(this->proc != 0);
    vector<dabit<T>> check_dabits;
    this->buffer_personal_dabits_without_check<0>(input_player, check_dabits,
            dabit_sacrifice.minimum_n_inputs(this->buffer_size));
    dabit_sacrifice.sacrifice_and_check_bits(
            this->personal_dabits[input_player], check_dabits, *this->proc, 0);
}

template<class T>
template<int>
void MaliciousRingPrep<T>::buffer_personal_dabits(int input_player, false_type,
        true_type)
{
    if (T::clear::length() >= 60)
        buffer_personal_dabits<0>(input_player, false_type(), false_type());
    else
    {
        assert(this->proc != 0);
        vector<dabit<T>> check_dabits;
        DabitShuffleSacrifice<T> shuffle_sacrifice;
        this->buffer_personal_dabits_without_check<0>(input_player, check_dabits,
                shuffle_sacrifice.minimum_n_inputs());
        shuffle_sacrifice.dabit_sacrifice(this->personal_dabits[input_player],
                check_dabits, *this->proc, 0);
    }
}

template<class T>
template<int>
void MaliciousRingPrep<T>::buffer_personal_dabits_without_check(
        int input_player, vector<dabit<T>>& to_check, int buffer_size)
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_dabit"))
        fprintf(stderr, "generating %d personal dabits\n", buffer_size);

    assert(this->proc != 0);
    auto& P = this->proc->P;
    auto &party = GC::ShareThread<typename T::bit_type>::s();
    typedef typename T::bit_type::part_type BT;
    typename BT::Input bit_input(party.MC->get_part_MC(),
            this->proc->bit_prep, this->proc->P);
    typename T::Input input(*this->proc, this->proc->MC);
    input.reset_all(P);
    bit_input.reset_all(P);
    SeededPRNG G;
    if (input.is_me(input_player))
    {
        for (int i = 0; i < buffer_size; i++)
        {
            auto bit = G.get_bit();
            bit_input.add_mine(bit, 1);
            input.add_mine(bit);
        }
    }
    else
        for (int i = 0; i < buffer_size; i++)
        {
            bit_input.add_other(input_player);
            input.add_other(input_player);
        }
    input.exchange();
    bit_input.exchange();
    for (int i = 0; i < buffer_size; i++)
        to_check.push_back({input.finalize(input_player),
                bit_input.finalize(input_player, 1)});
}

template<class T>
template<int>
void RingPrep<T>::buffer_personal_edabits_without_check(int n_bits,
        vector<T>& sums, vector<vector<BT> >& bits, SubProcessor<BT>& proc,
        int input_player, int begin, int end)
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_eda"))
        fprintf(stderr, "generate personal edaBits %d to %d\n", begin, end);

    InScope in_scope(this->do_count, false, *this);
    assert(this->proc != 0);
    auto& P = proc.P;
    typename T::Input input(*this->proc, this->proc->MC);
    typename BT::Input bit_input(proc, proc.MC);
    input.reset_all(P);
    bit_input.reset_all(P);
    assert(begin % BT::default_length == 0);
    int buffer_size = end - begin;
    BufferScope _(this->proc->DataF, buffer_size);
    BufferScope __(proc.DataF, buffer_size);
    buffer_personal_edabits_without_check_pre(n_bits, P, input, bit_input,
            input_player, buffer_size);
    input.exchange();
    bit_input.exchange();
    buffer_personal_edabits_without_check_post(n_bits, sums, bits, input,
            bit_input, input_player, begin, end);
}

template<class T>
template<int>
void RingPrep<T>::buffer_personal_edabits_without_check_pre(int n_bits,
        Player&, typename T::Input& input, typename BT::Input& bit_input,
        int input_player, int buffer_size)
{
    int n_chunks = DIV_CEIL(buffer_size, BT::default_length);
    SeededPRNG G;
    if (bit_input.is_me(input_player))
    {
        for (int i = 0; i < n_chunks; i++)
        {
            typename T::clear tmp[BT::default_length];
            for (int j = 0; j < n_bits; j++)
            {
                auto bits = G.get<typename BT::clear>();
                bit_input.add_mine(bits, BT::default_length);
                for (int k = 0; k < BT::default_length; k++)
                    tmp[k] += T::clear::power_of_two(bits.get_bit(k), j);
            }
            for (int k = 0; k < BT::default_length; k++)
                input.add_mine(tmp[k], n_bits);
        }
    }
    else
        for (int i = 0; i < n_chunks; i++)
        {
            for (int j = 0; j < n_bits; j++)
                bit_input.add_other(input_player);
            for (int i = 0; i < BT::default_length; i++)
                input.add_other(input_player);
        }
}

template<class T>
template<int>
void RingPrep<T>::buffer_personal_edabits_without_check_post(int n_bits,
        vector<T>& sums, vector<vector<BT> >& bits, typename T::Input& input,
        typename BT::Input& bit_input, int input_player, int begin, int end)
{
    int buffer_size = end - begin;
    int n_chunks = DIV_CEIL(buffer_size, BT::default_length);
    for (int i = 0; i < buffer_size; i++)
        sums[begin + i] = input.finalize(input_player);
    assert(bits.size() == size_t(n_bits));
    for (auto& x : bits)
        assert(x.size() >= size_t(end / BT::default_length));
    for (int i = 0; i < n_chunks; i++)
    {
        for (int j = 0; j < n_bits; j++)
            bits[j][begin / BT::default_length + i] =
                    bit_input.finalize(input_player, BT::default_length);
    }
}

template<class T>
void MaliciousRingPrep<T>::buffer_personal_edabits(int n_bits, vector<T>& wholes,
        vector<vector<BT> >& parts, SubProcessor<BT>& proc, int input_player,
        bool strict, ThreadQueues* queues)
{
    CODE_LOCATION
#ifdef VERBOSE_EDA
    cerr << "Generate personal edaBits of length " << n_bits
            << " to sacrifice" << endl;
    Timer timer;
    timer.start();
#endif
    EdabitShuffleSacrifice<T> shuffle_sacrifice(n_bits);
    int buffer_size = shuffle_sacrifice.minimum_n_inputs();
    vector<T> sums(buffer_size);
    vector<vector<BT>> bits(n_bits, vector<BT>(DIV_CEIL(buffer_size, BT::default_length)));
    if (queues)
    {
        ThreadJob job(n_bits, &sums, &bits, input_player);
        int start = queues->distribute(job, buffer_size, 0, BT::default_length);
        this->template buffer_personal_edabits_without_check<0>(n_bits, sums,
                bits, proc, input_player, start, buffer_size);
        if (start)
            queues->wrap_up(job);
    }
    else
        this->template buffer_personal_edabits_without_check<0>(n_bits, sums,
                bits, proc, input_player, 0, buffer_size);
#ifdef VERBOSE_EDA
    cerr << "Done with generating personal edaBits after " << timer.elapsed()
            << " seconds" << endl;
#endif
    vector<edabit<T>> edabits;
    shuffle_sacrifice.edabit_sacrifice(edabits, sums, bits, *this->proc,
            strict, input_player, queues);
    assert(not edabits.empty());
    wholes.clear();
    parts.clear();
    parts.resize(n_bits);
    for (size_t j = 0; j < edabits.size(); j++)
    {
        auto& x = edabits[j];
        wholes.push_back(x.first);
        for (int i = 0; i < n_bits; i++)
        {
            if (j % BT::default_length == 0)
                parts[i].push_back({});
            parts[i].back() ^= BT(x.second[i]) << (j % BT::default_length);
        }
    }
}

template<class T>
void buffer_bits_from_players(vector<vector<T>>& player_bits,
        PRNG& G, SubProcessor<T>& proc, int base_player,
        int buffer_size, int n_bits)
{
    auto& protocol = proc.protocol;
    auto& P = protocol.P;
    int n_relevant_players = protocol.get_n_relevant_players();
    player_bits.resize(n_relevant_players);
    auto& input = proc.input;
    input.reset_all(P);
    for (int i = 0; i < n_relevant_players; i++)
    {
        int input_player = (base_player + i) % P.num_players();
        if (input.is_me(input_player))
        {
            for (int i = 0; i < buffer_size; i++)
            {
                typename T::clear tmp;
                for (int j = 0; j < n_bits; j++)
                    tmp += typename T::clear(G.get_bit()) << j;
                input.add_mine(tmp, n_bits);
            }
        }
        else
            for (int i = 0; i < buffer_size; i++)
                input.add_other(input_player);
    }
    input.exchange();
    for (int i = 0; i < n_relevant_players; i++)
        for (int j = 0; j < buffer_size; j++)
            player_bits[i].push_back(
                    input.finalize((base_player + i) % P.num_players(),
                            n_bits));
    if (OnlineOptions::singleton.has_option("verbose_bit"))
        fprintf(stderr, "got %d bits from %d players\n", buffer_size,
                n_relevant_players);
}

template<class T>
void BitPrep<T>::buffer_ring_bits_without_check(vector<T>& bits, PRNG& G,
        int buffer_size)
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_bit"))
        fprintf(stderr, "generate %d bits\n", buffer_size);
    auto proc = this->proc;
    assert(protocol != 0);
    assert(proc != 0);
    int n_relevant_players = protocol->get_n_relevant_players();
    vector<vector<T>> player_bits;
    auto stat = proc->P.total_comm();
    BufferScope _(*this, buffer_size);
    buffer_bits_from_players(player_bits, G, *proc, this->base_player,
            buffer_size, 1);
    auto& prot = *protocol;
    BufferScope scope(prot, buffer_size);
    XOR(bits, player_bits[0], player_bits[1], prot);
    for (int i = 2; i < n_relevant_players; i++)
        XOR(bits, bits, player_bits[i], prot);
    this->base_player++;
    (void) stat;
#ifdef VERBOSE_PREP
    cerr << "bit generation" << endl;
    (proc->P.total_comm() - stat).print(true);
#endif
}

template<class T>
void RingPrep<T>::buffer_dabits_without_check(vector<dabit<T>>& dabits,
        int buffer_size, ThreadQueues* queues)
{
    buffer_size = BaseMachine::batch_size<T>(DATA_DABIT, buffer_size);
    int old_size = dabits.size();
    dabits.resize(dabits.size() + buffer_size);
    if (queues)
    {
        ThreadJob job(&dabits);
        int start = queues->distribute(job, buffer_size, old_size);
        this->buffer_dabits_without_check(dabits,
                start, dabits.size());
        if (start > old_size)
            queues->wrap_up(job);
    }
    else
        buffer_dabits_without_check(dabits, old_size, dabits.size());
}

template<class T>
void SemiRep3Prep<T>::buffer_dabits(ThreadQueues*)
{
    CODE_LOCATION
    assert(this->protocol);
    assert(this->proc);

    int n_blocks = DIV_CEIL(
            BaseMachine::batch_size<T>(DATA_DABIT, this->buffer_size),
            BT::default_length);
    int n_bits = n_blocks * BT::default_length;

    if (OnlineOptions::singleton.has_option("verbose_dabit"))
        fprintf(stderr, "generating %d daBits\n", n_bits);

    b.clear();
    b.reserve(n_bits);

    Player& P = this->proc->P;

    BT r;
    for (int i = 0; i < n_bits; i++)
    {
        for (int j = 0; j < 2; j++)
            r[j].randomize(this->protocol->shared_prngs[j], 1);
        b.push_back(r);
    }

    int my_num = P.my_num();

    // the first multiplication
    typename T::Input& input = this->proc->protocol.get_helper_input();
    input.reset_all(P);

    if (P.my_num() == 0)
    {
        for (auto& bb : b)
        {
            input.add_mine(bb[0] ^ bb[1]);
        }
    }
    else
        input.add_other(0);

    input.exchange();

#define X(I) if (my_num == I) buffer_dabits_finish<I>();
    X(0) X(1) X(2)
#undef X
}

template<class T>
template<int MY_NUM>
void SemiRep3Prep<T>::buffer_dabits_finish()
{
    Player& P = this->proc->P;

    auto& input = this->proc->protocol.get_helper_input();
    auto& input2 = this->proc->protocol.get_helper_input();
    input2.reset_all(P);

    if (MY_NUM == 0)
        for (auto& bb : b)
        {
            this->dabits.push_back({input.finalize_mine(), bb});
        }
    else
    {
        T y;
        for (auto& bb : b)
        {
            auto x = input.finalize_offset(0 - MY_NUM);
            y[MY_NUM - 1] = bb[MY_NUM - 1];
            input2.add_mine(x.local_mul(y));
            this->dabits.push_back({x + y, bb});
        }
    }

    input2.add_other(1);
    input2.add_other(2);
    input2.exchange();

    for (auto it = this->dabits.end() - b.size(); it < this->dabits.end(); it++)
    {
        it->first -= 2
                * (input2.finalize_offset(1 - MY_NUM)
                        + input2.finalize_offset(2 - MY_NUM));
    }
}

template<class T>
void RingPrep<T>::buffer_dabits_without_check(vector<dabit<T>>& dabits,
        size_t begin, size_t end)
{
    auto proc = this->proc;
    assert(proc != 0);
    buffer_dabits_without_check<0>(dabits, begin, end, proc->bit_prep);
}

template<class T>
template<int>
void RingPrep<T>::buffer_dabits_without_check(vector<dabit<T>>& dabits,
        size_t begin, size_t end,
        Preprocessing<typename T::bit_type::part_type>&)
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_dabit"))
        fprintf(stderr, "generate daBits %lu to %lu\n", begin, end);

    size_t buffer_size = end - begin;
    auto proc = this->proc;
    assert(this->protocol != 0);
    assert(proc != 0);
    SeededPRNG G;
    PRNG G2 = G;
    typedef typename T::bit_type::part_type bit_type;
    vector<vector<bit_type>> player_bits;
    auto& bit_proc = get_bit_part_proc();
    buffer_bits_from_players(player_bits, G, bit_proc, this->base_player,
            buffer_size, 1);
    vector<T> int_bits;
    this->buffer_ring_bits_without_check(int_bits, G2, buffer_size);
    for (auto& pb : player_bits)
        assert(pb.size() == int_bits.size());
    for (size_t i = 0; i < int_bits.size(); i++)
    {
        bit_type bit = player_bits[0][i];
        for (int j = 1; j < this->protocol->get_n_relevant_players(); j++)
            bit ^= player_bits[j][i];
        dabits[begin + i] = {int_bits[i], bit};
    }
}

template<class T>
SubProcessor<typename RingPrep<T>::BT>& RingPrep<T>::get_bit_part_proc()
{
    if (bit_part_proc == 0)
    {
        auto &party = GC::ShareThread<typename T::bit_type>::s();
        assert(this->proc);
        bit_part_proc = new SubProcessor<BT>(party.MC->get_part_MC(),
                this->proc->bit_prep, this->proc->P);
        bit_part_proc->protocol.set_suffix("edaBits");
    }
    return *bit_part_proc;
}

template<class T>
template<int>
void RingPrep<T>::buffer_edabits_without_check(int n_bits, vector<T>& sums,
        vector<vector<typename T::bit_type::part_type>>& bits, int buffer_size,
        ThreadQueues* queues)
{
    RunningTimer timer;
    int dl = T::bit_type::part_type::default_length;
    int rounded = DIV_CEIL(buffer_size, dl) * dl;
    sums.resize(rounded);
    bits.resize(rounded / dl);
    if (queues)
    {
        ThreadJob job(n_bits, &sums, &bits);
        int start = queues->distribute(job, rounded, 0, dl);
        buffer_edabits_without_check<0>(n_bits, sums, bits, start, rounded);
        if (start)
            queues->wrap_up(job);
    }
    else
        buffer_edabits_without_check<0>(n_bits, sums, bits, 0, rounded);
#ifdef VERBOSE_EDA
    cerr << "Done with unchecked edaBit generation after " << timer.elapsed()
            << " seconds" << endl;
#endif
}

template<class T>
template<int>
void RingPrep<T>::buffer_edabits_without_check(int n_bits, vector<T>& sums,
        vector<vector<typename T::bit_type::part_type>>& bits, int begin,
        int end)
{
    CODE_LOCATION
    typedef typename T::bit_type::part_type bit_type;
    int dl = bit_type::default_length;
    assert(begin % dl == 0);
    assert(end % dl == 0);
    int buffer_size = end - begin;
    auto proc = this->proc;
    assert(this->protocol != 0);
    assert(proc != 0);
    auto& bit_proc = get_bit_part_proc();
    int n_relevant = this->protocol->get_n_relevant_players();
    vector<vector<T>> player_ints(n_relevant, vector<T>(buffer_size));
    vector<vector<vector<bit_type>>> parts(n_relevant,
            vector<vector<bit_type>>(n_bits, vector<bit_type>(buffer_size / dl)));
    InScope in_scope(this->do_count, false, *this);
    assert(this->proc != 0);
    auto& P = proc->P;
    typename T::Input input(*this->proc, this->proc->MC);
    typename BT::Input bit_input(bit_proc, bit_proc.MC);
    input.reset_all(P);
    bit_input.reset_all(P);
    assert(begin % BT::default_length == 0);
    for (int i = 0; i < n_relevant; i++)
        buffer_personal_edabits_without_check_pre(n_bits, P, input, bit_input,
                i, buffer_size);
    input.exchange();
    bit_input.exchange();
    for (int i = 0; i < n_relevant; i++)
        buffer_personal_edabits_without_check_post(n_bits, player_ints[i],
                parts[i], input, bit_input, i, 0, buffer_size);
    vector<vector<vector<bit_type>>> player_bits(n_bits,
            vector<vector<bit_type>>(n_relevant));
    for (int i = 0; i < n_bits; i++)
        for (int j = 0; j < n_relevant; j++)
            player_bits[i][j] = parts[j][i];
    BitAdder().add(bits, player_bits, begin / dl, end / dl, bit_proc,
            bit_type::default_length, 0);
    for (int i = 0; i < buffer_size; i++)
    {
        T sum;
        for (auto& ints : player_ints)
            sum += ints[i];
        sums[begin + i] = sum;
    }
}

template<class T>
template<int>
void RingPrep<T>::buffer_edabits_without_check(int n_bits, vector<edabitvec<T>>& edabits,
        int buffer_size)
{
    if (OnlineOptions::singleton.has_option("verbose_eda"))
        fprintf(stderr, "edabit buffer size %d\n", buffer_size);
    auto stat = this->proc->P.total_comm();
    typedef typename T::bit_type::part_type bit_type;
    vector<vector<bit_type>> bits;
    vector<T> sums;
    buffer_edabits_without_check<0>(n_bits, sums, bits, buffer_size);
    this->push_edabits(edabits, sums, bits);
    (void) stat;
#ifdef VERBOSE_PREP
    cerr << "edaBit generation" << endl;
    (proc->P.total_comm() - stat).print(true);
#endif
}

template<class T>
void BufferPrep<T>::push_edabits(vector<edabitvec<T>>& edabits,
        const vector<T>& sums, const vector<vector<typename T::bit_type::part_type>>& bits)
{
    int unit = T::bit_type::part_type::default_length;
    edabits.reserve(edabits.size() + DIV_CEIL(sums.size(), unit));
    for (size_t i = 0; i < sums.size(); i++)
    {
        if (i % unit ==  0)
            edabits.push_back(bits.at(i / unit));
        edabits.back().push_a(sums[i]);
    }
}

template<class T>
template<int>
void RingPrep<T>::buffer_sedabits_from_edabits(int n_bits, false_type, false_type)
{
    assert(this->proc != 0);
    size_t buffer_size = DIV_CEIL(BaseMachine::edabit_batch_size<T>(n_bits),
            edabitvec<T>::MAX_SIZE);
#ifdef VERBOSE_EDA
    fprintf(stderr, "sedabit buffer size %zu\n", buffer_size);
#endif
    auto& loose = this->edabits[{false, n_bits}];
    BufferScope scope(*this, buffer_size * edabitvec<T>::MAX_SIZE);
    while (loose.size() < buffer_size)
        this->buffer_edabits(false, n_bits);
    sanitize<0>(loose, n_bits);
    for (auto& x : loose)
    {
        this->edabits[{true, n_bits}].push_back(x);
    }
    loose.clear();
}

template<class T>
template<int>
void RingPrep<T>::sanitize(vector<edabit<T>>& edabits, int n_bits,
        int player, ThreadQueues* queues)
{
    if (queues)
    {
        SanitizeJob job(&edabits, n_bits, player);
        int start = queues->distribute(job, edabits.size());
        sanitize<0>(edabits, n_bits, player, start, edabits.size());
        if (start)
            queues->wrap_up(job);
    }
    else
        sanitize<0>(edabits, n_bits, player, 0, edabits.size());
}

template<class T>
template<int>
void RingPrep<T>::sanitize(vector<edabit<T>>& edabits, int n_bits, int player,
        int begin, int end)
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_eda"))
        fprintf(stderr, "sanitize edaBits %d to %d in %d\n", begin, end,
                BaseMachine::thread_num);

    vector<T> dabits;
    typedef typename T::bit_type::part_type::small_type BT;
    vector<BT> to_open;
    BufferScope scope(*this, (end - begin));
    for (int i = begin; i < end; i++)
    {
        auto& x = edabits[i];
        for (size_t j = n_bits; j < x.second.size(); j++)
        {
            T a;
            typename T::bit_type b;
            if (player < 0)
                this->get_dabit_no_count(a, b);
            else
                this->get_personal_dabit(player, a, b);
            dabits.push_back(a);
            to_open.push_back(x.second[j] + BT(b));
        }
    }
    vector<typename BT::open_type> opened;
    auto& MCB = *BT::new_mc(
            GC::ShareThread<typename T::bit_type>::s().MC->get_alphai());
    MCB.POpen(opened, to_open, this->proc->P);
    this->proc->protocol.sync(opened, this->proc->P);
    auto dit = dabits.begin();
    auto oit = opened.begin();
    for (int i = begin; i < end; i++)
    {
        auto& x = edabits[i];
        auto& whole = x.first;
        for (size_t j = n_bits; j < x.second.size(); j++)
        {
            auto& mask = *dit++;
            int masked = (*oit++).get();
            auto overflow = mask
                    + T::constant(masked, this->proc->P.my_num(),
                            this->proc->MC.get_alphai())
                    - mask * typename T::clear(masked * 2);
            whole -= overflow << j;
        }
        x.second.resize(n_bits);
    }
    MCB.Check(this->proc->P);
    delete &MCB;
}

template<class T>
template<int>
void RingPrep<T>::sanitize(vector<edabitvec<T>>& edabits, int n_bits)
{
    CODE_LOCATION
    vector<T> dabits;
    typedef typename T::bit_type::part_type BT;
    vector<BT> to_open;
    BufferScope scope(*this, edabits.size() * edabits[0].size());

#ifdef DEBUG_BATCH_SIZE
    cerr << this->dabits.size() << " daBits left before" << endl;
#endif

    for (auto& x : edabits)
    {
        for (size_t j = n_bits; j < x.b.size(); j++)
        {
            BT bits;
            for (size_t i = 0; i < x.size(); i++)
            {
                T a;
                typename T::bit_type b;
                this->get_dabit_no_count(a, b);
                dabits.push_back(a);
                bits ^= BT(b) << i;
            }
            to_open.push_back(x.b[j] + bits);
        }
    }

#ifdef DEBUG_BATCH_SIZE
    cerr << this->dabits.size() << " daBits left after" << endl;
#endif

    vector<typename BT::open_type> opened;
    auto& MCB = *BT::new_mc(
            GC::ShareThread<typename T::bit_type>::s().MC->get_alphai());
    MCB.POpen(opened, to_open, this->proc->P);
    vector<Integer> synced(opened.begin(), opened.end());
    this->proc->protocol.sync(synced, this->proc->P);
    auto dit = dabits.begin();
    auto oit = synced.begin();
    for (auto& x : edabits)
    {
        for (size_t j = n_bits; j < x.b.size(); j++)
        {
            auto masked = (*oit++);
            for (size_t i = 0; i < x.size(); i++)
            {
                int masked_bit = masked.get_bit(i);
                auto& mask = *dit++;
                auto overflow = mask
                        + T::constant(masked_bit, this->proc->P.my_num(),
                                this->proc->MC.get_alphai())
                        - mask * typename T::clear(masked_bit * 2);
                x.a[i] -= overflow << j;
            }
        }
        x.b.resize(n_bits);
    }
    MCB.Check(this->proc->P);
    delete &MCB;
}

template<class T>
template<int>
void SemiHonestRingPrep<T>::buffer_bits(false_type, true_type)
{
    assert(this->protocol != 0);
    if (not T::dishonest_majority and T::variable_players)
        // Shamir
        this->buffer_bits_without_check();
    else
        while (this->bits.size() < (size_t) OnlineOptions::singleton.batch_size)
        {
            auto share = this->get_random();
            for (int j = 0; j < T::open_type::degree(); j++)
            {
                this->bits.push_back(share & 1);
                share >>= 1;
            }
        }
}

template<class T>
template<int>
void SemiHonestRingPrep<T>::buffer_bits(false_type, false_type)
{
    this->buffer_bits_without_check();
}

template<class T>
void SemiHonestRingPrep<T>::buffer_bits()
{
    assert(this->protocol != 0);
    buffer_bits(T::clear::prime_field, T::clear::characteristic_two);
}

template<class T>
void BufferPrep<T>::get_one_no_count(Dtype dtype, T& a)
{
    if (dtype != DATA_BIT)
        throw not_implemented();

    while (bits.empty())
    {
        InScope in_scope(this->do_count, false, *this);
        buffer_bits();
        n_bit_rounds++;
    }

    a = bits.back();
    bits.pop_back();
}

template<class T>
void BufferPrep<T>::get_input_no_count(T& a, typename T::open_type& x, int i)
{
    (void) a, (void) x, (void) i;
    if (inputs.size() <= (size_t)i)
        inputs.resize(i + 1);
    if (inputs.at(i).empty())
    {
        InScope in_scope(this->do_count, false, *this);
        buffer_inputs(i);
        assert(not inputs.empty());
    }
    a = inputs[i].back().share;
    x = inputs[i].back().value;
    inputs[i].pop_back();
}

template<class T>
void BufferPrep<T>::get_dabit_no_count(T& a, typename T::bit_type& b)
{
    if (dabits.empty())
    {
        InScope in_scope(this->do_count, false, *this);
        ThreadQueues* queues = 0;
        buffer_dabits(queues);
        assert(not dabits.empty());
    }
    a = dabits.back().first;
    b = dabits.back().second;
    dabits.pop_back();
}

template<class T>
void BufferPrep<T>::get_personal_dabit(int player, T& a, typename T::bit_type& b)
{
    auto& buffer = personal_dabits[player];
    if (buffer.empty())
    {
        InScope in_scope(this->do_count, false, *this);
        buffer_personal_dabits(player);
    }
    a = buffer.back().first;
    b = buffer.back().second;
    buffer.pop_back();
}

template<class T>
void Preprocessing<T>::get_dabit(T& a, typename T::bit_type& b)
{
    get_dabit_no_count(a, b);
    this->count(DATA_DABIT);
}

template<class T>
edabitvec<T> BufferPrep<T>::get_edabitvec(bool strict, int n_bits)
{
    auto& buffer = this->edabits[{strict, n_bits}];
    if (buffer.empty())
    {
        InScope in_scope(this->do_count, false, *this);
        buffer_edabits_with_queues(strict, n_bits);
    }
    assert(not buffer.empty());
    auto res = buffer.back();
    buffer.pop_back();
    this->fill(res, strict, n_bits);
    return res;
}

template<class T>
void BufferPrep<T>::get_edabit_no_count(bool strict, int n_bits, edabit<T>& a)
{
    auto& my_edabit = my_edabits[{strict, n_bits}];
    if (my_edabit.empty())
    {
        my_edabit = this->get_edabitvec(strict, n_bits);
    }
    a = my_edabit.next();
}

template<class T>
void Sub_Data_Files<T>::get_edabit_no_count(bool strict, int n_bits,
        edabit<T>& a)
{
    auto& my_edabit = my_edabits[n_bits];
    if (my_edabit.empty())
    {
        my_edabit = this->get_edabitvec(strict, n_bits);
    }
    a = my_edabit.next();
}

template<class T>
void BufferPrep<T>::buffer_edabits_with_queues(bool strict, int n_bits)
{
    ThreadQueues* queues = 0;
    if (BaseMachine::thread_num == 0 and BaseMachine::has_singleton())
        queues = &BaseMachine::s().queues;
    buffer_edabits(strict, n_bits, queues);
}

template<class T>
template<int>
void Preprocessing<T>::get_edabits(bool strict, size_t size, T* a,
        StackedVector<typename T::bit_type>& Sb, const vector<int>& regs, false_type)
{
    int n_bits = regs.size();
    edabit<T> eb;
    size_t unit = T::bit_type::default_length;
    for (int k = 0; k < DIV_CEIL(size, unit); k++)
    {

        if (unit == edabitvec<T>::MAX_SIZE and (k + 1) * unit <= size)
        {
            auto buffer = get_edabitvec(strict, n_bits);
            assert(unit == buffer.size());
            for (int j = 0; j < n_bits; j++)
                Sb[regs[j] + k] = buffer.get_b(j);
            for (size_t j = 0; j < unit; j++)
                a[k * unit + j] = buffer.get_a(j);
        }
        else
        {
            for (size_t i = k * unit; i < min(size, (k + 1) * unit); i++)
            {
                get_edabit_no_count(strict, n_bits, eb);
                a[i] = eb.first;
                for (int j = 0; j < n_bits; j++)
                {
                    if (i % unit == 0)
                        Sb[regs[j] + i / unit] = {};
                    Sb[regs[j] + i / unit].xor_bit(i % unit, eb.second[j]);
                }
            }
        }
    }

    for (size_t i = 0; i < size; i++)
        this->usage.count_edabit(strict, n_bits);
}

template<class T>
void BufferPrep<T>::buffer_edabits(bool strict, int n_bits,
        ThreadQueues* queues)
{
    if (strict)
        buffer_sedabits(n_bits, queues);
    else
        buffer_edabits(n_bits, queues);
}

template<class T>
inline void BufferPrep<T>::buffer_inputs(int player)
{
    (void) player;
    throw not_implemented();
}

template<class T>
void BufferPrep<T>::buffer_inputs_as_usual(int player, SubProcessor<T>* proc)
{
    CODE_LOCATION
    assert(proc != 0);
    auto& P = proc->P;
    this->inputs.resize(P.num_players());
    typename T::Input input(proc, P);
    input.reset(player);
    auto buffer_size = OnlineOptions::singleton.batch_size;
    if (input.is_me(player))
    {
        SeededPRNG G;
        vector<typename T::clear> rs;
        rs.reserve(buffer_size);
        for (int i = 0; i < buffer_size; i++)
        {
            typename T::clear r;
            r.randomize(G);
            input.add_mine(r);
            rs.push_back(r);
        }
        input.exchange();
        for (auto& r : rs)
            this->inputs[player].push_back({input.finalize(player), r});
    }
    else
    {
        for (int i = 0; i < buffer_size; i++)
            input.add_other(player);
        input.exchange();
        for (int i = 0; i < buffer_size; i++)
        {
            auto share = input.finalize(player);
            this->inputs[player].push_back({share, 0});
        }
    }
}

template<class T>
void BufferPrep<T>::get_no_count(StackedVector<T>& S, DataTag tag,
        const vector<int>& regs, int vector_size)
{
    (void) S, (void) tag, (void) regs, (void) vector_size;
    throw not_implemented();
}

template<class T>
void BufferPrep<T>::shrink_to_fit()
{
    triples.shrink_to_fit();
}

template<class T>
T BufferPrep<T>::get_random()
{
    try
    {
        if (proc != 0)
            return proc->protocol.get_random();
        else
            throw not_implemented();
    }
    catch (not_implemented&)
    {
        return Preprocessing<T>::get_random();
    }
}

template<class T>
void BufferPrep<T>::buffer_extra(Dtype type, int n_items)
{
    BufferScope scope(*this, n_items);

    switch (type)
    {
    case DATA_TRIPLE:
        buffer_triples();
        break;
    case DATA_SQUARE:
        buffer_squares();
        break;
    case DATA_BIT:
        buffer_bits();
        break;
    default:
        throw not_implemented();
    }
}

#endif
