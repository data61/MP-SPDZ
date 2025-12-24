/*
 * Astra.cpp
 *
 */

#ifndef PROTOCOLS_ASTRA_HPP_
#define PROTOCOLS_ASTRA_HPP_

#include "Astra.h"
#include "Tools/files.h"
#include "Tools/ranges.h"

template<class T>
string AstraBase<T>::get_filename(bool preprocessing, const char* name)
{
    int base = 1 - preprocessing;
    auto res = get_prep_sub_dir<T>(P.num_players() + base, preprocessing) + name
            + suffix + "-P" + to_string(P.my_num() + base) + "-T"
            + to_string(BaseMachine::thread_num);
    if (OnlineOptions::singleton.has_option("verbose_astra"))
        fprintf(stderr, "astra filename %s\n", res.c_str());
    return res;
}

template<class T>
string AstraBase<T>::get_output_filename()
{

    return get_filename(not T::real_shares(P), "Outputs");
}

template<class T>
void AstraBase<T>::debug()
{
    if (OnlineOptions::singleton.has_option("verbose_astra"))
        fprintf(stderr, "astra comm %s %p %d %s\n", T::type_string().c_str(), this,
                BaseMachine::thread_num, suffix.c_str());
}

template<class T>
AstraBase<T>::AstraBase(Player& P) :
        n_mults(0), P(P)
{
}

template<class T>
void AstraBase<T>::set_suffix(const string& suffix)
{
    this->suffix = "-" + suffix;
    init_prep();
}

template<class T>
AstraBase<T>::~AstraBase()
{
}

template<class T>
Astra<T>::Astra(Player& P) :
        AstraOnlineBase<T>(P)
{
}

template<class T>
AstraOnlineBase<T>::AstraOnlineBase(Player& P) :
        AstraBase<T>(P)
{
    astra_num = P.my_num() + 1;
}

template<class T>
AstraPrepProtocol<T>::AstraPrepProtocol(Player& P) :
        AstraBase<T>(P), unsplit_input(0), prng_protocol(P),
        prng_protocol_for_input0(P)
{
    my_num = P.my_num();
}

template<class T>
AstraPrepProtocol<T>::~AstraPrepProtocol()
{
    prng_protocol.output_time<T>();
    prng_protocol_for_input0.output_time<T>();
    if (unsplit_input)
        delete unsplit_input;
}

template<class T>
void AstraOnlineBase<T>::init_prep()
{
    try
    {
        open_with_check(prep, this->get_filename(false));
    }
    catch (...)
    {
        throw runtime_error(
                "Error with preprocessing in " + this->get_filename(false)
                        + ". You need to run the preprocessing before "
                        "the online phase or in parallel.");
    }
}

template<class T>
void AstraPrepProtocol<T>::init_prep()
{
    if (this->P.my_num() > 0)
        prep.open(this->get_filename(true));
}

template<class T>
void AstraBase<T>::init_mul()
{
    input_pairs.clear();
    inputs.clear();
    results.clear();
    n_mults = 0;
}

template<class T>
void AstraBase<T>::prepare_mul(const T& x, const T& y, int)
{
    this->input_pairs.push_back({x, y});
}

template<class T>
void AstraBase<T>::init_dotprod()
{
    init_mul();
}

template<class T>
void AstraBase<T>::prepare_dotprod(const T& x, const T& y)
{
    prepare_mul(x, y);
}

template<class T>
void AstraBase<T>::next_dotprod()
{
#define X(Pi) \
    if (my_astra_num() == Pi) \
    { \
        this->inputs.push_back({}); \
        for (auto& x : this->input_pairs) \
            this->inputs.back() += x[0].local_mul_P##Pi(x[1]); \
    }
    X(0) X(1) X(2)
#undef X

    n_mults++;
    this->input_pairs.clear();
}

template<class T>
T AstraBase<T>::finalize_dotprod(int)
{
    return this->finalize_mul();
}

template<class T>
T AstraPrepShare<T>::local_mul_P0(const AstraPrepShare& other) const
{
    return this->sum() * other.sum();
}

template<class T>
T AstraPrepShare<T>::local_mul_P1(const AstraPrepShare& other) const
{
    return local_mul_P0(other);
}

template<class T>
T AstraPrepShare<T>::local_mul_P2(const AstraPrepShare&) const
{
    return {};
}

template<class T>
T AstraShare<T>::local_mul_P0(const AstraShare&) const
{
    throw runtime_error("P0 should be absent");
}

template<class T>
T AstraShare<T>::local_mul_P1(const AstraShare& other) const
{
    return m(1) * other.neg_lambda(1) + other.m(1) * neg_lambda(1);
}

template<class T>
T AstraShare<T>::local_mul_P2(const AstraShare& other) const
{
    return m(2) * other.m(2) + local_mul_P1(other);
}

template<class T>
void AstraBase<T>::prepare_exchange()
{
    n_mults += this->input_pairs.size();
}

template<class T>
template<int my_num>
void AstraPrepProtocol<T>::pre()
{
    auto& inputs = this->inputs;
    auto& results = this->results;
    auto& n_mults = this->n_mults;

    n_mults += this->input_pairs.size();
    results.reserve(n_mults);

    if (my_num == 0)
    {
        os.clear();
        os.reserve(n_mults * T::open_type::size());
    }
    else
    {
        os_prep.clear();
        os_prep.reserve(n_mults * 2 * T::open_type::size());
    }

    T res;
    open_type gamma;

    for (auto& input : inputs)
    {
        pre_element<my_num>(res);
        pre_gamma<my_num>(res, gamma, input);
        results.push_back(res);
    }

    for (auto& x : this->input_pairs)
    {
        open_type input;
#define X(I) if (my_num == I) input = x[0].local_mul_P##I(x[1]);
        X(0) X(1) X(2)
#undef X
        pre_element<my_num>(res);
        pre_gamma<my_num>(res, gamma, input);
        results.push_back(res);
    }
}

template<class T>
template<int my_num>
void AstraPrepProtocol<T>::pre_element(T& res)
{
    if (my_num == 0)
        for (int i = 0; i < 2; i++)
            res[i].randomize(prng_protocol.shared_prngs[i]);
    else
        res[1].randomize(prng_protocol.shared_prngs[2 - my_num]);
}

template<class T>
template<int my_num>
void AstraPrepProtocol<T>::pre_gamma(T& res, open_type& gamma, const open_type& input)
{
    if (my_num < 2)
    {
        gamma.randomize(prng_protocol.shared_prngs[my_num]);
        if (my_num == 0)
            os.store_no_resize(input - gamma);
        else
            post(res, gamma);
    }
}

template<class T>
void AstraPrepProtocol<T>::exchange()
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_astra"))
        fprintf(stderr, "astra exchange %zu\n", this->inputs.size());

    auto& P = this->P;
    auto& results = this->results;
    int my_num = P.my_num();
    assert(results.size() == 0);

#define X(I) if (my_num == I) pre<I>();
    X(0) X(1) X(2)
#undef X

    if (my_num == 0)
        P.send_to(2, os);
    else if (my_num == 2)
        P.receive_player(0, os);

    if (my_num == 2)
    {
        if (os.left() < open_type::size() * results.size())
            throw runtime_error("insufficient data in Astra");
        for (auto& res : results)
            post(res, os.get_no_check<open_type>());
    }

    store(os_prep);
    results.reset();
}

template<class T>
void AstraPrepProtocol<T>::post(T& res, const open_type& gamma)
{
    os_prep.store_no_resize(gamma);
    os_prep.store_no_resize(res[1]);
}

template<class T>
T Astra<T>::pre(const open_type& input)
{
    int my_num = this->astra_num;
    typename T::open_type gamma;
    gamma = os_prep.get_no_check<open_type>();
    T res;
    res[1] = os_prep.get_no_check<open_type>();
    auto m_z = input - res.neg_lambda(my_num) + gamma;
    os.store_no_resize(m_z);
    res.m(my_num) = m_z;
    return res;
}

template<class T>
void Astra<T>::exchange()
{
    CODE_LOCATION
    if (OnlineOptions::singleton.has_option("verbose_astra"))
        fprintf(stderr, "astra exchange %zu\n", this->inputs.size());

    auto& P = this->P;
    auto& inputs = this->inputs;
    auto& results = this->results;
    assert(results.size() == 0);

    size_t n_mults = this->inputs.size() + this->input_pairs.size();

    int my_num = this->my_astra_num();
    if (my_num > 0)
    {
        this->read(os_prep);
        os.clear();
        os.reserve(n_mults * T::open_type::size());

        if (os_prep.left() < open_type::size() * n_mults)
            throw runtime_error("insufficient preprocessing");

        for (auto& input : inputs)
            results.push_back(pre(input));

        if (my_num == 1)
            for (auto& x : this->input_pairs)
                results.push_back(pre(x[0].local_mul_P1(x[1])));
        else
            for (auto& x : this->input_pairs)
                results.push_back(pre(x[0].local_mul_P2(x[1])));

        octetStream recv_os;
        P.exchange(1 - P.my_num(), os, recv_os);

        if (recv_os.left() < open_type::size() * results.size())
            throw runtime_error("insufficient data in Astra");

        for (auto& res : results)
            res.m(my_num) += recv_os.get_no_check<typename T::open_type>();

        assert(not os_prep.left());
    }

    results.reset();
}

template<class T>
T Astra<T>::finalize_mul(int)
{
    return this->results.next();
}

template<class T>
T AstraPrepProtocol<T>::finalize_mul(int)
{
    return this->results.next();
}

template<class T>
template<class U>
U AstraOnlineBase<T>::read()
{
    U res;
    octetStream os;
    read(os);
    os.get(res);
    assert(not os.left());
    return res;
}

template<class T>
void AstraOnlineBase<T>::read(octetStream& os)
{
    if (not prep.is_open())
        init_prep();
    Timer timer;
    TimeScope ts(timer);
    this->debug();
    os.input(prep);
    if (not prep.good())
        throw runtime_error("error in preprocessing reading");
    this->P.comm_stats["Preprocessing transmission"].add(os, ts);
}

template<class T>
template<class U>
void AstraPrepProtocol<T>::store(const U& value)
{
    if (this->P.my_num() > 0)
    {
        octetStream os;
        os.store(value);
        store(os);
    }
}

template<class T>
void AstraPrepProtocol<T>::store(const octetStream& os)
{
    if (this->P.my_num() > 0)
    {
        if (not prep.is_open())
            init_prep();
        TimeScope ts(this->P.comm_stats["Preprocessing transmission"].add(os));
        this->debug();
        os.output(prep);
        prep.flush();
        if (not prep.good())
            throw runtime_error("error in preprocessing storing");
    }
}

template<class T>
template<class U>
void AstraPrepProtocol<T>::sync(vector<U>& values, Player& P)
{
    if (P.my_num() == 1)
    {
        if (not outputs.is_open())
        {
            try
            {
                open_with_check(outputs, this->get_output_filename());
            }
            catch (...)
            {
                throw runtime_error("Error with output back channel. "
                        "This only works when preprocessing is run in parallel.");
            }
        }

        Timer timer;
        TimeScope ts(timer);
        octetStream os;
        os.input(outputs);
        os.get(values);
        this->P.comm_stats["Output transmission"].add(os, ts);
        P.send_all(os);
    }
    else
    {
        octetStream os;
        P.receive_player(1, os);
        os.get(values);
    }
}

template<class T>
template<class U>
void AstraOnlineBase<T>::sync(vector<U>& values, Player& P)
{
    if (P.my_num() == 0)
    {
        if (not outputs.is_open())
            outputs.open(this->get_output_filename());

        octetStream os;
        os.store(values);
        TimeScope ts(this->P.comm_stats["Output transmission"].add(os));
        os.output(outputs);
        outputs.flush();
    }
}

template<class T>
template<class U>
void AstraPrepProtocol<T>::forward_sync(vector<U>& values)
{
    store(values);
}

template<class T>
template<class U>
void AstraOnlineBase<T>::forward_sync(vector<U>& values)
{
    values = read<vector<U>>();
}

template<class T>
int AstraPrepProtocol<T>::rep_index(int i)
{
    return rep_index(i, my_num);
}

template<class T>
int AstraPrepProtocol<T>::rep_index(int i, int my_num)
{
    if (my_num == 0)
        return i;
    else
    {
        if (i == 0)
            // m
            return my_num - 1;
        else
            // lambda
            return 2 - my_num;
    }
}

template<class T>
template<class U>
AstraPrepShare<U> AstraPrepProtocol<T>::from_rep3(const FixedVec<U, 2>& x)
{
    return from_rep3(x, my_num);
}

template<class T>
template<class U>
AstraPrepShare<U> AstraPrepProtocol<T>::from_rep3(const FixedVec<U, 2>& x,
        int my_num)
{
    AstraPrepShare<U> res;
    for (int i = 0; i < 2; i++)
        res[i] = x[rep_index(i, my_num)];
    return res;
}

template<class T>
T AstraPrepProtocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(prng_protocol.shared_prngs[rep_index(i)]);
    store(res);
    return res;
}

template<class T>
T AstraOnlineBase<T>::get_random()
{
    return read<T>();
}

template<class T>
void AstraOnlineBase<T>::randoms_inst(StackedVector<T>& S, const Instruction& instruction)
{
    octetStream os;
    read(os);

    for (int j = 0; j < instruction.get_size(); j++)
    {
        auto& res = S[instruction.get_r(0) + j];
        res.unpack(os);
    }

    assert(not os.left());
}

template<class T>
void AstraPrepProtocol<T>::randoms_inst(StackedVector<T>& S,
        const Instruction& instruction)
{
    octetStream os;

    for (int j = 0; j < instruction.get_size(); j++)
    {
        auto& res = S[instruction.get_r(0) + j];
        for (int i = 0; i < 2; i++)
            res[i].randomize_part(
                    prng_protocol.shared_prngs[rep_index(i)],
                    instruction.get_n());
        res.pack(os);
    }

    store(os);
}

template<class T>
template<int>
void AstraOnlineBase<T>::trunc_pr(const vector<int>& regs, int size,
        SubProcessor<T>& proc, false_type)
{
    TruncPrTupleList<T> infos(regs, proc.get_S(), size);

    if (infos.have_big_gap())
        trunc_pr_big_gap(infos.get_big_gap(), size, proc);
    if (infos.have_small_gap())
        this->trunc_pr_small_gap(infos.get_small_gap(), size, proc);
}

template<class T>
template<int>
void AstraPrepProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        SubProcessor<T>& proc, false_type)
{
    TruncPrTupleList<T> infos(regs, proc.get_S(), size);

    if (infos.have_big_gap())
        trunc_pr_big_gap(infos.get_big_gap(), size, proc);
    if (infos.have_small_gap())
        this->trunc_pr_small_gap(infos.get_small_gap(), size, proc);
}

template<class T>
template<int>
void AstraOnlineBase<T>::trunc_pr_big_gap(
        const TruncPrTupleList<T>& infos, int size,
        SubProcessor<T>&)
{
    CODE_LOCATION
    typedef typename T::clear value_type;
    bool generate = my_astra_num() == this->gen_player;
    bool compute = my_astra_num() == this->comp_player;
    int my_num = my_astra_num();

    octetStream cs;
    read(cs);

    for (auto info : infos)
    {
        assert(info.big_gap());
        this->trunc_pr_counter += size;
    }

    this->trunc_rounds++;

    if (generate)
    {
        cs.require<T>(infos.size() * size);
        for (auto info : infos)
            for (auto& y : info.dest_range)
                y = cs.get_no_check<T>();
    }

    if (compute)
    {
        cs.require<value_type>(infos.size() * size);
        for (auto info : infos)
        {
            auto dest_it = info.dest_range.begin();
            for (auto& x : info.source_range)
            {
                {
                    auto& y = *dest_it++;
                    y.neg_lambda(my_num) = cs.get_no_check<value_type>();
                    y.set_common_m(x.common_m() >> info.m);
                }
            }
        }
    }

    if (not (compute or generate))
    {
        for (auto info : infos)
            if (info.big_gap())
            {
                cs.require<value_type>(size);
                auto dest_it = info.dest_range.begin();
                for (auto& x : info.source_range)
                {
                    auto& y = *dest_it++;
                    y.neg_lambda(my_num) = cs.get_no_check<value_type>();
                    y.set_common_m(x.common_m() >> info.m);
                }
            }
    }

    assert(not cs.left());
}

template<class T>
template<int>
void AstraPrepProtocol<T>::trunc_pr_big_gap(
        const TruncPrTupleList<T>& infos, int size,
        SubProcessor<T>& proc)
{
    CODE_LOCATION
    assert(proc.P.num_players() == 3);
    typedef typename T::clear value_type;
    auto& S = proc.get_S();
    bool generate = my_astra_num() == this->gen_player;
    bool compute = my_astra_num() == this->comp_player;

    octetStream cs;

    for (auto info : infos)
    {
        assert(info.big_gap());
        this->trunc_pr_counter += size;
    }

    this->trunc_rounds++;

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
        {
            auto dest_it = info.dest_range.begin();
            for (auto& x : info.source_range)
            {
                auto& y = *dest_it++;
                auto r =
                        prng_protocol.shared_prngs[1].template get<value_type>();
                y[0] = -value_type(
                        -value_type(x.neg_lambda_sum(my_num)) >> info.m) - r;
                y[0].pack(cs);
                y[1] = r;
//                store(y);
            }
        }

        this->P.send_to(this->comp_player, cs);
    }

    if (compute)
    {
        this->P.receive_player(this->gen_player, cs);
        octetStream os;
        for (auto info : infos)
        {
            cs.require<value_type>(size);
            for (int i = 0; i < size; i++)
            {
                {
                    auto& y = S[info.dest_base + i];
                    y.neg_lambda(my_num) = cs.get_no_check<value_type>();
                    os.store(y.neg_lambda(my_num));
                }
            }
        }
        store(os);
    }

    if (not (compute or generate))
    {
        for (auto info : infos)
            if (info.big_gap())
                for (int i = 0; i < size; i++)
                {
                    auto& y = S[info.dest_base + i];
                    y.neg_lambda(my_num) =
                            prng_protocol.shared_prngs[0].template get<
                                    value_type>();
                    cs.store(y.neg_lambda(my_num));
                }
        store(cs);
    }
}

template<class T>
template<int>
void AstraBase<T>::trunc_pr_small_gap(
        const TruncPrTupleList<T>& infos, int size,
        SubProcessor<T>& proc)
{
    CODE_LOCATION
    for (auto info : infos)
    {
        assert(info.small_gap());
        this->trunc_pr_counter += size;
    }

    this->trunc_rounds++;

    this->gen_values.clear();

#define X(I) if (my_astra_num() == I) \
        this->template trunc_pr_small_gap_finish<I>(infos, size, proc);
    X(0) X(1) X(2)
#undef X
}

template<class T>
void AstraPrepProtocol<T>::add_gen(octetStream& cs, const typename T::open_type& value)
{
    T res;
    res[1].randomize(prng_protocol_for_input0.shared_prngs[1]);
    res[0] = value - res[1];
    this->gen_values.push_back(res);
    cs.store_no_resize(res[0]);
}

template<class T>
template<class U, int MY_NUM>
void AstraPrepShare<T>::pre_input0(const clear& input, typename U::Protocol& protocol)
{
    assert(MY_NUM == 0);
    protocol.add_gen(protocol.cs, input);
}

template<class T>
template<class U, int MY_NUM>
AstraPrepShare<T> AstraPrepShare<T>::post_input0(typename U::Protocol& protocol)
{
    This r_prime;
    switch (MY_NUM)
    {
    case 0:
        r_prime = protocol.gen_values.next();
        break;
    case 1:
        protocol.cs.get_no_check(r_prime[1]);
        break;
    case 2:
        r_prime[1].randomize(
                protocol.prng_protocol_for_input0.shared_prngs[0]);
        protocol.cs.store_no_resize(r_prime[1]);
        break;
    }
    return r_prime;
}

template<class T>
template<class U, int MY_NUM>
AstraShare<T> AstraShare<T>::post_input0(typename U::Protocol& protocol)
{
    This res;
    protocol.cs_prep.get_no_check(res[1]);
    return res;
}

template<class T>
void AstraPrepProtocol<T>::init_input0(size_t n_inputs)
{
    cs.reset_write_head();
    cs.reserve<open_type>(n_inputs);
}

template<class T>
void AstraPrepProtocol<T>::exchange_input0(size_t n_inputs)
{
    auto& P = this->P;
    if (P.my_num() == 0)
    {
        P.send_to(1, cs);
        this->gen_values.reset();
        this->gen_values.require(n_inputs);
    }
    else if (P.my_num() == 1)
    {
        P.receive_player(0, cs);
        cs.require<open_type>(n_inputs);
    }
}

template<class T>
void AstraPrepProtocol<T>::finalize_input0(size_t n_inputs)
{
    if (this->P.my_num() != 0)
    {
        cs.reset_read_head();
        cs.require<open_type>(n_inputs);
        store(cs);
    }

    assert(not this->gen_values.left());
}

template<class T>
void AstraOnlineBase<T>::exchange_input0(size_t n_inputs)
{
    read(cs_prep);
    cs_prep.require<open_type>(n_inputs);
}

template<class T>
template<int MY_NUM>
void AstraBase<T>::trunc_pr_small_gap_finish(
        const TruncPrTupleList<T>& infos, int size,
        SubProcessor<T>& proc)
{
    bool generate = MY_NUM == gen_player;

    auto& protocol = proc.protocol;
    protocol.init_mul();
    gen_values.reset();

    init_reduced_mul(size * infos.size());
    init_input0(size * infos.size());

    for (auto info : infos)
    {
        if (info.small_gap())
        {
            auto source_it = info.source_range.begin();
            for (auto& x : info.dest_range)
            {
                auto y = *source_it++;
                T c_prime, c_dprime;
                typename T::clear c_msb, r_msb;

                if (generate and not T::real_shares(protocol.P))
                {
                    auto r = y.sum() + info.add_before() - 1;
                    r_msb = r.msb();
                    T::template pre_input0<T, MY_NUM>(r >> info.m, protocol);
                }

                if (not generate and T::real_shares(protocol.P))
                {
                    auto c = y.common_m();
                    c_prime.m(-1) = c >> info.m;
                    c_msb = c.msb();
                }

                T r_dprime, prod;
                T::template pre_reduced_mul<T, MY_NUM>(r_dprime, c_dprime, prod,
                        protocol, r_msb, c_msb);

                x = c_prime;
                x += info.correction_shift(prod - (r_dprime + c_dprime));
            }
        }
    }

    exchange_reduced_mul(size * infos.size());
    exchange_input0(size * infos.size());

    for (auto info : infos)
        for (auto& x : info.dest_range)
        {
            if (info.small_gap())
            {
                auto r_prime = T::template post_input0<T, MY_NUM>(protocol);
                auto res = T::template post_reduced_mul<T, MY_NUM>(protocol);
                x += r_prime - T::constant(info.subtract_after() - 1);
                x[0] += info.correction_shift(res.second);
           }
        }

    finalize_input0(size * infos.size());
}

template<class T>
void AstraOnlineBase<T>::unsplit(StackedVector<T>& dest,
        StackedVector<typename T::bit_type>& source,
        const Instruction& instruction)
{
    if (instruction.get_start().size() == 1)
        return unsplit1(dest, source, instruction);

    CODE_LOCATION
    int n_bits = instruction.get_size();
    int unit = T::bit_type::default_length;
    assert(instruction.get_start().size() == 2);
    int my_num = my_astra_num();

    octetStream os;
    read(os);
    os.require<T>(n_bits);

    for (int i = 0; i < DIV_CEIL(n_bits, unit); i++)
    {
        // conversion symmetric in binary
        auto x = T::bit_type::from_rep3(source.at(instruction.get_r(0) + i));
        int left = min(unit, n_bits - unit * i);
        typename vector<T>::iterator its[2];
        for (int k = 0; k < 2; k++)
            its[k] = dest.iterator_for_size(
                    instruction.get_start()[k] + i * unit, left);
        for (int j = 0; j < left; j++)
        {
            auto& y = *its[0]++;
            os.get_no_check(y);
            y = T::from_rep3(y);
            (*its[1]++).m(my_num) = x.m(my_num).get_bit(j);
        }
    }
}

template<class T>
void AstraPrepProtocol<T>::unsplit(StackedVector<T>& dest,
        StackedVector<typename T::bit_type>& source,
        const Instruction& instruction)
{
    if (instruction.get_start().size() == 1)
        return unsplit1(dest, source, instruction);

    CODE_LOCATION
    int n_bits = instruction.get_size();
    int unit = T::bit_type::default_length;
    assert(instruction.get_start().size() == 2);
    auto& P = this->P;

    if (not unsplit_input)
        unsplit_input = new ReplicatedInput<Rep3Share<typename T::clear>>(P);
    auto& input = *unsplit_input;
    input.reset_all(P);

    if (P.my_num() == 0)
    {
        int n_blocks = DIV_CEIL(n_bits, unit);
        auto it = source.iterator_for_size(instruction.get_r(0), n_blocks);
        for (int i = 0; i < n_blocks; i++)
        {
            auto x = (*it++).sum();
            for (int j = 0; j < min(unit, n_bits - unit * i); j++)
                input.add_mine(x.get_bit(j));
        }
    }
    else
        for (int i = 0; i < n_bits; i++)
            input.add_other(0);

#define X(I) if (P.my_num() == I) unsplit_finish<I>(dest, instruction);
    X(0) X(1) X(2)
#undef X
}

template<class T>
template<int MY_NUM>
void AstraPrepProtocol<T>::unsplit_finish(StackedVector<T>& dest,
        const Instruction& instruction)
{
    int n_bits = instruction.get_size();

    assert(unsplit_input);
    auto& input = *unsplit_input;
    input.exchange();
    os.reset_write_head();
    os.reserve<T>(n_bits);

    for (auto it : DoubleRange(dest, instruction.get_start()[0],
            instruction.get_start()[1], n_bits))
    {
        auto& x = it.first;
        x = from_rep3(input.finalize_offset(-MY_NUM), MY_NUM);
        os.store_no_resize(x);
        it.second = {};
    }

    store(os);
}

template<class T>
template<class U, int MY_NUM>
void AstraShare<T>::pre_reduced_mul(U& a, U& b, U& c,
        Astra<U>& protocol, const T&, const T& bb)
{
    auto& os_prep = protocol.os_prep;
    os_prep.get_no_check(a[1]);
    os_prep.get_no_check(c[1]);
    auto Mi = bb * a.neg_lambda(-1) - c.neg_lambda(-1);
    protocol.os.store_no_resize(Mi);
    b.m(-1) = bb;
    c.m(-1) = Mi;
    protocol.results.push_back({});
}

template<class T>
template<class U, int MY_NUM>
pair<U, T> AstraShare<T>::post_reduced_mul(typename U::Protocol& protocol)
{
    pair<U, T> res;
    res.first = protocol.results.next();
    res.second = protocol.recv_os.template get_no_check<clear>();
    return res;
}

template<class T>
void Astra<T>::init_reduced_mul(size_t n_mul)
{
    this->read(os_prep);
    os_prep.require<clear>(2 * n_mul);

    os.reset_write_head();
    os.reserve<clear>(n_mul);
    auto& results = this->results;
    results.clear();
    results.reserve(n_mul);
}

template<class T>
void Astra<T>::exchange_reduced_mul(size_t n_mul)
{
    auto& P = this->P;
    P.pass_around(os, recv_os, 1);
    recv_os.require<clear>(n_mul);
    this->results.reset();
    assert(this->results.left() == n_mul);
}

template<class T>
void Astra<T>::unsplit1(StackedVector<T>& dest,
        StackedVector<typename T::bit_type>& source,
        const Instruction& instruction)
{
    CODE_LOCATION
    size_t n_bits = instruction.get_size();
    assert(instruction.get_start().size() == 1);
    auto& results = this->results;

    init_reduced_mul(n_bits);
    auto range = BlockRange(source, instruction.get_r(0), n_bits);

    for (auto& x : range)
    {
        for (typename T::clear bit : BitLeftRange(x.m(-1), x, range))
        {
            T a, b, c;
            T::template pre_reduced_mul<T, -1>(a, b, c, *this, {}, bit);
            results.back() = a + b - 2 * c;
        }
    }

    exchange_reduced_mul(n_bits);

    for (auto& x : Range(dest, instruction.get_start()[0], n_bits))
    {
        auto res = T::template post_reduced_mul<T, 1>(*this);
        x = res.first;
        x.m(-1) -= res.second * 2;
    }

    assert(not recv_os.left());
    assert(not os_prep.left());
}

#endif
