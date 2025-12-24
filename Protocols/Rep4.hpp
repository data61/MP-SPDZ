/*
 * Rep4.cpp
 *
 */

#include "Rep4.h"
#include "GC/square64.h"
#include "Processor/TruncPrTuple.h"
#include "Tools/CodeLocations.h"

template<class T>
Rep4<T>::Rep4(Player& P) :
        my_num(P.my_num()), P(P)
{
    assert(P.num_players() == 4);

    rep_prngs[0].ReSeed();

    octetStreams to_send(P), to_receive;
    for (int i = 1; i < 3; i++)
        to_send[P.get_player(-i)].append(rep_prngs[0].get_seed(), SEED_SIZE);

    P.send_receive_all(to_send, to_receive);

    for (int i = 1; i < 3; i++)
        rep_prngs[i].SetSeed(to_receive[P.get_player(i)].get_data());

    malicious = not OnlineOptions::singleton.semi_honest;
}

template<class T>
Rep4<T>::Rep4(Player& P, prngs_type& prngs) :
        my_num(P.my_num()), P(P)
{
    for (int i = 0; i < 3; i++)
        rep_prngs[i].SetSeed(prngs[i]);

    malicious = not OnlineOptions::singleton.semi_honest;
}

template<class T>
Rep4<T>::~Rep4()
{
    check();

    for (auto& x : receive_hashes)
        for (auto& y : x)
            assert(y.size == 0);

    for (auto& x : send_hashes)
        for (auto& y : x)
            assert(y.size == 0);
}

template<class T>
void Rep4<T>::check()
{
    if (not malicious)
        return;

    for (auto& x : channels)
        for (auto y : x)
            if (y)
            {
                must_check();
                return;
            }
}

template<class T>
Rep4<T> Rep4<T>::branch()
{
    return {P, rep_prngs};
}

template<class T>
void Rep4<T>::init_mul()
{
    for (auto& x : add_shares)
        x.clear();
    bit_lengths.clear();

    send_os.reset(P);
    receive_os.reset(P);
    channels.resize(P.num_players(), vector<bool>(P.num_players(), false));
}

template<class T>
void Rep4<T>::reset_joint_input(int n_inputs)
{
    results.clear();
    results.resize(n_inputs);
    bit_lengths.clear();
    bit_lengths.resize(n_inputs, -1);
}

template<class T>
void Rep4<T>::prepare_joint_input(int sender, int backup, int receiver,
        int outsider, vector<open_type>& inputs)
{
    prepare_joint_input(sender, backup, receiver, outsider, inputs, results);
}

template<class T>
void Rep4<T>::prepare_joint_input(int sender, int backup, int receiver,
        int outsider, vector<open_type>& inputs, vector<ResTuple>& results)
{
    channels[sender][receiver] = true;

    if (P.my_num() != receiver)
    {
        int index = P.get_offset(receiver) - 1;
        for (auto& x : results)
        {
            x.r = rep_prngs[index].get();
            x.res[index] += x.r;
        }

        if (P.my_num() == sender or P.my_num() == backup)
        {
            int offset = P.get_offset(outsider) - 1;
            size_t n_results = results.size();
            for (size_t i = 0; i < n_results; i++)
            {
                auto& input = inputs[i];
                input -= results[i].r;
                results[i].res[offset] += input;
            }
        }
    }

    if (P.my_num() == backup and malicious)
    {
        send_hashes[sender][receiver].update(inputs, bit_lengths);
    }

    if (sender == P.my_num())
    {
        assert(inputs.size() == bit_lengths.size());
        switch (P.get_offset(backup))
        {
        case 2:
            for (size_t i = 0; i < inputs.size(); i++)
                inputs[i].pack(send_os[3 - my_num], bit_lengths[i]);
            break;
        case 1:
            for (size_t i = 0; i < inputs.size(); i++)
                inputs[i].pack(send_os[get_player(-1)], bit_lengths[i]);
            break;
        default:
            throw not_implemented();
        }
    }

    for (auto& x : send_os)
        x.append(0);
}

template<class T>
void Rep4<T>::finalize_joint_input(int sender, int backup, int receiver,
        int outsider)
{
    finalize_joint_input(sender, backup, receiver, outsider, results);
}

template<class T>
void Rep4<T>::finalize_joint_input(int sender, int backup, int receiver,
        int, vector<ResTuple>& results)
{
    if (P.my_num() == receiver)
    {
        assert(results.size() == bit_lengths.size());
        T res;
        size_t n_results = results.size();
        octetStream* os;
        int index;
        switch (P.get_offset(backup))
        {
        case 2:
            os = &receive_os[get_player(1)];
            index = 2;
            break;
        default:
            os = &receive_os[3 - P.my_num()];
            index = 1;
            break;
        }

        auto start = os->get_data_ptr();
        for (size_t i = 0; i < n_results; i++)
        {
            auto& x = results[i];
            res[1].unpack(*os, bit_lengths[i]);
            x.res[index] += res[1];
        }

        os->consume(0);

        if (malicious)
            receive_hashes[sender][backup].update(start,
                    os->get_data_ptr() - start);
    }
}

template<class T>
int Rep4<T>::get_player(int offset)
{
    return (my_num + offset) & 3;
}

template<class T>
void Rep4<T>::prepare_mul(const T& x, const T& y, int n_bits)
{
    auto a = get_addshares(x, y);
    for (int i = 0; i < 5; i++)
        add_shares[i].push_back(a[i]);
    bit_lengths.push_back(n_bits);
}

template<class T>
array<typename T::open_type, 5> Rep4<T>::get_addshares(const T& x, const T& y)
{
    array<open_type, 5> res;
    for (int i = 0; i < 2; i++)
        res[get_player(i - 1)] =
                (x[i] + x[i + 1]) * y[i] + x[i] * y[i + 1];
    res[4] = x[0] * y[2] + x[2] * y[0];
    return res;
}

template<class T>
void Rep4<T>::init_dotprod()
{
    init_mul();
    dotprod_shares = {};
}

template<class T>
void Rep4<T>::prepare_dotprod(const T& x, const T& y)
{
    auto a = get_addshares(x, y);
    for (int i = 0; i < 5; i++)
        dotprod_shares[i] += a[i];
}

template<class T>
void Rep4<T>::next_dotprod()
{
    for (int i = 0; i < 5; i++)
        add_shares[i].push_back(dotprod_shares[i]);
    bit_lengths.push_back(-1);
    dotprod_shares = {};
}

template<class T>
void Rep4<T>::exchange()
{
    CODE_LOCATION
    auto& a = add_shares;
    results.clear();
    results.resize(a[4].size());
    prepare_joint_input(0, 1, 3, 2, a[0]);
    prepare_joint_input(1, 2, 0, 3, a[1]);
    prepare_joint_input(2, 3, 1, 0, a[2]);
    prepare_joint_input(3, 0, 2, 1, a[3]);
    prepare_joint_input(0, 2, 3, 1, a[4]);
    prepare_joint_input(1, 3, 2, 0, a[4]);
    P.send_receive_all(channels, send_os, receive_os);
    finalize_joint_input(0, 1, 3, 2);
    finalize_joint_input(1, 2, 0, 3);
    finalize_joint_input(2, 3, 1, 0);
    finalize_joint_input(3, 0, 2, 1);
    finalize_joint_input(0, 2, 3, 1);
    finalize_joint_input(1, 3, 2, 0);
}

template<class T>
T Rep4<T>::finalize_mul(int n_bits)
{
    this->add_mul(n_bits);
    if (n_bits == -1)
        return results.next().res;
    else
        return finalize_mul(n_bits, T::clear::binary);
}

template<class T>
template<int>
T Rep4<T>::finalize_mul(int n_bits, true_type)
{
    return results.next().res.mask(n_bits);
}

template<class T>
template<int>
T Rep4<T>::finalize_mul(int, false_type)
{
    throw runtime_error("bit-wise multiplication not supported");
}

template<class T>
T Rep4<T>::finalize_dotprod(int)
{
    return finalize_mul();
}

template<class T>
void Rep4<T>::must_check()
{
    CODE_LOCATION
    octetStreams to_send(P);
    for (int i = 1; i < 4; i++)
        for (int j = 0; j < 4; j++)
            to_send[P.get_player(i)].concat(send_hashes[j][P.get_player(i)].final());

    octetStreams to_receive;
    P.send_receive_all(to_send, to_receive);

    octetStream tmp;
    for (int i = 1; i < 4; i++)
        for (int j = 0; j < 4; j++)
        {
            to_receive[P.get_player(-i)].consume(tmp, Hash::hash_length);
            if (receive_hashes[j][P.get_player(-i)].final() != tmp)
                throw runtime_error(
                        "hash mismatch for sender " + to_string(j)
                        + " and backup " + to_string(P.get_player(-i)));
        }
}

template<class T>
T Rep4<T>::get_random()
{
    T res;
    for (int i = 0; i < 3; i++)
        res[i].randomize(rep_prngs[i]);
    return res;
}

template<class T>
void Rep4<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 3; i++)
        res[i].randomize_part(rep_prngs[i], n_bits);
}

template<class T>
template<int>
void Rep4<T>::trunc_pr(const vector<int>&, int, SubProcessor<T>&, true_type)
{
    throw runtime_error("only implemented for integer-like domains");
}

template<class T>
template<int>
void Rep4<T>::trunc_pr(const vector<int>& regs, int size,
		SubProcessor<T>& proc, false_type)
{
    CODE_LOCATION
    assert(regs.size() % 4 == 0);
    this->trunc_pr_counter += size * regs.size() / 4;
    typedef typename T::open_type open_type;

    vector<TruncPrTupleWithGap<open_type>> infos;
    for (size_t i = 0; i < regs.size(); i += 4)
        infos.push_back({regs, i});

    PointerVector<T> rs(size * infos.size());
    for (int i = 2; i < 4; i++)
    {
        int index = P.get_offset(i) - 1;
        if (index >= 0)
            for (auto& r : rs)
                r[index].randomize(rep_prngs[index]);
    }

    vector<T> cs;
    cs.reserve(rs.size());
    for (auto& info : infos)
    {
        for (int j = 0; j < size; j++)
        {
            auto c = proc.get_S_ref(info.source_base + j) + rs.next();
            if (info.small_gap())
                c += T::constant(info.add_before(), my_num);
            cs.push_back(c);
        }
    }

    octetStream c_os;
    vector<open_type> eval_inputs;
    if (P.my_num() < 2)
    {
        if (P.my_num() == 0)
            for (auto& c : cs)
                (c[1] + c[2]).pack(c_os);
        else
            for (auto& c : cs)
                (c[1] + c[0]).pack(c_os);
        P.send_to(2 + P.my_num(), c_os);

        if (malicious)
            P.send_to(3 - P.my_num(), c_os.hash());
    }
    else
    {
        P.receive_player(P.my_num() - 2, c_os);

        if (malicious)
        {
            octetStream hash;
            P.receive_player(3 - P.my_num(), hash);
            if (hash != c_os.hash())
                throw runtime_error("hash mismatch in joint message passing");
        }

        PointerVector<open_type> open_cs;
        if (P.my_num() == 2)
            for (auto& c : cs)
                open_cs.push_back(c_os.get<open_type>() + c[1] + c[2]);
        else
            for (auto& c : cs)
                open_cs.push_back(c_os.get<open_type>() + c[1] + c[0]);
        for (auto& info : infos)
            for (int j = 0; j < size; j++)
            {
                auto c = open_cs.next();
                auto c_prime = info.upper(c);
                if (not info.big_gap())
                {
                    auto c_msb = info.msb(c);
                    eval_inputs.push_back(c_msb);
                }
                eval_inputs.push_back(c_prime);
            }
    }

    PointerVector<open_type> inputs;
    bool generate = proc.P.my_num() < 2;
    if (generate)
    {
        inputs.reserve(2 * rs.size());
        rs.reset();
        for (auto& info : infos)
            for (int j = 0; j < size; j++)
            {
                auto& r = rs.next();
                if (not info.big_gap())
                    inputs.push_back(info.msb(r.sum()));
                inputs.push_back(info.upper(r.sum()));
            }
    }

    init_mul();
    size_t n_inputs = max(inputs.size(), eval_inputs.size());
    reset_joint_input(n_inputs);
    PointerVector<ResTuple> gen_results(n_inputs);
    PointerVector<ResTuple> eval_results(n_inputs);
    prepare_joint_input(0, 1, 3, 2, inputs, gen_results);
    prepare_joint_input(2, 3, 1, 0, eval_inputs, eval_results);
    P.send_receive_all(channels, send_os, receive_os);
    finalize_joint_input(0, 1, 3, 2, gen_results);
    finalize_joint_input(2, 3, 1, 0, eval_results);

    init_mul();
    for (auto& info : infos)
        for (int j = 0; j < size; j++)
        {
            if (not info.big_gap())
                prepare_mul(gen_results.next().res, eval_results.next().res);
            gen_results.next();
            eval_results.next();
        }

    if (not add_shares[0].empty())
        exchange();

    eval_results.reset();
    gen_results.reset();

    for (auto& info : infos)
        for (int j = 0; j < size; j++)
        {
            if (info.big_gap())
                proc.get_S_ref(info.dest_base + j) = eval_results.next().res
                        - gen_results.next().res;
            else
            {
                auto b = gen_results.next().res + eval_results.next().res
                        - 2 * finalize_mul();
                proc.get_S_ref(info.dest_base + j) = eval_results.next().res
                        - gen_results.next().res + (b << (info.k - info.m))
                        - T::constant(info.subtract_after(), P.my_num());
            }
        }
}

template<class T>
template<class U>
void Rep4<T>::split(StackedVector<T>& dest, const vector<int>& regs, int n_bits,
        const U* source, int n_inputs)
{
    CODE_LOCATION
    assert(regs.size() / n_bits == 2);
    assert(n_bits <= 64);
    int unit = GC::Clear::N_BITS;
    int my_num = P.my_num();
    int i0 = -1;

    switch (my_num)
    {
    case 0:
        i0 = 1;
        break;
    case 1:
        i0 = 0;
        break;
    case 2:
        i0 = 1;
        break;
    case 3:
        i0 = 0;
        break;
    }

    vector<BitVec> to_share;
    init_mul();

    for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
    {
        int start = k * unit;
        int m = min(unit, n_inputs - start);

        square64 square;

        for (int j = 0; j < m; j++)
        {
            auto& input_share = source[j + start];
            auto input_value = input_share[i0] + input_share[i0 + 1];
            square.rows[j] = Integer(input_value).get();
        }

        square.transpose(m, n_bits);

        for (int j = 0; j < n_bits; j++)
        {
            to_share.push_back(square.rows[j]);
            bit_lengths.push_back(m);
        }
    }

    array<PointerVector<ResTuple>, 2> results;
    for (auto& x : results)
        x.resize(to_share.size());
    prepare_joint_input(0, 1, 3, 2, to_share, results[0]);
    prepare_joint_input(2, 3, 1, 0, to_share, results[1]);
    P.send_receive_all(channels, send_os, receive_os);
    finalize_joint_input(0, 1, 3, 2, results[0]);
    finalize_joint_input(2, 3, 1, 0, results[1]);

    for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
    {
        for (int j = 0; j < n_bits; j++)
            for (int i = 0; i < 2; i++)
            {
                auto res = results[i].next().res;
                dest.at(regs.at(2 * j + i) + k) = res;
            }
    }
}
