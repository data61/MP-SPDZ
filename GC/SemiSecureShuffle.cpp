/*
 * SemiSecureShuffle.cpp
 *
 */

#ifdef USE_TUNGSTEN
#include "secure-join/Perm/AltModPerm.h"
#include "LiboteState.h"
#include "Networking/PlayerCoSocket.h"
#endif

#include "SemiSecureShuffle.h"
#include "SemiPrep.h"
#include "ShareThread.h"
#include "F3.h"
#include "F2Vector.h"

#include "Protocols/SecureShuffle.hpp"
#include "Protocols/SemiMC.hpp"
#include "SemiSecret.hpp"

#include <numeric>

namespace GC
{

template<class T>
BitBuffer::BitBuffer(const T& other, size_t n)
{
    for (size_t i = 0; i < n; i++)
        values.push_back({other[i][0].mData, 128});
}

bool BitBuffer::has_enough(size_t n_bits)
{
    if (n_bits > 64)
        throw runtime_error("shuffling of more than 64-bit values not implemented");

    return not values.empty() and values.at(0).second >= n_bits;
}

SemiSecret BitBuffer::get(size_t index, size_t n_bits)
{
    auto& remaining = values.at(index).second;

    if (remaining < n_bits)
        throw runtime_error("not enough bits cached for shuffling");

    auto& value = values.at(index).first;
    auto res = BitVec(value.get_lower()).mask(n_bits);
    value >>= n_bits;
    remaining -= n_bits;
    return res;
}

void BitBuffer::resize(size_t size)
{
    values.resize(size);
}

void BitBuffer::add(size_t index, const BitVector& value)
{
    values.at(index) = {value.get_int128(0), value.size()};
}

void BitBuffer::add(size_t index, const F2Vec128& value)
{
    values.at(index) = {value.get(), value.size()};
}

SemiSecureShuffle::SemiSecureShuffle() :
        state(0), rot_ext(0)
{
}

SemiSecureShuffle::~SemiSecureShuffle()
{
    (void) state;
#ifdef USE_TUNGSTEN
    if (state)
        delete state;
#endif
    if (rot_ext)
        delete rot_ext;
}

void SemiSecureShuffle::generate(size_t n, const vector<shuffle_type*>& perms,
        bool full)
{
    SeededPRNG G;
    for (auto perm : perms)
        G.random_permutation(n, perm->pi);

    if (full)
        full_generate(n, perms);
}

void SemiSecureShuffle::full_generate(size_t n,
        const vector<shuffle_type*>& perms)
{
    CODE_LOCATION
    auto& party = ShareThread<SemiSecret>::s();
    assert(party.P);
    auto& P = *party.P;
    if (P.num_players() != 2)
        throw runtime_error("only implemented for two parties");

    if (not OnlineOptions::singleton.has_option("use_tungsten"))
        return generate_from_ot(n, perms, P);

#ifdef USE_TUNGSTEN
    if (not state)
    {
        state = new SemiSecureShuffleState(P);
    }

    typedef ShareThread<GC::SemiSecret> thread_type;
    bool time = thread_type::has_singleton();
    if (time)
        thread_type::s().DataF.prep_timer.start(P.total_comm());

    SemiSecureShuffleState::job_type job(n, perms);
    state->generate(&job);

    if (time)
        thread_type::s().DataF.prep_timer.stop(P.total_comm());
#else
    throw runtime_error("tungsten not compiled");
#endif
}

F2Vec128 SemiSecureShuffle::apply_prf(const BitVector& key,
        const F3VectorBitWiseView& x)
{
    bool debug_output = false;
    auto A_input = x.schur(key);
    if (debug_output)
        cout << "cleartext A input " << A_input << endl;
    auto prod = A.apply(A_input);
    if (debug_output)
        cout << "cleartext mid " << F3Vector(prod) << endl;
    F2Vector vec(prod);
    auto res = B.dot(vec);
    if (debug_output)
        cout << "PRF result " << res << endl;
    return res;
}

vector<F2Vec128> SemiSecureShuffle::apply_prf(const BitVector& key,
        const RowMatrix<F3VectorBitWise>& x)
{
    auto tmp = x;
    for (size_t i = 0; i < tmp.n_cols(); i++)
        tmp.col(i).ischur(key);
    auto A_output = A.apply(tmp.transpose()).transpose();
    assert(A_output.n_cols() == x.n_cols());
    vector<F2Vec128> res;
    res.reserve(x.n_cols());
    for (size_t i = 0; i < A_output.n_cols(); i++)
        res.push_back(B.dot(A_output.col(i).get_bits(0)));
    return res;
}

void SemiSecureShuffle::generate_from_ot(size_t n, shuffle_gen_type& perms, Player& P)
{
    CODE_LOCATION

    bool debug = OnlineOptions::singleton.has_option("debug_f3");
    bool debug_output = OnlineOptions::singleton.has_option("debug_more_f3");
    if (debug or debug_output)
    {
        insecure("F3 debugging");
    }

    int key_size = 128 * 4;
    int mid_size = 256;
    vector<PRNG> G_receiver;
    vector<array<PRNG, 2>> G_sender;
    if (not rot_ext)
        rot_ext = new OTExtensionWithMatrix(P, true);
    auto& ot_ext = *rot_ext;
    BitVector k(key_size);
    SeededPRNG G;
    GlobalPRNG shared_prng(P);
    k.randomize(G);
    ot_ext.extend(key_size, k);
    for (int i = 0; i < key_size; i++)
    {
        G_sender.push_back({});
        G_receiver.push_back({});
        for (int k = 0; k < 2; k++)
            G_sender.back()[k].SetSeedFrom(int128(ot_ext.senderOutputMatrices.at(k).at(i)));
        G_receiver.back().SetSeedFrom(int128(ot_ext.receiverOutputMatrix.at(i)));
    }

    if (A.empty())
    {
        A = F3Code(key_size, mid_size, shared_prng);
    }

    if (B.empty())
    {
        B.resize(128, mid_size);
        B.randomize(shared_prng);
    }

    F3VectorBitWise w0, w1;
    octetStream fs;

    vector<F3Vector> h0s;
    vector<F3VectorBitWise> all_prf_inputs;

    size_t budget = 1 << 20;
    if (OnlineOptions::singleton.has_param("shuffle_budget"))
        budget = OnlineOptions::singleton.get_param("shuffle_budget");

    bool progress = OnlineOptions::singleton.has_option("shuffle_progress");

    for (auto& shuffle : perms)
    {
        RowMatrix<F3VectorBitWise> prf_inputs(key_size, n);
        shuffle->A.resize(n);
        shuffle->B.resize(n);
        shuffle->C.resize(n);

        if (progress)
            fprintf(stderr, "generate PRF inputs\n");

        F3VectorBitWise tmp(key_size);
        for (size_t i = 0; i < n; i++)
        {
            tmp.randomize(shared_prng);
            prf_inputs.set_col(i, tmp);

            if (debug)
                all_prf_inputs.push_back(prf_inputs.col(i));
        }

        if (debug_output)
            cout << "input " << prf_inputs.col(0) << endl;

        for (size_t i = 0; i < n; i += budget)
        {
            auto part_size = min(budget, n - i);

            if (progress)
                fprintf(stderr, "pre F3 %zu from %zu\n", part_size, i);

            RowMatrix<F3VectorBitWise> input_part(key_size, part_size);

            for (size_t j = 0; j < part_size; j++)
                input_part.set_col(j, prf_inputs.col(i + j));

            auto prf_output = apply_prf(k, input_part);

            for (size_t j = 0; j < part_size; j++)
                shuffle->A.add(i + j, prf_output.at(j));

            array<RowMatrix<F3VectorBitWise>, 2> h_matrices;
            for (int k = 0; k < 2; k++)
            {
                auto& x = h_matrices[k];
                x.resize(part_size, key_size);

                F3VectorBitWise tmp(part_size);
                for (int j = 0; j < key_size; j++)
                {
                    tmp.randomize(G_sender[j][k]);
                    x.set_col(j, tmp);
                }
            }

            array<RowMatrix<F3VectorBitWise>, 2> hh;
            for (int k = 0; k < 2; k++)
                hh[k] = h_matrices[k].transpose();

            w1.append(A.apply(h_matrices[0]).transpose().concat());
            h_matrices = {};

            for (size_t j = 0; j < part_size; j++)
            {
                F3VectorBitWiseView h0 = hh[0].col(j), h1 = hh[1].col(j);
                h1 -= h0;
                h1 += prf_inputs.col(shuffle->pi.at(i + j));
                h1.pack(fs);

                if (debug_output)
                {
                    cout << "h0 " << h0 << endl;
                    cout << "h1 " << h1 << endl;
                }

                if (debug_output or debug)
                {
                    h0s.push_back(F3VectorBitWise(h0));
                }
            }
        }
    }

    P.exchange_relative(1, fs);

    SemiMC<SemiShare<F3Vector>> MC;

    for (auto& shuffle : perms)
    {
        (void) shuffle;
        RowMatrix<F3VectorBitWise> t_matrix;
        F3VectorBitWise tmp;
        RowMatrix<F3VectorBitWise> tt;
        F3VectorBitWise ff;

        for (size_t i = 0; i < n; i += budget)
        {
            auto part_size = min(budget, n - i);

            if (progress)
                fprintf(stderr, "post F3 %zu from %zu\n", part_size, i);

            t_matrix.resize(part_size, key_size);
            tmp.resize(part_size);
            for (int j = 0; j < key_size; j++)
            {
                tmp.randomize(G_receiver[j]);
                t_matrix.set_col(j, tmp);
            }

            tt = t_matrix.transpose();

            ff.resize(key_size);
            for (size_t j = 0; j < part_size; j++)
            {
                auto t = tt.col(j);
                ff.unpack(fs);
                ff.ischur(k);
                auto& vec = ff -= t;
                if (debug_output)
                {
                    cout << "t " << t << endl;
                    cout << "f " << ff << endl;
                    cout << "k " << k << endl;
                    cout << "vec " << vec << endl;
                }
                t.assign(vec);

                if (P.my_num() and debug_output)
                    cout << "shared A input " << MC.open(vec, P) << endl;

                if (debug and false)
                {
                    array<F3Vector, 2> w = {vec, h0s.at(i + j)};
                    SemiMC<SemiShare<F3Vector>> MC;
                    array<F3Vector, 2> opened;
                    for (int k = 0; k < 2; k++)
                        opened[k] = MC.open(w[k ^ P.my_num()], P);
                    auto& to_test = opened[P.my_num()];
                    F3Vector test_mid = all_prf_inputs.at(i + j).schur(k);
                    F3Vector part = to_test;
                    assert(test_mid == part);
                }
            }

            w0.append(A.apply(tt.transpose()).transpose().concat());
        }
    }

    fs = {};

    if (not P.my_num() and debug_output)
        for (auto& x : h0s)
            cout << "shared A input " << MC.open(x, P) << endl;

    if (debug_output)
    {
        cout << "shared mid ";
        if (P.my_num())
            cout << MC.open(w0, P) << endl;
        else
            cout << MC.open(w1, P) << endl;
    }

    if (debug and false)
    {
        array<F3Vector, 2> w = {w0, w1};
        SemiMC<SemiShare<F3Vector>> MC;
        array<F3Vector, 2> opened;
        for (int k = 0; k < 2; k++)
            opened[k] = MC.open(w[k ^ P.my_num()], P);
        auto& to_test = opened[P.my_num()];
        cout << "to test " << to_test << endl;
        for (size_t i = 0; i < n; i++)
        {
            F3Vector test_mid = A.apply(all_prf_inputs.at(i).schur(k));
            F3Vector part;
            part.assign(to_test.begin() + i * mid_size, to_test.begin() + (i + 1) * mid_size);
            assert(test_mid == part);
        }
    }

    // conversion prep
    assert(w0.size() == perms.size() * n * mid_size);
    assert(w0.size() == w1.size());
    assert(w1.size());
    auto offset = w0.size();
    assert(offset);

    octetStream ds, ts;
    array<BitVector, 2> vs;
    for (auto& v : vs)
        v.resize(w0.size());

    array<bool, 3> T[3] = {
            {0, 1, 0},
            {1, 0, 0},
            {0, 0, 1},
    };

    BitVector& r = vs[0];
    r.resize(w0.size());
    r.randomize(G);

    for (size_t i = 0; i < w0.size(); i += budget * mid_size)
    {
        size_t part_size = min(budget * mid_size, w0.size() - i);

        if (progress)
            fprintf(stderr, "conversion %zu+%zu\n", i, part_size);

        BitVector m_recv(part_size);
        array<BitVector, 3> m({part_size, part_size, part_size});
        vector<array<Bit, 3>> m_send;

        for (int k = 0; k < 2; k++)
        {
            auto choices = w1.part(i, part_size).get_bits(k).part(0, part_size);
            auto part_bits = ot_ext.bit_extension(choices, true);
            m_recv ^= part_bits.second;

            for (int j = 0; j < 3; j++)
            {
                auto& part = part_bits.first[F3(j).get_bit(k)];
                assert(part.size());
                m[j] ^= part;
            }
        }

        if (debug or debug_output)
            for (size_t i = 0; i < part_size; i++)
            {
                m_send.push_back({});
                for (int j = 0; j < 3; j++)
                {
                    m_send.back()[j] = bool(m[j][i]);
                }
            }

        if (debug_output)
            for (size_t i = 0; i < w0.size(); i++)
            {
                cout << i << endl;
                cout << "send ";
                for (auto x : m_send[i])
                    cout << x << " ";
                cout << endl;
            }

        if (debug)
        {
            auto& c = w1;
            octetStream os;
            c.pack(os);
            os.store(m_recv);
            os.store(m_send);
            os.flush_bits();
            P.exchange_relative(1, os);
            auto other_c = c;
            auto other_m_recv = m_recv;
            auto other_m_send = m_send;
            other_c.unpack(os);
            os.get(other_m_recv);
            os.get(other_m_send);
            for (size_t i = 0; i < w0.size(); i++)
            {
                assert(other_m_send[i][c[i].get()] == bool(m_recv[i]));
                assert(m_send[i][other_c[i].get()] == bool(other_m_recv[i]));
            }
        }

        array<BitVector, 3> tt;

        for (int k = 0; k < 3; k++)
        {

            auto a = F2Vector(m[k]);
            auto b = F2Vector(
                    F3VectorBitWise(w0.part(i, part_size)).select(T[k]));
            auto c = F2Vector(r.part(i, part_size));

            tt[k] = a + b + c;
        }

        ts.reset_write_head();
        ts.store(tt);
        P.exchange_relative(1, ts);
        ts.get(tt);

        vs[1].set_part(i,
                F2Vector(F3VectorBitWise(w1.part(i, part_size)).select(tt))
                        + F2Vector(m_recv));
    }

    ot_ext.resize(0);

    if (debug_output)
    {
        SemiMC<SemiShare<Bit>> MC2;
        cout << "shared B input ";
        for (size_t i = 0; i < w0.size(); i++)
            cout << MC2.open(vs[P.my_num()].get_bit(i), P);
        cout << endl;
    }

    if (debug and false)
    {
        SemiMC<SemiShare<Bit>> MC;
        for (size_t i = 0; i < n; i++)
        {
            auto B_input = A.apply(all_prf_inputs.at(i).schur(k));
            for (int j = 0; j < mid_size; j++)
            {
                int index = i * mid_size + j;
                array<Bit, 2> opened;
                for (int k = 0; k < 2; k++)
                    opened[k] = MC.open(vs[k ^ P.my_num()].get_bit(index), P);
                auto& to_test = opened[P.my_num()];
                assert(to_test == B_input[j].get() % 2);
            }
        }
    }

    int v_index = 0;
    size_t idx = 0;
    for (auto& shuffle : perms)
        for (size_t i = 0; i < n; i++)
        {
            shuffle->B.add(i, B.dot(vs[v_index].part(idx * mid_size, mid_size)));
            shuffle->C.add(i, B.dot(vs[1 - v_index].part(idx * mid_size, mid_size)));
            idx += 1;
        }

    if (debug)
    {
        SemiMC<SemiShare<Bit>> MC;
        octetStream os;
        os.store(perms[0]->pi);
        P.exchange_relative(1, os);
        vector<unsigned> other_pi;
        os.get(other_pi);

        for (size_t i = 0; i < n; i++)
        {
            array<int128, 2> w = {perms[0]->B.values[i].first, perms[0]->C.values[i].first};
            cout << "B=" << w[0] << " C=" << w[1] << endl;

            octetStream os;
            os.store(w);

            P.exchange_relative(1, os);

            array<int128, 2> out;
            os.get(out);
            cout << "got " << out[0] << " " << out[1] << endl;
            cout << "comb options ";
            for (int j = 0; j < 2; j++)
                for (int k = 0; k < 2; k++)
                    cout << "my " << (j ? "C" : "B") << " their " << (k ? "C" : "B") << " " << (w[j] ^ out[k]) << ", ";
            cout << endl;
            auto for_test = out[1] ^ w[0];
            auto to_test = perms[0]->A.values.at(other_pi.at(i)).first;
            cout << "test output " << for_test << " " << to_test << endl;
            assert(for_test == to_test);
        }

    }

    assert(not ds.left());
    assert(not ts.left());
}

#ifdef USE_TUNGSTEN
template<class T>
SemiSecureStateBase<T>::SemiSecureStateBase(Player& P) :
        P(P)
{
    CODE_LOCATION

    co_sockets[0] = new PlayerCoSocket(P);

    for (int i = 1; i < 4; i++)
        co_sockets[i] = new PlayerCoSocket(*P.fork(to_string(i)));

    for (int i = 0; i < 2; i++)
    {
        works[i] = pools[i].make_work();
        pools[i].create_threads(1);
    }

    auto ot_setup = BaseMachine::fresh_ot_setup(*ShareThread<SemiSecret>::s().P);
    BitVector bits;
    bits.resize(secJoin::AltModPrf::KeySize);
    SeededPRNG G;
    bits.randomize(G);
    base_bits = {bits.get_ptr(), bits.size()};

    VirtualTwoPartyPlayer player(P, 1 - P.my_num());
    auto base = ot_setup.get_base(0);
    OTExtensionWithMatrix ext(base, &player, false);
    ext.extend(bits.size(), bits);

    for (int i = 0; i < 2; i++)
    {
        auto& x = ext.senderOutputMatrices;
        for (unsigned j = 0; j < bits.size(); j++)
        {
            G_sender[i ^ P.my_num()].push_back({});
            for (int k = 0; k < 2; k++)
                G_sender[i ^ P.my_num()].back().at(k).SetSeedFrom(
                        int128(x.at(k).at(j)));
            G_receiver[i ^ P.my_num()].push_back({});
            G_receiver[i ^ P.my_num()].back().SetSeedFrom(
                    int128(ext.receiverOutputMatrix.at(j)));
        }
    }

    pthread_create(&thread, 0, run_thread, this);
}

template<class T>
SemiSecureStateBase<T>::~SemiSecureStateBase()
{
    for (auto socket : co_sockets)
        delete socket;
    job_queue.stop();
    pthread_join(thread, 0);
}

template<class T>
void* SemiSecureStateBase<T>::run_thread(void* state)
{
    assert(state);
    ((SemiSecureStateBase*) state)->run();
    return 0;
}

template<class T>
void SemiSecureStateBase<T>::run()
{
    const void* job;
    while (job_queue.pop(job))
    {
        ((T*) this)->generate_role(*(typename T::job_type*) job, 1);
        res_queue.push(job);
    }
}

template<class T>
template<class U>
void SemiSecureStateBase<T>::set_sender_base_ots(int role, U& sender)
{
    auto outputs = base_receiver_ots(role);
    osuCrypto::BitVector tmp;
    tmp = base_bits;
    tmp.resize(128);
    sender.setBaseOts(outputs, tmp);
}

template<class T>
vector<osuCrypto::block> SemiSecureStateBase<T>::base_receiver_ots(int role,
        size_t size)
{
    vector<osuCrypto::block> outputs;
    for (unsigned i = 0; i < size; i++)
    {
        auto& x = G_receiver.at(role).at(i);
        outputs.push_back(x.get_doubleword());
    }
    return outputs;
}

template<class T>
template<class U>
void SemiSecureStateBase<T>::set_receiver_base_ots(int role, U& receiver)
{
    auto inputs = base_sender_ots(role);
    receiver.setBaseOts(inputs);
}

template<class T>
vector<array<osuCrypto::block, 2>> SemiSecureStateBase<T>::base_sender_ots(
        int role, size_t size)
{
    vector<array<osuCrypto::block, 2>> inputs;
    for (unsigned i = 0; i < size; i++)
    {
        auto& x = G_sender.at(role).at(i);
        inputs.push_back({});
        for (int i = 0; i < 2; i++)
            inputs.back()[i] = x[i].get_doubleword();
    }
    return inputs;
}

template<class T>
void SemiSecureStateBase<T>::generate(const void* job)
{
    job_queue.push(job);
    ((T*) this)->generate_role(*(typename T::job_type*) job, 0);
    assert(res_queue.pop() == job);
}

class PermEnsemble
{
public:
    secJoin::Perm pi;
    secJoin::PermCorSender sender_perm;
    secJoin::AltModPermGenSender perm_gen_sender;

    secJoin::PermCorReceiver receiver_perm;
    secJoin::AltModPermGenReceiver perm_gen_receiver;
    secJoin::AltModPrf::KeyType tmp;
    optional<secJoin::AltModPrf::KeyType> key;
};

void SemiSecureShuffleState::generate_role(job_type& job,
        int role)
{
    auto n = job.first;
    auto& perms = job.second;

    bool debug = OnlineOptions::singleton.has_option("debug_binshuffle");
    if (debug)
        fprintf(stderr,
                "starting shuffle of size %zu with role %d and state %p\n", n,
                role, (void*) this);

    auto state = this;
    assert(state);
    coproto::Socket socket2({},
            *state->co_sockets[2 + (role ^ state->P.my_num())]);

    int rowSize = 16;

    auto& oles = state->oles;
    auto& prngs = state->prngs;

    auto& ole = oles[role];
    auto& prng = prngs[role];

    coproto::Socket socket({}, *state->co_sockets[role ^ state->P.my_num()]);
    socket.setExecutor(state->pools[role]);
    ole.init(std::move(socket), prngs[role], role, 1, 1 << 16, 0);
    ole.mGenState->mPool = &state->pools[role];

    vector<PermEnsemble> ensembles(perms.size());

    if (role == 0)
    {
        auto& vole = ole.mGenState->mRecvVoleBase;

        vole.mOtExtSender.emplace();
        vole.mOtExtRecver.emplace();

        state->set_sender_base_ots(role, *vole.mOtExtSender);
        state->set_receiver_base_ots(role, *vole.mOtExtRecver);
        state->set_receiver_base_ots(role, ole.mGenState->mRecvOtBase);

        for (size_t i = 0; i < perms.size(); i++)
        {
            auto& perm = *perms[i];
            auto& x = ensembles[i];

            if (perm.pi.empty())
                x.pi = {n, prng};
            else
            {
                assert(perm.pi.size() == n);
                x.pi.mPi = perm.pi;
            }

            auto ots = base_sender_ots(role, secJoin::AltModPrf::KeySize);
            x.perm_gen_sender.init(n, rowSize, ole, ots);
        }
    }
    else
    {
        auto& vole = ole.mGenState->mSendVoleBase;

        vole.mOtExtSender.emplace();
        vole.mOtExtRecver.emplace();

        state->set_sender_base_ots(role, *vole.mOtExtSender);
        state->set_receiver_base_ots(role, *vole.mOtExtRecver);
        state->set_sender_base_ots(role, ole.mGenState->mSendOtBase);

        for (auto& x : ensembles)
        {
            auto ots = base_receiver_ots(role, secJoin::AltModPrf::KeySize);
            for (int i = 0; i < secJoin::AltModPrf::KeySize / 128; i++)
                x.tmp.at(i) = base_bits.blocks()[i];
            x.key.emplace(x.tmp);
            x.perm_gen_receiver.init(n, rowSize, ole, x.key, ots);
        }
    }

    auto t = ole.start() | macoro::start_on(state->pools[role]);

    for (size_t i = 0; i < perms.size(); i++)
    {
        auto& perm = *perms[i];
        auto& x = ensembles[i];

        if (role == 0)
        {
            macoro::sync_wait(
                    x.perm_gen_sender.generate(x.pi, prng, socket2, x.sender_perm));

            perm.pi = x.pi.mPi;
            perm.C = {x.sender_perm.mDelta, n};
        }
        else
        {
            macoro::sync_wait(
                    x.perm_gen_receiver.generate(prng, socket2, x.receiver_perm));

            perm.A = {x.receiver_perm.mA, n};
            perm.B = {x.receiver_perm.mB, n};
        }

        x = {};
    }

    if (debug)
        fprintf(stderr,
                "finished shuffle of size %zu with role %d and state %p\n", n,
                role, (void*) state);

    macoro::sync_wait(t);
    auto ptr = ole.mStarted.back().lock();
    if (ptr)
        osuCrypto::cp::sync_wait(ptr->mSock.flush());

    osuCrypto::cp::sync_wait(socket2.flush());

    if (debug)
        fprintf(stderr,
                "closed socket for shuffle of size %zu with role %d and state %p\n",
                n, role, (void*) state);
}


void SemiSecureTripleState::generate_role(job_type& job, int role)
{
    auto batch_size = job.first;
    auto& triples = job.second;
    auto state = this;

    auto& oles = state->oles;
    auto& prngs = state->prngs;

    auto& ole = oles[role];

    coproto::Socket socket({}, *state->co_sockets[role ^ state->P.my_num()]);
    socket.setExecutor(state->pools[role]);
    ole.init(std::move(socket), prngs[role], role, 1, 1 << 16, 0);
    ole.mGenState->mPool = &state->pools[role];

    if (role == 0)
    {
        state->set_receiver_base_ots(role, ole.mGenState->mRecvOtBase);
    }
    else
    {
        state->set_sender_base_ots(role, ole.mGenState->mSendOtBase);
    }

    auto req = ole.binOleRequest(max(256, batch_size));
    auto t0 = ole.start() | macoro::start_on(state->pools[role]);

    for (size_t i = 0; i < req.batchCount() - 1; i++)
    {
        secJoin::BinOle o;
        macoro::sync_wait(req.get(o));

        auto a = o.mMult.begin();
        auto b = a;
        auto c = o.mAdd.begin();

        if (role)
            a++;
        else
            b++;

        while (c + 1 < o.mAdd.end())
        {
            int128 aa(*a), bb(*b), cc(*c), dd(*(c + 1));
            cc ^= dd ^ (aa & bb);
            triples[role].push_back(
            { aa.get_lower(), bb.get_lower(), cc.get_lower() });
            triples[role].push_back(
            { aa.get_upper(), bb.get_upper(), cc.get_upper() });
            a += 2;
            b += 2;
            c += 2;
        }
    }

    macoro::sync_wait(t0);
}
#endif

void SemiSecureShuffle::apply(StackedVector<SemiSecret>& S,
        shuffle_type& shuffle, const BaseInstruction& instruction)
{
    CODE_LOCATION
    auto& party = ShareThread<SemiSecret>::s();
    assert(party.P);
    auto& P = *party.P;
    auto& args = instruction.get_start();
    assert(args.size() % 2 == 1);
    assert(args[2] < 2);

    ShuffleTuple<shuffle_type> shuffle_tuple(args[0], 0, 0, (args.size() - 3) / 2, shuffle,
            args[2]);
    size_t dl = SemiSecret::default_length;
    assert(shuffle_tuple.unit_size <= dl);
    int n_units =  DIV_CEIL(shuffle_tuple.shuffle_size(), dl);

    if (not shuffle_tuple.shuffle.A.has_enough(shuffle_tuple.unit_size))
        full_generate(shuffle_tuple.shuffle_size(), {&shuffle_tuple.shuffle});

    StackedVector<SemiSecret> tmp(shuffle_tuple.shuffle_size()), tmp2;

    for (size_t i = 4; i < args.size(); i += 2)
        for (int j = 0; j < n_units; j++)
            tmp2.push_back(S[args[i] + j]);

    ArgVector trans_args(shuffle_tuple.shuffle_size() + shuffle_tuple.unit_size);
    iota(trans_args.begin(), trans_args.begin() + shuffle_tuple.shuffle_size(), 0);
    for (size_t i = 0; i < shuffle_tuple.unit_size; i++)
        trans_args[i + shuffle_tuple.shuffle_size()] = i * n_units;
    SemiSecret::trans(tmp, tmp2, shuffle_tuple.shuffle_size(), trans_args);

    apply_role(tmp, shuffle_tuple, P, args[2] ^ P.my_num());
    apply_role(tmp, shuffle_tuple, P, args[2] ^ (1 - P.my_num()));

    for (size_t i = 0; i < shuffle_tuple.unit_size; i++)
        trans_args[i] = i * n_units;
    iota(trans_args.begin() + shuffle_tuple.unit_size, trans_args.end(), 0);
    SemiSecret::trans(tmp2, tmp, shuffle_tuple.unit_size, trans_args);

    auto it = tmp2.begin();
    for (size_t i = 3; i < args.size(); i += 2)
        for (int j = 0; j < n_units; j++)
            S[args[i] + j] = *it++;
}

void SemiSecureShuffle::apply_role(StackedVector<SemiSecret>& S,
        ShuffleTuple<shuffle_type>& shuffle, Player& P, int role)
{
    octetStream os;
    size_t n = shuffle.shuffle_size();
    int n_bits = shuffle.unit_size;

    if (role)
    {
        for (size_t i = 0; i < shuffle.shuffle_size(); i++)
        {
            auto& dest = S[shuffle.dest + i];
            auto a = shuffle.shuffle.A.get(i, n_bits);
            auto b = shuffle.shuffle.B.get(i, n_bits);

            if (shuffle.reverse)
            {
                (dest - b).pack(os, n_bits);
                dest = a;
            }
            else
            {
                (dest - a).pack(os, n_bits);
                dest = b;
            }
        }
        os.append(0);
        P.send_to(1 - P.my_num(), os);
    }
    else
    {
        P.receive_player(1 - P.my_num(), os);
        vector<unsigned> pi(shuffle.shuffle_size());

        if (shuffle.reverse)
        {
            for (size_t i = 0; i < shuffle.shuffle_size(); i++)
                pi[shuffle.shuffle.pi[i]] = i;
        }
        else
            pi = shuffle.shuffle.pi;

        auto& C = shuffle.shuffle.C;
        vector<SemiSecret> tmp(n), deltas(n);
        for (size_t i = 0; i < shuffle.shuffle_size(); i++)
        {
            tmp[i] = S[shuffle.dest + i];
            deltas[i].unpack(os, n_bits);
        }

        for (size_t i = 0; i < shuffle.shuffle_size(); i++)
        {
            auto perm_i = pi[i];
            auto& res = S[shuffle.dest + i];

            if (shuffle.reverse)
                res = deltas[perm_i] + C.get(perm_i, n_bits) + tmp[perm_i];
            else
                res = deltas[perm_i] + C.get(i, n_bits) + tmp[perm_i];
        }

        assert(not os.left());
    }
}

#ifdef USE_TUNGSTEN
template SemiSecureStateBase<SemiSecureTripleState>::SemiSecureStateBase(Player& P);
template void SemiSecureStateBase<SemiSecureTripleState>::generate(void const*);
#endif

} /* namespace GC */
