/*
 * AstraShare.h
 *
 */

#ifndef PROTOCOLS_ASTRASHARE_H_
#define PROTOCOLS_ASTRASHARE_H_

#include "Math/Z2k.h"
#include "Math/FixedVec.h"
#include "ShareInterface.h"
#include "NoShare.h"
#include "Rep3Share2k.h"

template<class T> class Astra;
template<class T> class AstraMC;
template<class T> class AstraPrepProtocol;
template<class T> class AstraInput;
template<class T> class AstraPrepInput;
template<class T> class AstraPrep;
template<class T> class AstraPrepPrep;

namespace GC
{
template<class T> class AstraSecret;
}

template<class T>
class AstraShare : public ShareInterface, public FixedVec<T, 2>
{
    typedef FixedVec<T, 2> super;
    typedef AstraShare This;

public:
    typedef This share_type;

    // type for clear values in relevant domain
    typedef T clear;
    typedef clear open_type;

    typedef GC::AstraSecret<AstraShare<BitVec>> bit_type;

    // opening facility
    typedef AstraMC<This> MAC_Check;
    typedef MAC_Check Direct_MC;

    // multiplication protocol
    typedef Astra<This> Protocol;

    // preprocessing facility
    typedef AstraPrep<This> LivePrep;

    // private input facility
    typedef AstraInput<This> Input;

    // default private output facility (using input tuples)
    typedef ::PrivateOutput<This> PrivateOutput;

    template<class U>
    using mc_template = AstraMC<U>;
    template<class U>
    using protocol_template = Astra<U>;
    template<class U>
    using input_template = AstraInput<U>;

    // indicate whether protocol allows dishonest majority and variable players
    static const bool dishonest_majority = true;
    static const bool variable_players = false;
    static const bool has_trunc_pr = true;
    static const bool function_dependent = true;

    // description used for debugging output
    static string type_string()
    {
        return "Astra share " + T::type_string();
    }

    // used for preprocessing storage location
    static string type_short()
    {
        return "astra-" + T::type_short();
    }

    // maximum number of corrupted parties
    // only used in virtual machine instruction
    static int threshold(int)
    {
        return 1;
    }

    // serialize computation domain for client communication
    static void specification(octetStream& os)
    {
        T::specification(os);
    }

    // constant secret sharing
    static This constant(const clear& value, int my_num = -1,
            const mac_key_type& = {})
    {
        This res;
        res.m(my_num + 1) = value;
        return res;
    }

    AstraShare()
    {
    }
    template<class U>
    AstraShare(const U& other) :
            super(other)
    {
    }

    T& m(int)
    {
        return (*this)[0];
    }

    const T& m(int) const
    {
        return (*this)[0];
    }

    const T& common_m() const
    {
        return m(-1);
    }

    void set_common_m(const T& x)
    {
        m(-1) = x;
    }

    T& neg_lambda(int)
    {
        return (*this)[1];
    }

    const T& neg_lambda(int) const
    {
        return (*this)[1];
    }

    T lambda(int my_num) const
    {
        return -neg_lambda(my_num);
    }

    static This from_astra(FixedVec<T, 2>& x)
    {
        return x;
    }

    T local_mul_P0(const This& other) const;
    T local_mul_P1(const This& other) const;
    T local_mul_P2(const This& other) const;

    template<class U, int MY_NUM>
    static void pre_reduced_mul(U& a, U& b, U& c, Astra<U>& protocol,
            const T& aa, const T& bb);

    template<class U, int MY_NUM>
    static pair<U, clear> post_reduced_mul(typename U::Protocol & protocol);

    template<class U, int MY_NUM>
    static void pre_input0(const clear&, typename U::Protocol&)
    {
    }

    template<class U, int MY_NUM>
    static This post_input0(typename U::Protocol& protocol);

    void pack(octetStream& os, T) const
    {
        super::pack(os);
    }
    void pack(octetStream& os, bool full = true) const
    {
        assert(full);
        super::pack(os);
    }
    void unpack(octetStream& os, bool full = true)
    {
        assert(full);
        super::unpack(os);
    }

    static int split_index(int arithmetic_index, int my_num)
    {
        unsigned res;
        if (arithmetic_index == 0)
            // m
            res = 0;
        else if (arithmetic_index == 1)
            // my lambda
            res = my_num + 1;
        else
            // other lambda
            res = 2 - my_num;
        assert(res < 3);
        return res;
    }

    static bool matters_for_split(int, int)
    {
        return true;
    }

    static This from_rep3(const FixedVec<T, 2>& x)
    {
        return x;
    }

    template<class U, class V>
    static void split(StackedVector<U>& dest,
            const ArgVector& regs, int n_bits, const V* source,
            int n_inputs, typename U::Protocol& protocol)
    {
        switch (regs.size() / n_bits)
        {
        case 3:
            Rep3Share2<T::N_BITS>::split(dest, regs, n_bits, source, n_inputs, protocol);
            break;
        case 2:
            V::split2(dest, regs, n_bits, source, n_inputs, protocol);
            break;
        default:
            throw runtime_error("only 2-way and 3-way split is implemented");

        }
    }

    template<class U, class V>
    static void split2(StackedVector<U>& dest,
            const ArgVector& regs, int n_bits, const V* source,
            int n_inputs, typename U::Protocol& protocol)
    {
        assert(regs.size() / n_bits == 2);
        int unit = U::default_length;
        assert(n_bits <= unit);
        octetStream os;
        protocol.read(os);
        int my_num = protocol.P.my_num();
        int n_blocks = DIV_CEIL(n_inputs, unit);
        os.require<U>(n_bits * n_blocks);
        vector<typename StackedVector<U>::iterator> iterators[2];
        for (int i = 0; i < 2; i++)
            for (int j = 0; j < n_bits; j++)
                iterators[i].push_back(
                        dest.iterator_for_size(regs.at(2 * j + i), n_blocks));
        for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
        {
            int start = k * unit;
            for (auto& it : iterators[0])
                os.get_no_check(*it++);
            int m = min(unit, n_inputs - start);
            square64 square;
            for (int j = 0; j < m; j++)
                square.rows[j] = Integer(source[j + start].for_split(0)).get();
            square.transpose(m, n_bits);
            for (int j = 0; j < n_bits; j++)
            {
                auto& dest_reg = *iterators[1][j]++;
                dest_reg.m(my_num) = square.rows[j];
                dest_reg.neg_lambda(my_num) = {};
                dest_reg = U::from_rep3(dest_reg);
            }

        }
    }

    template<class U>
    static void shrsi(SubProcessor<U>& proc, const Instruction& inst)
    {
        for (int i = 0; i < inst.get_size(); i++)
        {
            auto& dest = proc.get_S_ref(inst.get_r(0) + i);
            auto& source = proc.get_S_ref(inst.get_r(1) + i);
            dest = source >> inst.get_n();
        }
    }
};

template<class T>
class AstraPrepShare : public AstraShare<T>
{
    typedef AstraPrepShare This;
    typedef AstraShare<T> super;

public:
    typedef T clear;

    typedef GC::AstraSecret<AstraPrepShare<BitVec>> bit_type;

    // opening facility
    typedef ReplicatedMC<This> MAC_Check;
    typedef MAC_Check Direct_MC;

    // multiplication protocol
    typedef AstraPrepProtocol<This> Protocol;

    // preprocessing facility
    typedef AstraPrepPrep<This> LivePrep;

    // private input facility
    typedef AstraPrepInput<This> Input;

    // default private output facility (using input tuples)
    typedef ::PrivateOutput<This> PrivateOutput;

    template<class U>
    using mc_template = ReplicatedMC<U>;
    template<class U>
    using protocol_template = AstraPrepProtocol<U>;
    template<class U>
    using input_template = AstraPrepInput<U>;

    static bool real_shares(const Player&)
    {
        return false;
    }

    // constant secret sharing
    static This constant(const typename super::clear&, int = -1,
            const typename super::mac_key_type& = {})
    {
        return {};
    }

    AstraPrepShare()
    {
    }
    template<class U>
    AstraPrepShare(const U& other) :
            super(other)
    {
    }

    T& m(int my_num)
    {
        assert(my_num > 0);
        return super::m(my_num);
    }

    const T& m(int my_num) const
    {
        assert(my_num > 0);
        return super::m(my_num);
    }

    T& neg_lambda(int my_num)
    {
//        assert(my_num > 0);
        return super::neg_lambda(my_num);
    }

    const T& neg_lambda(int my_num) const
    {
        assert(my_num > 0);
        return super::neg_lambda(my_num);
    }

    T lambda(int my_num)
    {
        return -neg_lambda(my_num);
    }

    T neg_lambda_sum(int my_num)
    {
        assert(my_num == 0);
        return this->sum();
    }

    T local_mul_P0(const AstraPrepShare& other) const;
    T local_mul_P1(const AstraPrepShare& other) const;
    T local_mul_P2(const AstraPrepShare& other) const;

    template<class U, int MY_NUM>
    static void pre_reduced_mul(U& a, U& b, U& c, AstraPrepProtocol<U>& protocol,
            const T& aa, const T& bb);

    template<class U, int MY_NUM>
    static pair<U, typename super::clear> post_reduced_mul(typename U::Protocol&)
    {
        return pair<U, typename super::clear>();
    }

    template<class U, int MY_NUM>
    static void pre_input0(const clear& input, typename U::Protocol& protocol);

    template<class U, int MY_NUM>
    static This post_input0(typename U::Protocol& protocol);

    static int split_index(int arithmetic_index, int my_num)
    {
        unsigned res;
        if (my_num > 0)
            res = super::split_index(arithmetic_index, my_num - 1);
        else
            res = (arithmetic_index + 1) % 3;
        assert(res < 3);
        return res;
    }

    static bool matters_for_split(int i, int my_num)
    {
        return my_num == 0 or i == 0;
    }

    template<class U, class V>
    static void split2(StackedVector<U>& dest,
            const ArgVector& regs, int n_bits, const V* source,
            int n_inputs, typename U::Protocol& protocol)
    {
        assert(regs.size() / n_bits == 2);
        Rep3Share2<T::N_BITS>::split(dest, regs, n_bits, source, n_inputs, protocol);
        if (protocol.P.my_num() == 0)
            return;

        int unit = U::default_length;
        vector<typename StackedVector<U>::iterator> iterators;
        octetStream os;
        int n_blocks = DIV_CEIL(n_inputs, unit);
        os.reserve<U>(n_bits * n_blocks);
        for (int j = 0; j < n_bits; j++)
            iterators.push_back(
                    dest.iterator_for_size(regs.at(2 * j), n_blocks));
        for (int k = 0; k < n_blocks; k++)
        {
            for (auto& it : iterators)
            {
                auto& x = *it++;
                x = protocol.from_rep3(x);
                os.store_no_resize(x);
            }
        }
        protocol.store(os);
   }
};

template<int K>
using AstraShare2 = AstraShare<SignedZ2<K>>;
template<int K>
using AstraPrepShare2 = AstraPrepShare<SignedZ2<K>>;

#endif /* PROTOCOLS_ASTRASHARE_H_ */
