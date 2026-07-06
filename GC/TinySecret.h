/*
 * TinySecret.h
 *
 */

#ifndef GC_TINYSECRET_H_
#define GC_TINYSECRET_H_

#include "Secret.h"
#include "TinyShare.h"
#include "ShareParty.h"
#include "OT/Rectangle.h"
#include "OT/BitDiagonal.h"

template<class T> class NPartyTripleGenerator;
template<class T> class OTTripleGenerator;
template<class T> class TinyMultiplier;

namespace GC
{

template<class T> class TinyOnlyPrep;
template<class T> class TinyMC;
template<class T> class VectorProtocol;
template<class T> class VectorInput;
template<class T> class CcdPrep;

template<class T>
class VectorSecret : public Secret<T>
{
    typedef VectorSecret This;

public:
    typedef T part_type;
    typedef Secret<part_type> super;

    typedef typename part_type::mac_key_type mac_key_type;

    typedef BitVec open_type;
    typedef BitVec clear;

    typedef typename part_type::sacri_type sacri_type;
    typedef typename part_type::mac_type mac_type;
    typedef typename part_type::mac_share_type mac_share_type;
    typedef BitDiagonal Rectangle;

    typedef typename T::super check_type;

    static const bool dishonest_majority = T::dishonest_majority;
    static const bool variable_players = T::variable_players;
    static const bool needs_ot = T::needs_ot;
    static const bool has_mac = T::has_mac;
    static const bool malicious = T::malicious;
    static const bool expensive_triples = T::expensive_triples;
    static const bool randoms_for_opens = false;
    static const bool symmetric = true;
    static const bool function_dependent = T::function_dependent;

    static const int default_length = 64;

    static bool real_shares(const Player&)
    {
        return true;
    }

    static int size()
    {
        return part_type::size() * default_length;
    }

    static void specification(octetStream& os)
    {
        T::specification(os);
    }

    static void read_or_generate_mac_key(string directory, const Player& P,
            mac_key_type& key)
    {
        T::read_or_generate_mac_key(directory, P, key);
    }

    static typename T::mac_type get_mac_key()
    {
        return T::get_mac_key();
    }

    static void set_mac_key(mac_key_type& mac_key)
    {
        part_type::set_mac_key(mac_key);
    }

    template<class U>
    static void reveal_inst(U& processor, const ArgVector& args)
    {
        T::reveal_inst(processor, args);
    }

    static This constant(BitVec other, int my_num, mac_key_type alphai,
            int n_bits = -1)
    {
        if (n_bits < 0)
            n_bits = other.length();
        This res;
        res.resize_regs(n_bits);
        for (int i = 0; i < n_bits; i++)
            res.get_reg(i) = part_type::constant(other.get_bit(i), my_num, alphai);
        return res;
    }

    VectorSecret()
    {
    }
    VectorSecret(const super& other) :
            super(other)
    {
    }
    VectorSecret(const Clear& other) :
            super(other)
    {
    }
    VectorSecret(const part_type& other)
    {
        this->get_regs().push_back(other);
    }

    void assign(const char* buffer)
    {
        this->resize_regs(default_length);
        for (int i = 0; i < default_length; i++)
            this->get_reg(i).assign(buffer + i * part_type::size());
    }

    This operator-(const This& other) const
    {
        return *this + other;
    }

    This& operator^=(const This& other)
    {
        return *this = *this + other;
    }

    This operator*(const BitVec& other) const
    {
        This res = *this;
        for (int i = 0; i < super::size(); i++)
            if (not other.get_bit(i))
                res.get_reg(i) = {};
        return res;
    }

    This operator&(const BitVec::super& other) const
    {
        return *this * BitVec(other);
    }

    void extend_bit(This& res, int n_bits) const
    {
        auto& regs = res.get_regs();
        regs.assign(n_bits, this->get_reg(0));
    }

    void mask(This& res, int n_bits) const
    {
        if (this != &res)
            res.get_regs().assign(this->get_regs().begin(),
                    this->get_regs().begin()
                            + min(size_t(n_bits), this->get_regs().size()));

        res.resize_regs(n_bits);
    }

    T get_bit(int i) const
    {
        return this->get_reg(i);
    }

    void xor_bit(size_t i, const T& bit)
    {
        if (i < this->get_regs().size())
            XOR(this->get_reg(i), this->get_reg(i), bit);
        else
        {
            this->resize_regs(i + 1);
            this->get_reg(i) = bit;
        }
    }

    void output(ostream& s, bool human = true) const
    {
        assert(this->get_regs().size() == default_length);
        for (auto& reg : this->get_regs())
            reg.output(s, human);
    }

    void input(istream&, bool)
    {
        throw not_implemented();
    }

    template <class U>
    void my_input(U& inputter, BitVec value, int n_bits)
    {
        inputter.add_mine(value, n_bits);
    }

    template <class U>
    void other_input(U& inputter, int from, int n_bits)
    {
        inputter.add_other(from, n_bits);
    }

    template <class U>
    void finalize_input(U& inputter, int from, int n_bits)
    {
        inputter.finalize(from, n_bits).mask(*this, n_bits);
    }

    void random_bit()
    {
        auto& thread = GC::ShareThread<typename T::whole_type>::s();
        *this = thread.DataF.get_part().get_bit();
    }
};

template<int S>
class TinySecret : public VectorSecret<TinyShare<S>>
{
    typedef VectorSecret<TinyShare<S>> super;
    typedef TinySecret This;

public:
    typedef TinyMC<This> MC;
    typedef MC MAC_Check;
    typedef VectorProtocol<This> Protocol;
    typedef VectorInput<This> Input;
    typedef CcdPrep<This> LivePrep;
    typedef Memory<This> DynamicMemory;

    typedef OTTripleGenerator<This> TripleGenerator;
    typedef typename super::part_type::TripleGenerator InputGenerator;

    typedef TinyMultiplier<This> Multiplier;

    static string type_short()
    {
        return "T";
    }

    static MC* new_mc(typename super::mac_key_type mac_key)
    {
        return new MC(mac_key);
    }

    static void store_clear_in_dynamic(Memory<This>& mem,
            const vector<ClearWriteAccess>& accesses)
    {
        auto& party = ShareThread<This>::s();
        for (auto access : accesses)
            mem[access.address] = super::constant(access.value,
                    party.P->my_num(), {});
    }

    static void generate_mac_key(typename This::mac_key_type& dest,
            const typename This::mac_key_type& source)
    {
        dest = source;
    }

    TinySecret()
    {
    }
    TinySecret(const typename super::super& other) :
            super(other)
    {
    }
    TinySecret(const typename super::part_type& other) :
            super(other)
    {
    }

    void reveal(size_t n_bits, Clear& x)
    {
        auto& to_open = *this;
        to_open.resize_regs(n_bits);
        auto& party = ShareThread<This>::s();
        x = party.MC->POpen(to_open, *party.P);
    }
};

template<class U>
const int VectorSecret<U>::default_length;

template<class T>
inline VectorSecret<T> operator*(const BitVec& clear, const VectorSecret<T>& share)
{
    return share * clear;
}

} /* namespace GC */

#endif /* GC_TINYSECRET_H_ */
