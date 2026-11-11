/*
 * Triple.hpp
 *
 */

#ifndef OT_TRIPLE_HPP_
#define OT_TRIPLE_HPP_

template<class T> class NPartyTripleGenerator;

template <class T, int N>
class Triple
{
public:
    T a[N];
    T b;
    T c[N];

    int repeat(int l, bool check)
    {
        switch (l)
        {
        case 0:
        case 2:
            if (check)
                return N;
            else
                return 1;
        case 1:
            return 1;
        default:
            throw bad_value();
        }
    }

    T& byIndex(int l, int j)
    {
        switch (l)
        {
        case 0:
            return a[j];
        case 1:
            return b;
        case 2:
            return c[j];
        default:
            throw bad_value();
        }
    }

    template <int M>
    void amplify(const Triple<T,M>& uncheckedTriple, PRNG& G, int nAmplify)
    {
        b = uncheckedTriple.b;
        for (int i = 0; i < N; i++)
            for (int j = 0; j < nAmplify; j++)
            {
                typename T::value_type r;
                r.randomize(G);
                a[i] += r * uncheckedTriple.a[j];
                c[i] += r * uncheckedTriple.c[j];
            }
    }

    void output(ostream& outputStream, int n = N, bool human = false)
    {
        for (int i = 0; i < n; i++)
        {
            a[i].output(outputStream, human);
            b.output(outputStream, human);
            c[i].output(outputStream, human);
        }
    }

    template<class V>
    Triple<V, 1> reduce()
    {
        Triple<V, 1> triple;
        for (int i = 0; i < 3; i++)
            triple.byIndex(i, 0) = byIndex(i, 0);
        return triple;
    }
};

template <class T, int N>
class PlainTriple : public Triple<T,N>
{
public:
    // this assumes that valueBits[1] is still set to the bits of b
    void to(vector<BitVector>& valueBits, int i, int repeat = N)
    {
        for (int j = 0; j < N; j++)
        {
            valueBits[0].set_portion(i * repeat + j, this->a[j]);
            valueBits[2].set_portion(i * repeat + j, this->c[j]);
        }
    }
};

// T is Z2<K + 2S>, U is Z2<K + S>
template <class T, class U, int N>
class PlainTriple_ : public PlainTriple<T,N>
{
public:

    template <int M>
    void amplify(BitVector& a, U& b, Rectangle<Z2<M>, U>& c, PRNG& G)
    {
        assert(a.size() == M);
        this->b = b;
        for (int i = 0; i < N; i++)
        {
            U aa = 0, cc = 0;
            for (int j = 0; j < M; j++)
            {
                U r;
                r.randomize(G);
                if (a.get_bit(j))
                    aa += r;
                cc += U::Mul(r, c.rows[j]);
            }
            this->a[i] = aa;
            this->c[i] = cc;
        }
    }
};

template <class U, int N>
class ShareTriple : public Triple<U, N>
{
    typedef typename U::open_type T;

public:
    template<class V>
    void from(PlainTriple<T,N>& triple,
            int iTriple, const NPartyTripleGenerator<V>& generator)
    {
        for (int l = 0; l < 3; l++)
        {
            int repeat = this->repeat(l, generator.machine.check);
            for (int j = 0; j < repeat; j++)
            {
                typename U::share_type value = triple.byIndex(l,j);
                typename U::mac_type mac;
                mac = (value * generator.get_mac_key());
                for (int i = 0; i < generator.nparties-1; i++)
                    mac += generator.ot_multipliers[i]->macs.at(l).at(iTriple * repeat + j);
                U& share = this->byIndex(l,j);
                share.set_share(value);
                share.set_mac(mac);
            }
        }
    }
};

template <class T>
class TripleToSacrifice : public Triple<T, 1>
{
public:
    template <class W>
    void prepare_sacrifice(const Triple<T, 2>& uncheckedTriple, PRNG& G)
    {
        this->b = uncheckedTriple.b;
        typename W::mac_key_type t;
        t.randomize(G);
        this->a[0] = uncheckedTriple.a[0] * t - uncheckedTriple.a[1];
        this->c[0] = uncheckedTriple.c[0] * t - uncheckedTriple.c[1];
    }

    T computeCheckShare(const typename T::open_type& maskedA)
    {
        return this->c[0] - maskedA * this->b;
    }
};

#endif /* OT_TRIPLE_HPP_ */
