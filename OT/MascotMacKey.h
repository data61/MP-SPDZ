/*
 * MascotMacKey.h
 *
 */

#ifndef OT_MASCOTMACKEY_H_
#define OT_MASCOTMACKEY_H_

template<class share_type>
string get_ot_secrets_filename(const Player& P);

template<class T>
class MascotMacKey : public T
{
    MascotMacKey(const MascotMacKey&) = default;

public:
    OTTripleSetup ot;

    MascotMacKey() = default;

    MascotMacKey& operator=(MascotMacKey&&) = default;

    template<class share_type>
    void read_or_generate(Player& P);

    void pack(octetStream& os) const
    {
        T::pack(os);
        ot.pack(os);
    }

    void unpack(octetStream& os)
    {
        T::unpack(os);
        ot.unpack(os);
    }

    template<class U = T>
    MascotMacKey<U> get_fresh()
    {
        MascotMacKey<U> res;
        res.U::operator=(U(*this));
        res.ot = ot.get_fresh();
        return res;
    }
};

#endif /* OT_MASCOTMACKEY_H_ */
