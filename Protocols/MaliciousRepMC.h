/*
 * MaliciousRepMC.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSREPMC_H_
#define PROTOCOLS_MALICIOUSREPMC_H_

#include "ReplicatedMC.h"

template<class T>
class MaliciousRepMC : public ReplicatedMC<T>
{
protected:
    typedef ReplicatedMC<T> super;

public:
    MaliciousRepMC(typename T::mac_key_type = {})
    {
    }

    virtual void POpen(vector<typename T::open_type>&,
            const vector<T>&, const Player&)
    {
        throw runtime_error("use subclass");
    }

    virtual void POpen_Begin(vector<typename T::open_type>& values,
            const vector<T>& S, const Player& P);

    virtual void POpen_End(vector<typename T::open_type>&,
            const vector<T>&, const Player&)
    {
        throw runtime_error("use subclass");
    }

    virtual void Check(const Player&)
    {
        throw runtime_error("use subclass");
    }

    MaliciousRepMC& get_part_MC()
    {
        return *this;
    }
};

/**
 * 3-party replicated opening with checking via hash
 */
template<class T>
class HashMaliciousRepMC : public MaliciousRepMC<T>
{
    Hash hash;

    octetStream os;

    bool needs_checking;

    vector<octetStream> to_send, to_receive;
    octetStream hash_buffer;

    void reset();
    void update();

    void prepare(const vector<T>& secrets, const Player& P);
    void finalize(vector<typename T::open_type>& values,
            const vector<T>& secrets, const Player& P);

public:
    // emulate MAC_Check
    HashMaliciousRepMC(const typename T::mac_key_type& _, int __ = 0, int ___ = 0) : HashMaliciousRepMC()
    { (void)_; (void)__; (void)___; }

    // emulate Direct_MAC_Check
    HashMaliciousRepMC(const typename T::mac_key_type& _, Names& ____, int __ = 0, int ___ = 0) : HashMaliciousRepMC()
    { (void)_; (void)__; (void)___; (void)____; }

    HashMaliciousRepMC();
    ~HashMaliciousRepMC();

    void POpen(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);
    void POpen_Begin(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);
    void POpen_End(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);

    virtual void exchange(const Player& P);
    virtual typename T::open_type finalize_raw();

    void CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P);

    void Check(const Player& P);
};

template<class T>
class CommMaliciousRepMC : public MaliciousRepMC<T>
{
    vector<octetStream> os;

public:
    void POpen(vector<typename T::clear>& values, const vector<T>& S,
            const Player& P);
    void POpen_Begin(vector<typename T::clear>& values, const vector<T>& S,
            const Player& P);
    void POpen_End(vector<typename T::clear>& values, const vector<T>& S,
            const Player& P);

    void Check(const Player& P);
};

#endif /* PROTOCOLS_MALICIOUSREPMC_H_ */
