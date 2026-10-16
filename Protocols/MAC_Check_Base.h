/*
 * MAC_Check_Base.h
 *
 */

#ifndef PROTOCOLS_MAC_CHECK_BASE_H_
#define PROTOCOLS_MAC_CHECK_BASE_H_

#include <vector>
using namespace std;

#include "Networking/Player.h"
#include "Tools/PointerVector.h"

template<class T> class Preprocessing;
template<class T> class MatrixMC;

/**
 * Abstract base class for opening protocols
 */
template<class T>
class MAC_Check_Base
{
    friend class MatrixMC<T>;

protected:
    /* MAC Share */
    typename T::mac_key_type::Scalar alphai;

    PointerVector<T> secrets;
    PointerVector<typename T::open_type> values;

public:
    size_t values_opened;

    static void setup(Player&) {}
    static void teardown() {}

    MAC_Check_Base(const typename T::mac_key_type::Scalar& mac_key = { }) :
            alphai(mac_key), values_opened(0) {}
    virtual ~MAC_Check_Base() {}

    /// Run checking protocol
    virtual void Check(const Player& P) { (void)P; }

    int number() const { return values_opened; }

    /// Get MAC key
    const typename T::mac_key_type::Scalar& get_alphai() const { return alphai; }

    virtual void POpen_Begin(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);
    virtual void POpen_End(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);
    /// Open values in ``S`` and store results in ``values``
    virtual void POpen(vector<typename T::open_type>& values,const vector<T>& S,const Player& P);
    typename T::open_type POpen(const T& secret, const Player& P);
    /// Open single value
    typename T::open_type open(const T& secret, const Player& P) { return POpen(secret, P); }

    /// Initialize opening round
    virtual void init_open(const Player& P, int n = 0);
    /// Add value to be opened
    virtual void prepare_open(const T& secret, int n_bits = -1);
    /// Run opening protocol
    virtual void exchange(const Player& P) = 0;
    /// Get next opened value
    virtual typename T::clear finalize_open();
    virtual typename T::open_type finalize_raw();
    virtual array<typename T::open_type*, 2> finalize_several(size_t n);

    virtual void start_exchange(const Player& P);
    virtual void stop_exchange(const Player& P);

    /// Check whether all ``shares`` are ``value``
    virtual void CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P);

    virtual const Player& get_check_player(const Player& P) const { return P; }

    virtual void set_prep(Preprocessing<T>&) {}

    void set_random_element(const T&) {}
};

#endif /* PROTOCOLS_MAC_CHECK_BASE_H_ */
