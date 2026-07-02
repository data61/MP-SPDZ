#ifndef PROTOCOLS_SHARE_H_
#define PROTOCOLS_SHARE_H_

#include "Share.h"
#include "Tools/pprint.h"

template<class T, class V>
typename Share_<T, V>::mac_key_type Share_<T, V>::mac_key;


template<class T, class V>
typename Share_<T, V>::mac_key_type Share_<T, V>::get_mac_key()
{
    return mac_key;
}

template<class T, class V>
void Share_<T, V>::set_mac_key(const mac_key_type& mac_key)
{
    Share_<T, V>::mac_key = mac_key;

    if (OnlineOptions::singleton.has_option("output_mac"))
    {
        octetStream os;
        mac_key.pack(os);
        cerr << mac_key.type_string() << " MAC key: " << mac_key << ", ";
        pprint_bytes("raw", (unsigned char*) os.get_data(), os.get_length(),
                cerr);
    }
}

template<class T, class V>
void Share_<T, V>::specification(octetStream& os)
{
    T::specification(os);
}

template<class T, class V>
void Share_<T, V>::randomize(PRNG& G)
{
  a.randomize(G);
  mac.randomize(G);
}

template<class T, class V>
inline void Share_<T, V>::pack(octetStream& os, bool full) const
{
  a.pack(os, full);
  if (full)
    mac.pack(os);
}

template<class T, class V>
inline void Share_<T, V>::unpack(octetStream& os, bool full)
{
  a.unpack(os, full);
  if (full)
    mac.unpack(os);
}

#endif
