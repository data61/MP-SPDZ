/*
 * SPDZ2k.h
 *
 */

#ifndef PROTOCOLS_SPDZ2K_H_
#define PROTOCOLS_SPDZ2K_H_

#include "SPDZ.h"

template<class T>
class SPDZ2k : public SPDZ<T>
{
public:
    SPDZ2k(Player& P) :
            SPDZ<T>(P)
    {
    }

    void exchange()
    {
        for (size_t i = 0;
                i < this->shares.size() + 2 * this->multiplicands.size(); i++)
            this->MC->set_random_element({});
        SPDZ<T>::exchange();
    }
};

#endif /* PROTOCOLS_SPDZ2K_H_ */
