/*
 * AstraMC.cpp
 *
 */

#include "AstraMC.h"

#include "SemiMC.hpp"

template<class T>
typename T::open_type AstraMC<T>::prepare_summand(const T& secret, int my_num)
{
    if (my_num == 1)
        return secret.m(my_num) - secret.lambda(my_num);
    else
        return -secret.lambda(my_num);
}

template<class T>
void AstraMC<T>::exchange(const Player& P)
{
    DirectSemiMC<SemiShare<typename T::open_type>> opener;
    opener.init_open(P, this->secrets.size());
    int my_num = P.my_num() + 1;

    for (auto& secret : this->secrets)
    {
        if (P.my_num() == 1)
            opener.prepare_open(prepare_summand(secret, my_num));
        else
            opener.prepare_open(prepare_summand(secret, my_num));
    }

    opener.exchange(P);

    for (size_t i = 0; i < this->secrets.size(); i++)
        this->values.push_back(opener.finalize_open());
}
