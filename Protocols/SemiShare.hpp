/*
 * SemiShare.hpp
 *
 */

#ifndef PROTOCOLS_SEMISHARE_HPP_
#define PROTOCOLS_SEMISHARE_HPP_

#include "SemiShare.h"
#include "Semi2kShare.h"

template<class T>
template<class U>
void SemiShare<T>::split(StackedVector<U>& dest, const ArgVector& regs,
        int n_bits, const SemiShare<T>* source, int n_inputs,
        typename U::Protocol& protocol)
{
    auto& P = protocol.P;
    if (P.num_players() > 2)
        throw runtime_error(
                "prime modulus splitting only working with two parties");

    vector<Semi2kShare<T::MAX_N_BITS>> inputs;
    for (int i = 0; i < n_inputs; i++)
    {
        inputs.push_back(bigint::tmp.from_signed(T(source[i])));
    }

    Semi2kShare<T::MAX_N_BITS>::split(dest, regs, n_bits, inputs.data(),
            n_inputs, protocol);
}

#endif /* PROTOCOLS_SEMISHARE_HPP_ */
