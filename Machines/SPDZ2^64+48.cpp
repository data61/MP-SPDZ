/*
 * SPDZ2^(64+48).cpp
 *
 */

#include "SPDZ2k.hpp"

template int OnlineMachine::run<Spdz2kShare<64, 48>, Share<gf2n>>();
