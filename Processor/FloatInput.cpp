/*
 * FloatInput.cpp
 *
 */

#include "FloatInput.h"

#include <math.h>

const char* FloatInput::NAME = "real number";

void FloatInput::read(std::istream& in, const ArgVector::value_type* params)
{
    double x;
    in >> x;
    int exp;
    double mant = fabs(frexp(x, &exp));

    items[0] = round(mant * (1LL << *params));
    items[1] = exp - *params;
    items[2] = (x == 0);
    items[3] = (x < 0);
}
