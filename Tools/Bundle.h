/*
 * Bundle.h
 *
 */

#ifndef TOOLS_BUNDLE_H_
#define TOOLS_BUNDLE_H_

#include "Networking/Player.h"

#include <vector>
using namespace std;

class mismatch_among_parties : public runtime_error
{
public:
    mismatch_among_parties() :
            runtime_error("mismatch among parties")
    {
    }
};

template<class T>
class Bundle : public vector<T>
{
public:
    T& mine;

    Bundle(const PlayerBase& P) :
            vector<T>(P.num_players()), mine(this->at(P.my_num()))
    {
    }

    void compare(PlayerBase& P)
    {
        if (mine.get_length() > 1000)
        {
            Bundle<T> bundle(P);
            bundle.mine = mine.hash();
            bundle.compare(P);
            return;
        }

        P.unchecked_broadcast(*this);
        for (auto& os : *this)
            if (os != mine)
                throw mismatch_among_parties();
    }

    void reset()
    {
        for (auto& x : *this)
            x.reset_write_head();
    }
};

#endif /* TOOLS_BUNDLE_H_ */
