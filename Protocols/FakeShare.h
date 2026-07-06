/*
 * FakeShare.h
 *
 */

#ifndef PROTOCOLS_FAKESHARE_H_
#define PROTOCOLS_FAKESHARE_H_

#include "GC/FakeSecret.h"
#include "ShareInterface.h"
#include "FakeMC.h"
#include "FakeProtocol.h"
#include "FakePrep.h"
#include "FakeInput.h"

template<class T>
class FakeShare : public T, public ShareInterface
{
    typedef FakeShare This;

public:
    typedef T open_type;
    typedef T clear;
    typedef This share_type;

    typedef FakePrep<This> LivePrep;
    typedef FakeMC<This> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef FakeInput<This> Input;
    typedef ::PrivateOutput<This> PrivateOutput;
    typedef FakeProtocol<This> Protocol;

    typedef GC::FakeSecret bit_type;

    static const bool has_trunc_pr = true;
    static const bool dishonest_majority = false;
    static const bool malicious = false;
    static const bool is_real = false;
    static const bool variable_players = false;

    static false_type is_clear;

    static string type_short()
    {
        return "emul";
    }

    static int threshold(int)
    {
        return 0;
    }

    static T constant(T value, int = 0, mac_key_type = {})
    {
        return value;
    }

    FakeShare()
    {
    }

    template<class U>
    FakeShare(U other) :
            T(other)
    {
    }

    static void split(StackedVector<bit_type>& dest, const ArgVector& regs,
            int n_bits, const This* source, int n_inputs,
            GC::FakeSecret::Protocol& protocol);
};

#endif /* PROTOCOLS_FAKESHARE_H_ */
