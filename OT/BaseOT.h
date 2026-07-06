#ifndef _BASE_OT
#define _BASE_OT

/* The OT thread uses the Miracl library, which is not thread safe.
 * Thus all Miracl based code is contained in this one thread so as
 * to avoid locking issues etc.
 *
 * Thus this thread serves all base OTs to all other threads
 */

#include "Networking/Player.h"
#include "Tools/random.h"
#include "Tools/BitVector.h"

// currently always assumes BOTH, i.e. do 2 sets of OT symmetrically,
// use bitwise & to check for role
enum OT_ROLE
{
	RECEIVER = 0x01,
	SENDER = 0x10,
	BOTH = 0x11
};

OT_ROLE INV_ROLE(OT_ROLE role);

const char* role_to_str(OT_ROLE role);
void send_if_ot_sender(TwoPartyPlayer* P, vector<octetStream>& os, OT_ROLE role);
void send_if_ot_receiver(TwoPartyPlayer* P, vector<octetStream>& os, OT_ROLE role);

/** Generating and holding a number of base OTs.
 * @param nOT number of OTs
 * @param ot_length obsolete (always 128 bits for seeding PRGs)
 * @param player two-party networking
 * @param role which role(s) to play
 */
class BaseOT
{
    /// Hash with counter
    static void hash_with_id(BitVector& bits, long id);

public:
    static int avx;

    /// Receiver choice bits
	BitVector receiver_inputs;
	/// Sender inputs
	vector< array<BitVector, 2> > sender_inputs;
	/// Receiver outputs (according to choice bits)
	vector<BitVector> receiver_outputs;
	TwoPartyPlayer* P;
	/// Number of OTs
	int nOT;
	/// Which role(s) on this side
	OT_ROLE ot_role;

	BaseOT(int nOT, TwoPartyPlayer* player, OT_ROLE role=BOTH)
		: P(player), nOT(nOT), ot_role(role)
	{
		receiver_inputs.resize(nOT);
		sender_inputs.resize(nOT);
		receiver_outputs.resize(nOT);
	}

	BaseOT(TwoPartyPlayer* player, OT_ROLE role) :
			BaseOT(128, player, role)
	{
	}

	virtual ~BaseOT() {}

	/// Set choice bits
	void set_receiver_inputs(const BitVector& new_inputs)
	{
		if ((int)new_inputs.size() != nOT)
			throw invalid_length("BaseOT");
		receiver_inputs = new_inputs;
	}

	/// Set choice bits
	void set_receiver_inputs(int128 inputs)
	{
		BitVector new_inputs(128);
		for (int i = 0; i < 128; i++)
			new_inputs[i] = (inputs >> i).get_lower() & 1;
		set_receiver_inputs(new_inputs);
	}

	/**
	 * Generate OTs
	 * @param new_receiver_inputs generate fresh random choice bits
	 */
	virtual void exec_base(bool new_receiver_inputs=true);

	/// Set the PRG seeds from the input/output strings
	void set_seeds();

	/// Set the input/output strings from the PRGs
	void extend_length();

	/// Check the strings by mutually revealing them
	void check();

protected:
	/// Sender-side PRGs
	vector< array<PRNG, 2> > G_sender;
	/// Receiver-side PRGs
	vector<PRNG> G_receiver;

	bool is_sender() { return (bool) (ot_role & SENDER); }
	bool is_receiver() { return (bool) (ot_role & RECEIVER); }

	void allocate();

	bool use_avx();

	/// CPU-specific instantiation of Simplest OT using Curve25519
	template<class T, class U>
	void exec_base(bool new_receiver_inputs=true);
};

class FakeOT : public BaseOT
{
public:
   FakeOT(int nOT, TwoPartyPlayer* player, OT_ROLE role=BOTH) :
       BaseOT(nOT, player, role) {}
   void exec_base(bool new_receiver_inputs=true);
};

#endif
