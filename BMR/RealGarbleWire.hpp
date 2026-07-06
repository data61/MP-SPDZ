/*
 * RealGarbleWire.cpp
 *
 */

#include "RealGarbleWire.h"
#include "RealProgramParty.h"
#include "Protocols/MascotPrep.h"

template<class T>
void RealGarbleWire<T>::garble(PRFOutputs& prf_output,
		const RealGarbleWire<T>& left, const RealGarbleWire<T>& right)
{
	auto& party = RealProgramParty<T>::s();
	assert(party.prep != 0);
	party.prep->get_one(DATA_BIT, mask);
	auto& inputter = *party.garble_inputter;
	int n = party.N.num_players();
	int me = party.N.my_num();
	inputter.add_from_all(int128(keys[0][me].r));
	for (int k = 0; k < 4; k++)
		for (int j = 0; j < n; j++)
			inputter.add_from_all(int128(prf_output[j].for_garbling(k).r));

	assert(party.shared_proc != 0);
	assert(party.garble_protocol != 0);
	auto& protocol = *party.garble_protocol;
	protocol.prepare_mul(left.mask, right.mask);
	GarbleJob<T> job(left.mask, right.mask, mask);
	party.garble_jobs.push_back(job);
}

template<class T>
GarbleJob<T>::GarbleJob(T lambda_u, T lambda_v, T lambda_w) :
		lambda_u(lambda_u), lambda_v(lambda_v), lambda_w(lambda_w)
{
}

template<class T>
void GarbleJob<T>::middle_round(RealProgramParty<T>& party, Protocol& second_protocol)
{
	int n = party.N.num_players();
	int me = party.N.my_num();
	assert(party.garble_protocol != 0);
	auto& protocol = *party.garble_protocol;
	lambda_uv = protocol.finalize_mul();

#ifdef DEBUG_MASK
	cout << "lambda_u " << party.MC->POpen(lambda_u, *party.P) << endl;
	cout << "lambda_v " << party.MC->POpen(lambda_v, *party.P) << endl;
	cout << "lambda_w " << party.MC->POpen(lambda_w, *party.P) << endl;
	cout << "lambda_uv " << party.MC->POpen(lambda_uv, *party.P) << endl;
#endif

	for (int alpha = 0; alpha < 2; alpha++)
		for (int beta = 0; beta < 2; beta++)
			for (int j = 0; j < n; j++)
			{
				second_protocol.prepare_mul(party.shared_delta(j),
						lambda_uv + lambda_v * alpha + lambda_u * beta
								+ T::constant(alpha * beta, me, party.MC->get_alphai())
								+ lambda_w);
			}
}

template<class T>
void GarbleJob<T>::last_round(RealProgramParty<T>& party, Inputter& inputter,
		Protocol& second_protocol, vector<T>& wires)
{
	int n = party.N.num_players();
	auto& protocol = second_protocol;

	vector<T> base_keys;
	for (int i = 0; i < n; i++)
		base_keys.push_back(inputter.finalize(i));

	for (int k = 0; k < 4; k++)
		for (int j = 0; j < n; j++)
		{
			wires.push_back({});
			auto& wire = wires.back();
			for (int i = 0; i < n; i++)
				wire += inputter.finalize(i);
			wire += base_keys[j];
			wire += protocol.finalize_mul();
		}
}

template<class T>
void RealGarbleWire<T>::XOR(const RealGarbleWire<T>& left, const RealGarbleWire<T>& right)
{
	PRFRegister::XOR(left, right);
	mask = left.mask + right.mask;
}

template<class T>
void RealGarbleWire<T>::inputb(
		GC::Processor<GC::Secret<RealGarbleWire>>& processor,
		const ArgVector& args)
{
	GarbleInputter<T> inputter;
	processor.inputb(inputter, processor, args,
			inputter.party.P->my_num());
}

template<class T>
void RealGarbleWire<T>::inputbvec(
		GC::Processor<GC::Secret<RealGarbleWire>>& processor,
		ProcessorBase& input_processor, const ArgVector& args)
{
	GarbleInputter<T> inputter;
	processor.inputbvec(inputter, input_processor, args,
			*inputter.party.P);
}

template<class T>
GarbleInputter<T>::GarbleInputter() :
		party(RealProgramParty<T>::s()), oss(*party.P)
{
}

template<class T>
void RealGarbleWire<T>::my_input(Input& inputter, bool, int n_bits)
{
	assert(n_bits == 1);
	inputter.tuples.push_back({this, inputter.party.P->my_num()});
}

template<class T>
void RealGarbleWire<T>::other_input(Input& inputter, int from)
{
	inputter.tuples.push_back({this, from});
}

template<class T>
void GarbleInputter<T>::exchange()
{
	assert(party.shared_proc != 0);
	auto& inputter = party.shared_proc->input;
	inputter.reset_all(*party.P);
	for (auto& tuple : tuples)
	{
		int from = tuple.second;
		party_id_t from_id = from + 1;
		tuple.first->PRFRegister::input(from_id, -1);
		if (from_id == party.get_id())
		{
			char my_mask;
			my_mask = party.prng.get_bit();
			party.garble_input_masks.serialize(my_mask);
			inputter.add_mine(my_mask);
#ifdef DEBUG_MASK
			cout << "my mask: " << (int)my_mask << endl;
#endif
		}
		else
		{
			inputter.add_other(from);
		}
	}

	inputter.exchange();

	for (auto& tuple : tuples)
		tuple.first->mask = (inputter.finalize(tuple.second));

	// important to make sure that mask is a bit
	try
	{
		for (auto& tuple : tuples)
			tuple.first->mask.force_to_bit();
	}
	catch (not_implemented& e)
	{
		assert(party.P != 0);
		assert(party.MC != 0);
		auto& protocol = party.shared_proc->protocol;
		protocol.init_mul();
		for (auto& tuple : tuples)
			protocol.prepare_mul(tuple.first->mask,
					T::constant(1, party.P->my_num(), party.mac_key)
							- tuple.first->mask);
		protocol.exchange();
		vector<T> to_check;
		to_check.reserve(tuples.size());
		for (size_t i = 0; i < tuples.size(); i++)
		{
			to_check.push_back(protocol.finalize_mul());
		}
		try
		{
			party.MC->CheckFor(0, to_check, *party.P);
		}
		catch (mac_fail&)
		{
			throw runtime_error("input mask not a bit");
		}
	}
#ifdef DEBUG_MASK
	cout << "shared mask: " << party.MC->POpen(mask, *party.P) << endl;
#endif
}

template<class T>
void RealGarbleWire<T>::finalize_input(GarbleInputter<T>&, int, int)
{
}

template<class T>
void RealGarbleWire<T>::public_input(bool value)
{
	PRFRegister::public_input(value);
	mask = {};
}

template<class T>
void RealGarbleWire<T>::random()
{
	// no need to randomize keys
	PRFRegister::public_input(0);
	auto& party = RealProgramParty<T>::s();
	assert(party.prep != 0);
	party.prep->get_one(DATA_BIT, mask);
	// this is necessary to match the fake BMR evaluation phase
	party.store_wire(*this);
	keys[0].serialize(party.wires);
}

template<class T>
void RealGarbleWire<T>::output()
{
	PRFRegister::output();
	auto& party = RealProgramParty<T>::s();
	assert(party.MC != 0);
	assert(party.P != 0);
	auto m = party.MC->open(mask, *party.P);
	party.garble_output_masks.push_back(m.get_bit(0));
	party.taint();
#ifdef DEBUG_MASK
	cout << "output mask: " << m << endl;
#endif
}

template<class T>
void RealGarbleWire<T>::store(NoMemory& dest,
		const vector<GC::WriteAccess<GC::Secret<RealGarbleWire> > >& accesses)
{
	(void) dest;
	auto& party = RealProgramParty<T>::s();
	for (auto access : accesses)
		for (auto& reg : access.source.get_regs())
		{
			party.push_spdz_wire(SPDZ_STORE, reg);
		}
}

template<class T>
void RealGarbleWire<T>::load(
		vector<GC::ReadAccess<GC::Secret<RealGarbleWire> > >& accesses,
		const NoMemory& source)
{
	PRFRegister::load(accesses, source);
	auto& party = RealProgramParty<T>::s();
	assert(party.prep != 0);
	for (auto access : accesses)
		for (auto& reg : access.dest.get_regs())
		{
			party.prep->get_one(DATA_BIT, reg.mask);
			party.push_spdz_wire(SPDZ_LOAD, reg);
		}
}

template<class T>
void RealGarbleWire<T>::convcbit(Integer& dest, const GC::Clear& source,
        GC::Processor<GC::Secret<RealGarbleWire>>& processor)
{
	(void) source;
	auto& party = RealProgramParty<T>::s();
	processor.untaint();
	dest = party.convcbit;
}
