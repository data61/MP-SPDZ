/*
 * Register.hpp
 *
 */

#ifndef BMR_REGISTER_HPP_
#define BMR_REGISTER_HPP_

#include "Register.h"
#include "Party.h"

template<class T>
void ProgramRegister::inputbvec(T& processor, ProcessorBase& input_processor,
		const ArgVector& args)
{
	NoOpInputter inputter;
	processor.inputbvec(inputter, input_processor, args, *ProgramParty::s().P);
}

template<class T>
void EvalRegister::inputbvec(T& processor, ProcessorBase& input_processor,
		const ArgVector& args)
{
	EvalInputter inputter;
	processor.inputbvec(inputter, input_processor, args,
			*ProgramParty::s().P);
}

template <class T>
void PRFRegister::load(vector<GC::ReadAccess<T> >& accesses,
        const NoMemory& source)
{
    (void)source;
    for (auto access : accesses)
        for (auto& reg : access.dest.get_regs())
        {
            ProgramParty::s().receive_keys(reg);
            ProgramParty::s().store_wire(reg);
        }
}

template <class T>
void EvalRegister::store_clear_in_dynamic(GC::Memory<T>& mem,
		const vector<GC::ClearWriteAccess>& accesses)
{
	for (auto access : accesses)
	{
		T& dest = mem[access.address];
		GC::Clear value = access.value;
		ProgramParty& party = ProgramParty::s();
		dest = T::constant(value.get(), party.get_id() - 1, party.get_mac_key().get());
#ifdef DEBUG_DYNAMIC
		cout << "store clear " << dest.share << " " << dest.mac << " " << value << endl;
#endif
	}
}

template <class T>
void check_for_doubles(const vector<T>& accesses, const char* name)
{
    (void)accesses;
    (void)name;
#ifdef OUTPUT_DOUBLES
    set<GC::Clear> seen;
	int doubles = 0;
	for (auto access : accesses)
	{
		if (seen.find(access.address) != seen.end())
			doubles++;
		seen.insert(access.address);
	}
	cout << doubles << "/" << accesses.size() << " doubles in " << name << endl;
#endif
}

template<class T, class U>
void EvalRegister::store(GC::Memory<U>& mem,
		const vector< GC::WriteAccess<T> >& accesses)
{
	check_for_doubles(accesses, "storing");
	auto& party = ProgramPartySpec<U>::s();
	vector<U> S, S2, S3, S4, S5, SS;
	vector<gf2n_long> exts;
	int n_registers = 0;
	for (auto access : accesses)
		n_registers += access.source.get_regs().size();
	for (auto access : accesses)
	{
		U& dest = mem[access.address];
		dest.assign_zero();
		const vector<EvalRegister>& sources = access.source.get_regs();
		for (unsigned int i = 0; i < sources.size(); i++)
		{
			DualWire<U> spdz_wire;
			party.get_spdz_wire(SPDZ_STORE, spdz_wire);
			const EvalRegister& reg = sources[i];
			U tmp;
			gf2n_long ext = (int)reg.get_external();
			//cout << "ext:" << ext << "/" << (int)reg.get_external() << " " << endl;
			tmp = spdz_wire.mask + U::constant(ext, (int)party.get_id() - 1, party.get_mac_key());
			S.push_back(tmp);
			tmp <<= i;
			dest += tmp;
			const Key& key = reg.external_key(party.get_id());
			Key& expected_key = spdz_wire.my_keys[(int)reg.get_external()];
			if (expected_key != key)
			{
				cout << "wire label: " << key << ", expected: "
							<< expected_key << endl;
				cout << "opposite: " << spdz_wire.my_keys[1-reg.get_external()] << endl;
				sources[i].keys.print(sources[i].get_id());
				throw runtime_error("key check failed");
			}
#ifdef DEBUG_SPDZ
			S3.push_back(spdz_wire.mask);
			S4.push_back(dest);
			S5.push_back(tmp);
			exts.push_back(ext);
#endif
        }
#ifdef DEBUG_SPDZ
		SS.push_back(dest);
#endif
    }

#ifdef DEBUG_SPDZ
	party.MC->Check(*party.P);
	vector<gf2n> v, v3, vv;
	party.MC->POpen_Begin(vv, SS, *party.P);
	party.MC->POpen_End(vv, SS, *party.P);
	cout << "stored " << vv.back() << " from bits:";
	vv.pop_back();
	party.MC->Check(*party.P);
	party.MC->POpen_Begin(v, S, *party.P);
	party.MC->POpen_End(v, S, *party.P);
	for (auto val : v)
		cout << val.get_bit(0);
	party.MC->Check(*party.P);
	cout << " / exts:";
	for (auto ext : exts)
		cout << ext.get_bit(0);
	cout << " / masks:";
	party.MC->POpen_Begin(v3, S3, *party.P);
	party.MC->POpen_End(v3, S3, *party.P);
	for (auto val : v3)
		cout << val.get_word();
	cout << endl;
	party.MC->Check(*party.P);
	cout << "share: " << SS.back() << endl;
	party.MC->Check(*party.P);

	party.MC->POpen_Begin(v, S4, *party.P);
	party.MC->POpen_End(v, S4, *party.P);
	for (auto x : v)
		cout << x << " ";
	cout << endl;

	party.MC->POpen_Begin(v, S5, *party.P);
	party.MC->POpen_End(v, S5, *party.P);
	for (auto x : v)
		cout << x << " ";
	cout << endl;

	party.MC->POpen_Begin(v, S2, *party.P);
	party.MC->POpen_End(v, S2, *party.P);
	party.MC->Check(*party.P);
#endif
}

template <class T, class U>
void EvalRegister::load(vector<GC::ReadAccess<T> >& accesses,
		const GC::Memory<U>& mem)
{
	check_for_doubles(accesses, "loading");
	vector<U> shares;
	shares.reserve(accesses.size());
	auto& party = ProgramPartySpec<U>::s();
	deque<DualWire<U>> spdz_wires;
	vector<U> S;
	for (auto access : accesses)
	{
		const U& source = mem[access.address];
		U mask;
		vector<EvalRegister>& dests = access.dest.get_regs();
		for (unsigned int i = 0; i < dests.size(); i++)
		{
			spdz_wires.push_back({});
			party.get_spdz_wire(SPDZ_LOAD, spdz_wires.back());
			mask += spdz_wires.back().mask << i;
		}
		shares.push_back(source + mask);
#ifdef DEBUG_SPDZ
		S.push_back(source);
#endif
	}

#ifdef DEBUG_SPDZ
	party.MC->Check(*party.P);
	vector<gf2n> v;
	party.MC->POpen_Begin(v, S, *party.P);
	party.MC->POpen_End(v, S, *party.P);
	for (size_t j = 0; j < accesses.size(); j++)
	{
		cout << "loaded " << v[j] << " / ";
		vector<Register>& dests = accesses[j].dest.get_regs();
		for (unsigned int i = 0; i < dests.size(); i++)
			cout << (int)dests[i].get_external();
		cout << " from " << S[j] << endl;
	}
	party.MC->Check(*party.P);
#endif

	vector<gf2n_long> masked;
	party.MC->POpen_Begin(masked, shares, *party.P);
	party.MC->POpen_End(masked, shares, *party.P);
	vector<octetStream> keys(party.get_n_parties());

	for (size_t j = 0; j < accesses.size(); j++)
	{
		vector<EvalRegister>& dests = accesses[j].dest.get_regs();
		for (unsigned int i = 0; i < dests.size(); i++)
		{
			bool ext = masked[j].get_bit(i);
			party.load_wire(dests[i]);
			dests[i].set_external(ext);
			keys[party.get_id() - 1].serialize(spdz_wires.front().my_keys[ext]);
			spdz_wires.pop_front();
		}
	}

	party.P->unchecked_broadcast(keys);

	int base = 0;
	for (auto access : accesses)
	{
		vector<EvalRegister>& dests = access.dest.get_regs();
		for (unsigned int i = 0; i < dests.size(); i++)
			for (int j = 0; j < party.get_n_parties(); j++)
			{
				Key key;
				keys[j].unserialize(key);
				dests[i].set_external_key(j + 1, key);
			}
		base += dests.size() * party.get_n_parties();
	}

#ifdef DEBUG_SPDZ
	cout << "masked: ";
	for (auto& m : masked)
		cout << m << " ";
	cout << endl;
#endif
}

#endif /* BMR_REGISTER_HPP_ */
