/*
 * Register.cpp
 *
 */

#include "Register.h"
#include "Wire.h"
#include "GarbledGate.h"
#include "Gate.h"
#include "Party.h"
#include "TrustedParty.h"
#include "CommonParty.h"
#include "Register_inline.h"
#include "RealGarbleWire.h"

#include "prf.h"

#include "GC/Secret.h"
#include "GC/Secret_inline.h"
#include "GC/Processor.h"
#include "Tools/FlexBuffer.h"

#include "GC/Processor.hpp"

#include <unistd.h>

int Register::counter = 0;

void Register::init(int n_parties)
{
	keys.init(n_parties);
	mask = NO_SIGNAL;
	external = NO_SIGNAL;
}

void Register::init(int rfd, int n_parties) {
	(void)rfd;
	mask = CommonParty::s().prng.get_uchar();
#ifdef DEBUG
	mask = counter & 1;
	counter++;
#endif
#ifdef DEBUG_MASK
	mask = 0;
#endif
	mask = mask>0 ? 1 : 0;
	keys.init(n_parties);
	keys.randomize();
	for (int i = 0; i < 2; i++)
		for (size_t j = 0; j < keys[i].size(); j++)
			if (keys[i][j].get_signal() != i)
				keys[i][j] ^= Key(1);
}

void Register::set_eval_keys()
{
    if (external == NO_SIGNAL)
        throw exception();
    garbled_entry = keys[external];
}

void Register::set_eval_keys(Key* keys, int n_parties, int except)
{
    this->keys.copy_from(keys, n_parties, except);
    set_eval_keys();
}

void Register::set_external_key(party_id_t i, const Key& key)
{
    check_external();
    garbled_entry[i-1] = key;
    keys[external][i-1] = key;
    //keys[1-external][i-1] = 0;
}

void Register::reset_non_external_key(party_id_t i)
{
    check_external();
    keys[1-external][i-1] = 0;
}

void Register::set_external(char ext)
{
    external = ext;
	check_external();
    garbled_entry = keys[external];
}

void Register::check_mask() const
{
#ifdef SIGNAL_CHECK
	if (mask * (1 - mask) != 0)
	{
		if (mask == NO_SIGNAL)
			throw runtime_error("no signal in mask");
		else
			throw runtime_error("invalid mask");
	}
#endif
}

void Register::set_mask(char mask)
{
#ifdef DEBUG_MASK
	cout << "setting mask: " << (int)mask << endl;
#endif
	this->mask = mask;
	check_mask();
}

void Register::check_external() const
{
#ifdef SIGNAL_CHECK
	if (external * (1 - external) != 0)
	{
		if (external == NO_SIGNAL)
			throw runtime_error("no signal in external value");
		else
			throw runtime_error("invalid external value");
	}
#endif
}

void Register::check_signal_key(int my_id, KeyVector& garbled_entry)
{
	if (garbled_entry[my_id - 1] != keys[get_external()][my_id - 1])
	{
		if (garbled_entry[my_id - 1] == keys[1 - get_external()][my_id - 1])
			throw runtime_error("key matches inverted signal");
		else
		{
			cout << "signal " << (int)get_external() << ", ";
			cout << garbled_entry[my_id - 1] << " none of ";
			for (int i = 0; i < 2; i++)
				cout << keys[i][my_id - 1] << " ";
			cout << endl;
			throw runtime_error("key doesn't match signal");
		}
	}
}

void Register::print_input(int id)
{
	for (int x = 0; x < 2; x++)
	{
		printf("k^I_{%u,%d}:  ",id,x);
		for (unsigned int i = 0; i < keys[x].size(); i++)
			std::cout << keys[x][i] << "  ";
		std::cout << std::endl;
	}
}

template <>
void EvalRegister::andrs(GC::Processor<GC::Secret<EvalRegister> >& processor,
		const ArgVector& args)
{
	ProgramParty& party = ProgramParty::s();
	int total = 0;
	for (size_t j = 0; j < args.size(); j += 4)
		total += args[j];
	if (total < party.threshold)
	{
		// run in single thread
		processor.andrs(args);
		return;
	}

	int max_gates_per_thread = (total + N_EVAL_THREADS - 1) / N_EVAL_THREADS;
	int i_thread = 0, i_gate = 0;
	party.and_jobs[0].reset(processor.S, args, 0, party.next_gate(0),
			total, party.get_n_parties());
	for (size_t j = 0; j < args.size(); j += 4)
	{
		AndJob& and_job = party.and_jobs[i_thread];
		size_t dl = GC::Clear::N_BITS;
		for (size_t i = 0; i < args[j]; i += dl)
		{
			GC::Secret<EvalRegister>& dest = processor.S[args[j + 1] + i / dl];
			dest.resize_regs(min(args[j] - i, dl));
		}
		processor.complexity += args[j];
		for (size_t i = 0; i < args[j]; i++)
		{
			and_job.gates[i_gate].unserialize(party.garbled_circuit,
					party.get_n_parties());
			i_gate++;
		}
		and_job.end = j + 4;
		if (i_gate >= max_gates_per_thread or and_job.end >= args.size())
		{
			party.eval_threads[i_thread].request(and_job);
			gate_id_t gate_id = party.next_gate(i_gate);
			i_gate = 0;
			// advance to next thread but only if not on least thread
			if(and_job.end < args.size())
				party.and_jobs[++i_thread].reset(processor.S, args, and_job.end,
						gate_id, total, party.get_n_parties());
		}
	}

	for (int i = 0; i <= i_thread; i++)
		party.eval_threads[i].done();
}

void EvalRegister::op(const ProgramRegister& left, const ProgramRegister& right, Function func)
{
	(void)func;
#ifdef DEBUG
	cout << "eval left " << &left << " " << dec << " " << left.get_id() << endl;
	cout << "eval right " << &right << " " << dec << " " << right.get_id() << endl;
#endif
	ProgramParty& party = *ProgramParty::singleton;
	GarbledGate gate(party.get_n_parties());
	party.next_gate(gate);
	gate.unserialize(party.garbled_circuit, party.get_n_parties());
	party.prf_output.resize(PAD_TO_8(party.get_n_parties()) * sizeof(__m128i));
	Register::eval(left, right, gate, party._id, party.prf_output.data(),
			get_id(), left.get_id(), right.get_id());
}

void Register::eval(const Register& left, const Register& right, GarbledGate& gate,
        party_id_t my_id, char* prf_output, int w_o, int w_l, int w_r)
{
    (void)w_o;
    (void)w_l;
    (void)w_r;
    size_t n_parties = CommonParty::singleton->get_n_parties();
    int sig_l = left.get_external();
    int sig_r = right.get_external();
    int entry = 2 * sig_l + sig_r;

#ifdef DEBUG_MASK
    cout << "input signals: " << sig_l << " " << sig_r << endl;
#endif

#ifdef DEBUG
    gate.print();
    cout << "picking " << entry << endl;
#endif

    garbled_entry = gate[entry];
    int ext_l = entry%2 ? 1 : 0 ;
    int ext_r = entry<2 ? 0 : 1 ;

#ifdef DEBUG
    printf("left input");
    phex(gate.input(ext_l, 1), 16);
    printf("right input");
    phex(gate.input(ext_r, 1), 16);
    unsigned g = gate.id;
#endif

    Key k;
    for(party_id_t i=1; i<=n_parties; i++) {
#ifdef DEBUG
                                std::cout << "using key: " << left.external_key(i) << endl;
#endif
        PRF_chunk(left.external_key(i), gate.input(ext_l, 1), prf_output, PAD_TO_8(n_parties));
        for(party_id_t j=1; j<=n_parties; j++) {
            k = *(Key*)(prf_output+16*(j-1));
#ifdef DEBUG
                        printf("Fk^%d_{%u,%d}(%d,%u,%d) = ",i, w_l, sig_l,ext_l,g,j);
                        std::cout << k << std::endl;
#endif
            garbled_entry[j-1] -= k;
        }

#ifdef DEBUG
                                    std::cout << "using key: " << right.external_key(i) << endl;
#endif
        PRF_chunk(right.external_key(i), gate.input(ext_r, 1) , prf_output, PAD_TO_8(n_parties));
        for(party_id_t j=1; j<=n_parties; j++) {
            k = *(Key*)(prf_output+16*(j-1));
#ifdef DEBUG
            printf("Fk^%d_{%u,%d}(%d,%u,%d) = ",i, w_r, sig_r,ext_r,g,j);
                        std::cout << k << std::endl;
#endif
            garbled_entry[j-1] -= k;
        }
    }

//  for(party_id_t i=1; i<=n_parties; i++) {
//      std::cout << garbled_entry[i-1] << "  ";
//  }
//  std::cout << std::endl;

    external = garbled_entry[my_id - 1].get_signal();

#ifdef DEBUG_MASK
    cout << "output signal: " << (int)external << endl;
#endif

#ifdef DEBUG
    std::cout << "k^"<<my_id<<"_{"<<w_o<<","<<(int)external<<"} = " << key(my_id, external) << std::endl;
#endif
}

void GarbleRegister::op(const Register& left, const Register& right, Function func)
{
	TrustedProgramParty& party = *TrustedProgramParty::singleton;
	party.load_wire(*this);
	Gate _;
	Register::garble(left, right, func, &_, 0, party.prf_outputs,
			party.buffers[TYPE_GARBLED_CIRCUIT]);
}

void Register::garble(const Register& left, const Register& right,
        Function func, Gate* gate, int g,
        vector<ReceivedMsg>& prf_outputs, SendBuffer& buffer)
{
    (void)func;
    (void)gate;
    (void)g;
    size_t n_parties = CommonParty::singleton->get_n_parties();
    GarbledGate garbled_gate(n_parties);
    garbled_gate.reset();
    KeyVector& gg_A = garbled_gate[0];
    KeyVector& gg_B = garbled_gate[1];
    KeyVector& gg_C = garbled_gate[2];
    KeyVector& gg_D = garbled_gate[3];

    for(party_id_t i=1; i<=n_parties; i++) {
#ifdef DEBUG
        std::cout << "adding prfs of party " << i << std::endl ;
#endif
        Key left_i_j, right_i_j;
        for (party_id_t j=1; j<=n_parties; j++) {
            PRFTuple party_prfs;
            prf_outputs[i - 1].unserialize(party_prfs);
            //A
#ifdef DEBUG
            left_i_j = *(Key*)party_prfs.outputs[0][0][0];
            right_i_j = *(Key*)party_prfs.outputs[1][0][0];
            std::cout << "A" << std::endl;
                        cout << gg_A[j-1] << std::endl;
                        cout << left_i_j << std::endl;
                        cout << right_i_j << std::endl;
#endif
            gg_A[j-1] += party_prfs.for_garbling(0);
//                          cout << gg_A[j-1] << std::endl<< std::endl;

            //B
#ifdef DEBUG
            left_i_j = *(Key*)party_prfs.outputs[0][0][1];
            right_i_j = *(Key*)party_prfs.outputs[1][1][0];
            std::cout << "B" << std::endl;
                        cout << gg_B[j-1] << std::endl;
                        cout << left_i_j << std::endl;
                        cout << right_i_j << std::endl;
#endif
            gg_B[j-1] += party_prfs.for_garbling(1);
//                          cout << gg_B[j-1] << std::endl<< std::endl;

            //C
#ifdef DEBUG
            left_i_j = *(Key*)party_prfs.outputs[0][1][0];
            right_i_j = *(Key*)party_prfs.outputs[1][0][1];
            std::cout << "C" << std::endl;
                        cout << gg_C[j-1] << std::endl;
                        cout << left_i_j << std::endl;
                        cout << right_i_j << std::endl;
#endif
            gg_C[j-1] += party_prfs.for_garbling(2);
//                          cout << gg_C[j-1] << std::endl<< std::endl;

            //D
#ifdef DEBUG
            left_i_j = *(Key*)party_prfs.outputs[0][1][1];
            right_i_j = *(Key*)party_prfs.outputs[1][1][1];
            std::cout << "D" << std::endl;
                        cout << gg_D[j-1] << std::endl;
                        cout << left_i_j << std::endl;
                        cout << right_i_j << std::endl;
#endif
            gg_D[j-1] += party_prfs.for_garbling(3);
//                          cout << gg_D[j-1] << std::endl<< std::endl;
        }
    }

    //Adding the hidden keys
    left.check_mask();
    right.check_mask();
    check_mask();
    char maskl =    left.mask;
    char maskr =    right.mask;
    char masko =    mask;
#ifdef DEBUG
    printf("\ngate %u, leftwire=%lu, rightwire=%lu, outwire=%lu: func=%d%d%d%d, msk_l=%d, msk_r=%d, msk_o=%d\n"
            , g,gate->_left, gate->_right, gate->_out
            ,func[0],func[1],func[2],func[3], maskl, maskr, masko);
#endif

//      printf("\n");
//      printf("maskl=%d, maskr=%d, masko=%d\n",maskl,maskr,masko);
//      printf("gate func = %d%d%d%d\n",gate->_func[0],gate->_func[1],gate->_func[2],gate->_func[3]);
    bool xa = func[2*maskl+maskr] != masko;
    bool xb = func[2*maskl+(1-maskr)] != masko;
    bool xc = func[2*(1-maskl)+maskr] != masko;
    bool xd = func[2*(1-maskl)+(1-maskr)] != masko;

#ifdef DEBUG
    printf("xa=%d, xb=%d, xc=%d, xd=%d\n", xa,xb,xc,xd);
#endif

    // these are the 0-keys
    Register& outwire = *this;
    keys.init(n_parties);
    KeyVector& keyxa = outwire[xa];
    KeyVector& keyxb = outwire[xb];
    KeyVector& keyxc = outwire[xc];
    KeyVector& keyxd = outwire[xd];

    for(party_id_t i=1; i<=n_parties; i++) {
#ifdef DEBUG
        std::cout << "adding to A = " << keyxa[i-1] << std::endl;
        std::cout << "adding to B = " << keyxb[i-1] << std::endl;
        std::cout << "adding to C = " << keyxc[i-1] << std::endl;
        std::cout << "adding to D = " << keyxd[i-1] << std::endl;
#endif
        gg_A[i-1] += keyxa[i-1];
        gg_B[i-1] += keyxb[i-1];
        gg_C[i-1] += keyxc[i-1];
        gg_D[i-1] += keyxd[i-1];
    }
    garbled_gate.serialize_no_allocate(buffer);
#ifdef DEBUG
    garbled_gate.print();
#endif
}

void PRFRegister::output()
{
	ProgramParty& party = *ProgramParty::singleton;
	party.store_wire(*this);
}

void PRFRegister::op(const PRFRegister& left, const PRFRegister& right, Function func)
{
	(void)func;
#ifdef DEBUG
	cout << "prf op " << &left << " " << &right << endl;
	cout << "sizes " << left.keys[0].size() << " " << right.keys[0].size() << endl;
#endif
	const Register* in_wires[2] = { &left, &right };
	ProgramParty& party = *ProgramParty::singleton;
	party.receive_keys(*this);
	GarbledGate gate(party.get_n_parties());
	PRFOutputs prf_output(party.get_n_parties());
	gate.compute_prfs_outputs(in_wires, party._id, prf_output, party.new_gate());
	party.process_prf_output(prf_output, this, &left, &right);
#ifdef DEBUG_FREE_XOR
	int i = ProgramParty::s()._id - 1;
	Key delta = party.get_delta();
	if (delta != (left.keys[0][i] ^ left.keys[1][i]))
		throw runtime_error("inconsistent delta");
	if (delta != (right.keys[0][i] ^ right.keys[1][i]))
		throw runtime_error("inconsistent delta");
	if (delta != (keys[0][i] ^ keys[1][i]))
		throw runtime_error("inconsistent delta");
#endif
}

void PRFRegister::input(party_id_t from, char value)
{
	(void)from;
	(void)value;
	ProgramParty& party = *ProgramParty::singleton;
	party.receive_keys(*this);
	party.store_wire(*this);
#ifdef DEBUG
	cout << "(PRF) input from " << from << ":" << endl;
	keys.print(get_id());
#endif
}

void PRFRegister::public_input(bool value)
{
	ProgramParty& party = ProgramParty::s();
	int i = party.get_id() - 1;
	keys[value][i] = 0;
	keys[1 - value][i] = party.get_delta();
	set_mask(0);
}

void PRFRegister::random()
{
	ProgramParty& party = ProgramParty::s();
	ProgramParty::s().receive_keys(*this);
	ProgramParty::s().receive_all_keys(*this, 0);
	party.store_wire(*this);
	keys[0].serialize(party.wires);
#ifdef DEBUG
	cout << "(PRF) random:" << endl;
	keys.print(get_id());
#endif
}

class InputAccess
{
	party_id_t from;
	size_t n_bits;
	GC::Secret<EvalRegister>& dest;
	GC::Processor<GC::Secret<EvalRegister> >& processor;
	ProgramParty& party;
	InputArgs args;

public:
	InputAccess(const InputArgs& args,
			GC::Processor<GC::Secret<EvalRegister> >& processor) :
            from(args.from + 1), n_bits(args.n_bits), dest(
                    processor.S[args.dest]), processor(processor), party(
                    ProgramParty::s()), args(args)
	{
		if (from > unsigned(party.get_n_parties()) or n_bits > 100)
			throw runtime_error("invalid input parameters");
	}

	void prepare_masks(octetStream& os)
	{
		dest.resize_regs(n_bits);
		for (auto& reg : dest.get_regs())
			party.load_wire(reg);
		if (from == party.get_id())
		{
			long long in = processor.get_input(args.params);
			for (size_t i = 0; i < n_bits; i++)
			{
				auto& reg = dest.get_reg(i);
				reg.input_helper((in >> i) & 1, os);
			}
		}
	}

	void received_masks(vector<octetStream>& oss)
	{
		size_t id = party.get_id() - 1;
		for (auto& reg : dest.get_regs())
		{
			if (party.get_id() != from)
			{
				char ext;
				oss[from - 1].unserialize(ext);
				reg.set_external(ext);
			}
			oss[id].serialize(reg.get_garbled_entry()[id]);
		}
	}

	void received_labels(vector<octetStream>& oss)
	{
		for (auto& reg : dest.get_regs())
		{
			for (party_id_t id = 1; id < (size_t)party.get_n_parties() + 1; id++)
			{
				Key key;
				if (id != party.get_id())
				{
					oss[id - 1].unserialize(key);
					reg.set_external_key(id, key);
				}
			}
		}
	}
};

template <>
void EvalRegister::inputb(GC::Processor<GC::Secret<EvalRegister> >& processor,
		const ArgVector& args)
{
	auto& party = ProgramParty::s();
	vector<octetStream> oss(party.get_n_parties());
	octetStream& my_os = oss[party.get_id() - 1];
	vector<InputAccess> accesses;
	InputArgList a(args);
	processor.complexity += a.n_input_bits();
	for (auto x : a)
	{
		accesses.push_back({x , processor});
	}
	for (auto& access : accesses)
		access.prepare_masks(my_os);
	party.P->unchecked_broadcast(oss);
	my_os.reset_write_head();
	for (auto& access : accesses)
		access.received_masks(oss);
	party.P->unchecked_broadcast(oss);
	for (auto& access : accesses)
		access.received_labels(oss);
}

void EvalRegister::convcbit(Integer& dest, const GC::Clear& source,
        GC::Processor<GC::Secret<EvalRegister>>& processor)
{
	auto& party = ProgramParty::s();
	dest = source;
	party.convcbit = source;
	processor.untaint();
}

void EvalRegister::input_helper(char value, octetStream& os)
{
	set_mask(ProgramParty::s().input_masks.pop_front());
	set_external(get_mask() ^ value);
	os.serialize(get_external());
}

EvalInputter::EvalInputter() :
		party(ProgramParty::s()), oss(*party.P)
{
}

void EvalRegister::my_input(EvalInputter& inputter, bool input, int n_bits)
{
	assert(n_bits == 1);
	auto& party = inputter.party;
	party.load_wire(*this);
	input_helper(input, inputter.oss.mine);
	inputter.tuples.push_back({this, party.P->my_num()});
}

void EvalRegister::other_input(EvalInputter& inputter, int from)
{
	auto& party = inputter.party;
	party.load_wire(*this);
	inputter.tuples.push_back({this, from});
}

void EvalInputter::exchange()
{
	party.P->unchecked_broadcast(oss);
	for (auto& tuple : tuples)
	{
		if (tuple.from != party.P->my_num())
		{
			char ext;
			oss[tuple.from].unserialize(ext);
			tuple.reg->set_external(ext);
		}
	}

	size_t id = party.get_id() - 1;
	for (auto& os : oss)
		os.reset_write_head();

	for (auto& tuple : tuples)
	{
		oss[id].serialize(tuple.reg->get_garbled_entry()[id]);
#ifdef DEBUG_COMM
		cout << "send " << garbled_entry[id] << ", "
				<< oss[id].get_length() << " bytes from " << id << endl;
#endif
	}

	party.P->unchecked_broadcast(oss);
}

void EvalRegister::finalize_input(EvalInputter& inputter, int from, int)
{
	(void) from;
	auto& party = inputter.party;
	size_t id = party.get_id() - 1;
	for (size_t i = 0; i < (size_t)party.get_n_parties(); i++)
	{
		if (i != id)
			inputter.oss[i].unserialize(garbled_entry[i]);
	}
	keys[external] = garbled_entry;
#ifdef DEBUG
	cout << "(Input) input from " << from << ":" << endl;
	keys.print(get_id());
	cout << garbled_entry << endl;
#endif
}

void EvalRegister::public_input(bool value)
{
	ProgramParty& party = ProgramParty::s();
	set_mask(0);
	set_external(value);
	for (int i = 0; i < party.get_n_parties(); i++)
		set_external_key(i + 1, 0);
}

void EvalRegister::random()
{
	auto& party = ProgramParty::s();
	party.load_wire(*this);
	keys[0].unserialize(party.wires, party.get_n_parties());
	set_external(0);
}

void RandomRegister::randomize()
{
	TrustedProgramParty& party = *TrustedProgramParty::singleton;
	party.random_timer.start();
	init(party.randomfd, party._N);
	party.random_timer.stop();
	keys[1] = keys[0] ^ party.get_deltas();
	party.add_keys(*this);
}

void RandomRegister::op(const Register& left, const Register& right,
		Function func)
{
	(void)left;
	(void)right;
	(void)func;
	randomize();
	TrustedProgramParty& party = *TrustedProgramParty::singleton;
	party.new_gate();
	party.store_wire(*this);
}

void RandomRegister::input(party_id_t from, char value)
{
	(void)value;
	randomize();
	auto& party = TrustedProgramParty::s();
	party.store_wire(*this);
	party.msg_input_masks[from - 1].push_back(get_mask());
#ifdef DEBUG
	cout << "(Random) input from " << from << ":" << endl;
	keys.print(get_id());
#endif
}

void RandomRegister::public_input(bool value)
{
	auto& party = TrustedProgramParty::s();
	keys.init(party.get_n_parties());
	for (int i = 0; i < party.get_n_parties(); i++)
	{
		keys[value][i] = 0;
		keys[1 - value][i] = party.delta(i);
	}
	set_mask(0);
	party.store_wire(*this);
}

void GarbleRegister::input(party_id_t from, char value)
{
    (void)from;
    (void)value;
    TrustedProgramParty::s().load_wire(*this);
}

void GarbleRegister::public_input(bool value)
{
	(void)value;
	TrustedProgramParty::s().load_wire(*this);
}

void RandomRegister::random()
{
	randomize();
	TrustedProgramParty::s().add_all_keys(*this, 0);
	TrustedProgramParty::s().store_wire(*this);
#ifdef DEBUG
	cout << "random mask: " << get_mask() << endl;
	cout << "(Random) random:" << endl;
	keys.print(get_id());
#endif
}

void GarbleRegister::random()
{
	TrustedProgramParty::s().load_wire(*this);
}

void RandomRegister::output()
{
	TrustedProgramParty::s().msg_output_masks.push_back(get_mask());
}

void EvalRegister::output()
{
	ProgramParty& party = ProgramParty::s();
	party.load_wire(*this);
	set_mask(party.output_masks.pop_front());
#ifdef DEBUG_REGS
	cout << "check " << get_id() << endl;
#endif
	check_signal_key(party.get_id(), garbled_entry);
	party.taint();
}

void RandomRegister::XOR(const Register& left, const Register& right)
{
	mask = left.get_mask() ^ right.get_mask();
	keys[0] = left.keys[0] ^ right.keys[0];
	keys[1] = keys[0] ^ TrustedProgramParty::singleton->get_deltas();
}

void GarbleRegister::XOR(const Register& left, const Register& right)
{
	mask = left.get_mask() ^ right.get_mask();
}

void PRFRegister::XOR(const Register& left, const Register& right)
{
	int i = ProgramParty::s()._id - 1;
	Key delta = ProgramParty::s().get_delta();
	keys[0][i] = left.keys[0][i] ^ right.keys[0][i];
	keys[1][i] = keys[0][i] ^ delta;
#ifdef DEBUG
	cout << "PRF XOR" << endl;
	cout << "delta " << delta << endl;
	cout << endl;
	cout << "res" << endl;
	keys.print(get_id());
	cout << "left" << endl;
	left.keys.print(left.get_id());
	cout << "right" << endl;
	right.keys.print(right.get_id());
#endif
#ifdef DEBUG_FREE_XOR
	if (delta != (left.keys[0][i] ^ left.keys[1][i]))
		throw runtime_error("inconsistent delta");
	if (delta != (right.keys[0][i] ^ right.keys[1][i]))
		throw runtime_error("inconsistent delta");
	if (delta != (keys[0][i] ^ keys[1][i]))
		throw runtime_error("inconsistent delta");
#endif
}

void EvalRegister::XOR(const Register& left, const Register& right)
{
	external = left.get_external() ^ right.get_external();
	garbled_entry = left.get_garbled_entry() ^ right.get_garbled_entry();
#ifdef DEBUG
	cout << "Eval XOR *" << get_id() << " = *" << left.get_id() << " ^ *" << right.get_id() << endl;
	for (size_t i = 0; i < garbled_entry.size(); i++)
		cout << garbled_entry[i] << " = " << left.get_garbled_entry()[i]
				<< " ^ " << right.get_garbled_entry()[i] << endl;
#endif
}

template <>
void RandomRegister::store(NoMemory& mem,
        const vector< GC::WriteAccess< GC::Secret<RandomRegister> > >& accesses)
{
	(void)mem;
	for (auto access : accesses)
	{
		for (auto& reg : access.source.get_regs())
			TrustedProgramParty::s().store_spdz_wire(SPDZ_STORE, reg);
	}
}

template <>
void RandomRegister::load(vector<GC::ReadAccess< GC::Secret<RandomRegister> > >& accesses,
		const NoMemory& source)
{
	(void)source;
	for (auto access : accesses)
		for (auto& reg : access.dest.get_regs())
		{
			((RandomRegister*)&reg)->randomize();
			TrustedProgramParty::s().store_spdz_wire(SPDZ_LOAD, reg);
			TrustedProgramParty::s().store_wire(reg);
		}
}

template <>
void GarbleRegister::load(vector<GC::ReadAccess< GC::Secret<GarbleRegister> > >& accesses,
		const NoMemory& source)
{
	(void)source;
	for (auto access : accesses)
		for (auto& reg : access.dest.get_regs())
			TrustedProgramParty::s().load_wire(reg);
}

KeyVector KeyVector::operator^(const KeyVector& other) const
{
	if (size() != other.size())
		throw runtime_error("size mismatch");
	KeyVector res;
	res.resize(size());
	for (size_t i = 0; i < size(); i++)
		res[i] = (*this)[i] ^ other[i];
	return res;
}

ostream& operator<<(ostream& os, const KeyVector& kv)
{
	for (size_t i = 0; i < kv.size(); i++)
		os << kv[i] << " ";
	return os;
}

template <int I>
KeyTuple<I> KeyTuple<I>::operator^(const KeyTuple<I>& other) const
{
	KeyTuple<I> res;
	for (int i = 0; i < I; i++)
		res[i] = (*this)[i] ^ other[i];
	return res;
}

template <int I>
void KeyTuple<I>::copy_to(Key* dest) {
	for (int b = 0; b < I; b++)
		avx_memcpy(dest + b * keys[0].size(), keys[b].data(), part_size());
}

template <int I>
void KeyTuple<I>::copy_from(Key* source, int n_parties, int except)
{
#ifdef DEBUG
	cout << "skip copying for " << except << endl;
#endif
	for (int b = 0; b < I; b++)
	{
		keys[b].resize(n_parties);
		for (int i = 0; i < n_parties; i++)
		{
			if (i != except)
				keys[b][i] = *source;
			source++;
#ifdef DEBUG
			cout << "copy from " << b << " " << i << " " << keys[b][i] << endl;
#endif
		}
	}
}

template <int I>
long KeyTuple<I>::counter = 0;

template<int I>
void KeyTuple<I>::randomize()
{
	for (int i = 0; i < I; i++)
	{
		CommonParty::s().prng.get_octets((octet*)keys[i].data(), part_size());
#ifdef DEBUG
		for (unsigned j = 0; j < keys[i].size(); j++)
		{
			keys[i][j] = { 0, (counter << 16) + (i << 8) + j };
			counter++;
		}
#endif
	}
}

template<int I>
void KeyTuple<I>::print(int wire_id) const
{
	for(int b=0; b<I; b++) {
		for (party_id_t i=1; i<=keys[b].size(); i++) {
			printf("k^%d_{%u,%d}: ",i,wire_id,b);
			std::cout << keys[b][i-1] << std::endl;
		}
	}
}

template<int I>
void KeyTuple<I>::print(int wire_id, party_id_t pid)
{
	for(int b=0; b<I; b++) {
		printf("k^%d_{%u,%d}: ",pid,wire_id,b);
		std::cout << keys[b][pid-1] << std::endl;
	}
}

template class KeyTuple<2>;
template class KeyTuple<4> ;
