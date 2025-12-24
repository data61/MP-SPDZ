#ifndef PROCESSOR_PROCESSOR_HPP_
#define PROCESSOR_PROCESSOR_HPP_

#include "Processor/Processor.h"
#include "Processor/Program.h"
#include "GC/square64.h"
#include "SpecificPrivateOutput.h"
#include "Conv2dTuple.h"
#include "Protocols/Replicated.h"

#include "Processor/ProcessorBase.hpp"
#include "GC/Processor.hpp"
#include "GC/ShareThread.hpp"
#include "Protocols/SecureShuffle.hpp"

#include <sodium.h>
#include <string>

template <class T>
SubProcessor<T>::SubProcessor(ArithmeticProcessor& Proc, typename T::MAC_Check& MC,
    Preprocessing<T>& DataF, Player& P) :
    SubProcessor<T>(MC, DataF, P, &Proc)
{
}

template <class T>
SubProcessor<T>::SubProcessor(typename T::MAC_Check& MC,
    Preprocessing<T>& DataF, Player& P, ArithmeticProcessor* Proc) :
    Proc(Proc), MC(MC), P(P), DataF(DataF), protocol(P), input(*this, MC),
    bit_prep(bit_usage), shuffler(*this)
{
  DataF.set_proc(this);
  protocol.init(DataF, MC);
  DataF.set_protocol(protocol);
  MC.set_prep(DataF);
  bit_usage.set_num_players(P.num_players());
  personal_bit_preps.resize(P.num_players());
  for (int i = 0; i < P.num_players(); i++)
    personal_bit_preps[i] = new typename BT::LivePrep(bit_usage, i);
}

template<class T>
SubProcessor<T>::~SubProcessor()
{
  DataF.set_proc(0);
  for (size_t i = 0; i < personal_bit_preps.size(); i++)
    {
      auto& x = personal_bit_preps[i];
      delete x;
    }
#ifdef VERBOSE
  if (not bit_usage.empty())
    {
      cerr << "Mixed-circuit preprocessing cost:" << endl;
      bit_usage.print_cost();
    }
#endif
}

template<class sint, class sgf2n>
inline ofstream& Processor<sint, sgf2n>::get_public_output()
{
  if (not public_output.is_open())
    public_output.open(get_filename(PREP_DIR "Public-Output-", true).c_str(),
        ios_base::out);

  return public_output;
}

template<class sint, class sgf2n>
inline ofstream& Processor<sint, sgf2n>::get_binary_output()
{
  if (not binary_output.is_open())
    binary_output.open(
        get_parameterized_filename(P.my_num(), thread_num,
            PREP_DIR "Binary-Output"), ios_base::out);

  return binary_output;
}

template<class sint, class sgf2n>
Processor<sint, sgf2n>::Processor(int thread_num,Player& P,
        typename sgf2n::MAC_Check& MC2,typename sint::MAC_Check& MCp,
        Machine<sint, sgf2n>& machine,
        const Program& program)
: ArithmeticProcessor(machine.opts, thread_num),DataF(machine, &Procp, &Proc2),P(P),
  MC2(MC2),MCp(MCp),machine(machine),
  share_thread(DataF.DataFb, P, machine.get_bit_mac_key()),
  Procb(machine.bit_memories),
  Proc2(*this,MC2,DataF.DataF2,P),Procp(*this,MCp,DataF.DataFp,P),
  external_clients(machine.external_clients),
  client_timer(client_stats.timer)
{
  reset(program,0);

  public_input_filename = get_filename("Programs/Public-Input/",false);
  public_input.open(public_input_filename);
  private_input_filename = (get_filename(PREP_DIR "Private-Input-",true));
  private_input.open(private_input_filename.c_str());

  open_input_file(P.my_num(), thread_num, machine.opts.cmd_private_input_file);

  string input_prefix = machine.opts.cmd_private_input_file;
  if (input_prefix == OnlineOptions().cmd_private_input_file
      or input_prefix == ".")
    input_prefix = PREP_DIR "Input-Binary";
  else
    input_prefix += "-Binary";
  binary_input_filename = get_parameterized_filename(P.my_num(), thread_num,
      input_prefix);
  binary_input.open(binary_input_filename);

  secure_prng.ReSeed();
  shared_prng.SeedGlobally(P, false);
  vector<IntBase<octet>> seed(shared_prng.get_seed(), shared_prng.get_seed() + SEED_SIZE);
  Procp.protocol.forward_sync(seed);
  shared_prng.SetSeed((octet*) seed.data());

  setup_redirection(P.my_num(), thread_num, opts, out, sint::real_shares(P));
  Procb.out = out;
}


template<class sint, class sgf2n>
Processor<sint, sgf2n>::~Processor()
{
  share_thread.post_run();
#ifdef VERBOSE
  if (sent)
    cerr << "Opened " << sent << " elements in " << rounds << " rounds" << endl;
#endif
  if (OnlineOptions::singleton.verbose and client_timer.elapsed())
    cerr << "Client communication: " << client_stats.data * 1e-6 << " MB in "
        << client_timer.elapsed() << " seconds and " << client_stats.rounds
        << " rounds " << endl;
}

template<class sint, class sgf2n>
string Processor<sint, sgf2n>::get_filename(const char* prefix, bool use_number)
{
  stringstream filename;
  filename << prefix;
  if (!use_number)
    filename << machine.progname;
  if (use_number)
    filename << P.my_num();
  if (thread_num > 0)
    filename << "-" << thread_num;
#ifdef DEBUG_FILES
  cerr << "Opening file " << filename.str() << endl;
#endif
  return filename.str();
}


template<class sint, class sgf2n>
void Processor<sint, sgf2n>::reset(const Program& program,int arg)
{
  Proc2.get_S().resize(program.num_reg(SGF2N));
  Proc2.get_C().resize(program.num_reg(CGF2N));
  Procp.get_S().resize(program.num_reg(SINT));
  Procp.get_C().resize(program.num_reg(CINT));
  Ci.resize(program.num_reg(INT));

  this->arg = arg;
  Procb.reset(program);
}

template<class T>
void SubProcessor<T>::check()
{
  // protocol check before last MAC check
  protocol.check();
  // MACCheck
  MC.Check(P);
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::check()
{
  Procp.check();
  Proc2.check();
  share_thread.check();

  //cout << num << " : Checking broadcast" << endl;
  P.Check_Broadcast();
  //cout << num << " : Broadcast checked "<< endl;
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::dabit(const Instruction& instruction)
{
  int size = instruction.get_size();
  int unit = sint::bit_type::default_length;
  for (int i = 0; i < DIV_CEIL(size, unit); i++)
  {
    Procb.S[instruction.get_r(1) + i] = {};
  }
  auto a = Procp.get_S().iterator_for_size(instruction.get_r(0), size);
  for (int i = 0; i < size; i++)
  {
    typename sint::bit_type tmp;
    Procp.DataF.get_dabit(*a++, tmp);
    Procb.S[instruction.get_r(1) + i / unit] ^= tmp << (i % unit);
  }
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::edabit(const Instruction& instruction, bool strict)
{
  auto& regs = instruction.get_start();
  int size = instruction.get_size();
  Procp.DataF.get_edabits(strict, size,
          &Procp.get_S_ref(instruction.get_r(0)), Procb.S, regs);
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::convcintvec(const Instruction& instruction)
{
  int unit = GC::Clear::N_BITS;
  assert(unit == 64);
  int n_inputs = instruction.get_size();
  int n_bits = instruction.get_start().size();
  for (int i = 0; i < DIV_CEIL(n_inputs, unit); i++)
    {
      for (int j = 0; j < DIV_CEIL(n_bits, unit); j++)
        {
          square64 square;
          int n_rows = min(n_inputs - i * unit, unit);
          int n_cols = min(n_bits - j * unit, unit);
          for (int k = 0; k < n_rows; k++)
            square.rows[k] =
                Integer::convert_unsigned(
                    Procp.C[instruction.get_r(0) + i * unit + k] >> (j * unit)).get();
          square.transpose(n_rows, n_cols);
          for (int k = 0; k < n_cols; k++)
            Procb.C[instruction.get_start()[k + j * unit] + i] = square.rows[k];
        }
    }
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::split(const Instruction& instruction)
{
  int n = instruction.get_n();
  assert (instruction.get_start().size() % n == 0);
  int unit = GC::Clear::N_BITS;
  assert(unit == 64);
  int n_inputs = instruction.get_size();
  int n_bits = instruction.get_start().size() / n;
  assert(share_thread.protocol != 0);
  sint::split(Procb.S, instruction.get_start(), n_bits,
      &read_Sp(instruction.get_r(0)), n_inputs, *share_thread.protocol);
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::unsplit(const Instruction& instruction)
{
  Procp.protocol.unsplit(Procp.S, Procb.S, instruction);
}


#include "Networking/sockets.h"
#include "Math/Setup.h"

// Write socket (typically SPDZ engine -> external client), for different register types.
// RegType and SecrecyType determines how registers are read and the socket stream is packed.
// If message_type is > 0, send message_type in bytes 0 - 3, to allow an external client to
//  determine the data structure being sent in a message.
template<class sint, class sgf2n>
void Processor<sint, sgf2n>::write_socket(const RegType reg_type,
    bool send_macs, int socket_id, int message_type,
    const vector<int>& registers, int size)
{
  int m = registers.size();
  socket_stream.reset_write_head();

  //First 4 bytes is message_type (unless indicate not needed)
  if (message_type != 0) {
    socket_stream.store(message_type);
  }

  auto rec_factor = sint::get_rec_factor(P.my_num(), P.num_players());

  for (int j = 0; j < size; j++)
    {
      for (int i = 0; i < m; i++)
        {
          if (reg_type == SINT)
            {
              // Send vector of secret shares and optionally macs
              if (send_macs)
                get_Sp_ref(registers[i] + j).pack(socket_stream);
              else
                get_Sp_ref(registers[i] + j).pack(socket_stream, rec_factor);
            }
          else if (reg_type == CINT)
            {
              // Send vector of clear public field elements
              get_Cp_ref(registers[i] + j).pack(socket_stream);
            }
          else if (reg_type == INT)
            {
              // Send vector of 64-bit clear ints
              socket_stream.store(get_Ci_ref(registers[i] + j));
            }
          else
            {
              stringstream ss;
              ss << "Write socket instruction with unknown reg type "
                  << reg_type << "." << endl;
              throw Processor_Error(ss.str());
            }
        }
    }

  if (OnlineOptions::singleton.has_option("verbose_comm"))
    fprintf(stderr, "Send %zu bytes to client %d\n", socket_stream.get_length(),
        socket_id);

  try {
    TimeScope _(client_stats.add(socket_stream.get_length()));
    socket_stream.Send(external_clients.get_socket(socket_id));
  }
    catch (bad_value& e) {
    cerr << "Send error thrown when writing " << m << " values of type " << reg_type << " to socket id " 
      << socket_id << "." << endl;
  }
}


// Receive vector of 64-bit clear ints
template<class sint, class sgf2n>
void Processor<sint, sgf2n>::read_socket_ints(int client_id,
    const vector<int>& registers, int size)
{
  int m = registers.size();
  socket_stream.reset_write_head();
  client_timer.start();
  socket_stream.Receive(external_clients.get_socket(client_id));
  client_timer.stop();
  client_stats.add(socket_stream.get_length());
  for (int j = 0; j < size; j++)
    for (int i = 0; i < m; i++)
      {
        write_Ci(registers[i] + j, socket_stream.get_int(8));
      }
}

// Receive vector of public field elements
template<class sint, class sgf2n>
void Processor<sint, sgf2n>::read_socket_vector(int client_id,
    const vector<int>& registers, int size)
{
  int m = registers.size();
  socket_stream.reset_write_head();
  client_timer.start();
  socket_stream.Receive(external_clients.get_socket(client_id));
  client_timer.stop();
  client_stats.add(socket_stream.get_length());
  for (int j = 0; j < size; j++)
    for (int i = 0; i < m; i++)
      get_Cp_ref(registers[i] + j) =
          socket_stream.get<typename sint::share_type::open_type>();

  if (socket_stream.left())
    throw runtime_error("unexpected data");
}

// Receive vector of field element shares over private channel
template<class sint, class sgf2n>
void Processor<sint, sgf2n>::read_socket_private(int client_id,
    const vector<int>& registers, int size, bool read_macs)
{
  int m = registers.size();
  socket_stream.reset_write_head();
  client_timer.start();
  socket_stream.Receive(external_clients.get_socket(client_id));
  client_timer.stop();
  client_stats.add(socket_stream.get_length());

  int j, i;
  try
    {
      for (j = 0; j < size; j++)
        for (i = 0; i < m; i++)
          get_Sp_ref(registers[i] + j).unpack(socket_stream, read_macs);
    }
  catch (exception& e)
    {
      throw insufficient_shares(m * size, j * m + i, e);
    }

  if (socket_stream.left())
    throw runtime_error("unexpected share data");
}


// Read share data from a file starting at file_pos until registers filled.
// file_pos_register is written with new file position (-1 is eof).
// Tolerent to no file if no shares yet persisted.
template<class T>
template<class U>
void SubProcessor<T>::read_shares_from_file(long start_file_posn,
    int end_file_pos_register, const vector<int>& data_registers,
    size_t vector_size, U& Proc)
{
  if (not T::real_shares(P))
    return;

  string filename;
  filename = binary_file_io.filename(P.my_num());

  unsigned int size = data_registers.size();

  PointerVector<T> outbuf(size * vector_size);

  auto end_file_posn = start_file_posn;

  try {
    binary_file_io.read_from_file(filename, outbuf, start_file_posn, end_file_posn);

    for (unsigned int i = 0; i < size; i++)
    {
      for (size_t j = 0; j < vector_size; j++)
        get_S_ref(data_registers[i] + j) = outbuf.next();
    }

    Proc.write_Ci(end_file_pos_register, (long)end_file_posn);
  }
  catch (file_missing& e) {
    if (OnlineOptions::singleton.has_option("verbose_persistence"))
      cerr << "Got file missing error, will return -2. " << e.what() << endl;
    Proc.write_Ci(end_file_pos_register, (long)-2);
  }
}

// Append share data in data_registers to end of file. Expects Persistence directory to exist.
template<class T>
void SubProcessor<T>::write_shares_to_file(long start_pos,
    const vector<int>& data_registers, size_t vector_size)
{
  if (not T::real_shares(P))
    return;

  string filename = binary_file_io.filename(P.my_num());

  unsigned int size = data_registers.size();

  PointerVector<T> inpbuf(size * vector_size);

  for (unsigned int i = 0; i < size; i++)
  {
    for (size_t j = 0; j < vector_size; j++)
      inpbuf.next() = get_S_ref(data_registers[i] + j);
  }

  binary_file_io.write_to_file(filename, inpbuf, start_pos);
}

template<class T>
void SubProcessor<T>::maybe_check()
{
  if (OnlineOptions::singleton.has_option("always_check"))
    check();
}

template <class T>
void SubProcessor<T>::POpen(const Instruction& inst)
{
  if (inst.get_n() or BaseMachine::s().nthreads > 0)
    check();
  auto& reg = inst.get_start();
  int size = inst.get_size();
  assert(reg.size() % 2 == 0);
  int sz=reg.size() / 2;
  MC.init_open(P, sz * size);
  for (auto it = reg.begin() + 1; it < reg.end(); it += 2)
    for (int i = 0; i < size; i++)
      MC.prepare_open(S[*it + i]);
  MC.exchange(P);
  for (auto it = reg.begin(); it < reg.end(); it += 2)
    for (int i = 0; i < size; i++)
      C[*it + i] = MC.finalize_open();
  if (inst.get_n() or BaseMachine::s().nthreads > 0)
    check();

  if (Proc != 0)
    {
      Proc->sent += sz * size;
      Proc->rounds++;
    }

  maybe_check();
}

template<class T>
void SubProcessor<T>::muls(const vector<int>& reg)
{
    assert(reg.size() % 4 == 0);

    SubProcessor<T>& proc = *this;
    protocol.init_mul();
    for (auto it = reg.begin(); it < reg.end(); it += 4)
    {
        for (int j = 1; j < 4; j++)
            assert(proc.S.begin() + *(it + j) <= proc.S.end());
        auto x = proc.S.begin() + *(it + 2);
        auto y = proc.S.begin() + *(it + 3);
        for (int j = 0; j < *it; j++)
            protocol.prepare_mul(*x++, *y++);
    }
    protocol.exchange();
    for (auto it = reg.begin(); it < reg.end(); it += 4)
    {
        auto z = proc.S.begin() + *(it + 1);
        for (int j = 0; j < *it; j++)
            *z++ = protocol.finalize_mul();
        protocol.counter += *it;
    }

    maybe_check();
}

template<class T>
void SubProcessor<T>::mulrs(const vector<int>& reg)
{
    assert(reg.size() % 4 == 0);
    int n = reg.size() / 4;

    SubProcessor<T>& proc = *this;
    protocol.init_mul();
    for (int i = 0; i < n; i++)
        for (int j = 0; j < reg[4 * i]; j++)
        {
            auto& x = proc.S[reg[4 * i + 2] + j];
            auto& y = proc.S[reg[4 * i + 3]];
            protocol.prepare_mul(x, y);
        }
    protocol.exchange();
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < reg[4 * i]; j++)
        {
            proc.S[reg[4 * i + 1] + j] = protocol.finalize_mul();
        }
        protocol.counter += reg[4 * i];
    }

    maybe_check();
}

template<class T>
void SubProcessor<T>::dotprods(const vector<int>& reg, int size)
{
    protocol.init_dotprod();
    for (int i = 0; i < size; i++)
    {
        auto it = reg.begin();
        while (it != reg.end())
        {
            auto next = it + *it;
            it += 2;
            while (it != next)
            {
                protocol.prepare_dotprod(S[*it + i], S[*(it + 1) + i]);
                it += 2;
            }
            protocol.next_dotprod();
        }
    }
    protocol.exchange();
    for (int i = 0; i < size; i++)
    {
        auto it = reg.begin();
        while (it != reg.end())
        {
            auto next = it + *it;
            it++;
            S[*it + i] = protocol.finalize_dotprod((next - it) / 2);
            it = next;
        }
    }

    maybe_check();
}

template<class T>
void SubProcessor<T>::matmuls(const StackedVector<T>& source,
        const Instruction& instruction)
{
    protocol.init_dotprod();

    auto& start = instruction.get_start();
    assert(start.size() % 6 == 0);

    for(auto it = start.begin(); it < start.end(); it += 6)
    {
        auto dim = it + 3;
        auto A = source.begin() + *(it + 1);
        auto B = source.begin() + *(it + 2);
        assert(A + dim[0] * dim[1] <= source.end());
        assert(B + dim[1] * dim[2] <= source.end());

        for (int i = 0; i < dim[0]; i++)
            for (int j = 0; j < dim[2]; j++)
            {
                for (int k = 0; k < dim[1]; k++)
                    protocol.prepare_dotprod(*(A + i * dim[1] + k),
                            *(B + k * dim[2] + j));
                protocol.next_dotprod();
            }
    }

    protocol.exchange();

    for(auto it = start.begin(); it < start.end(); it += 6)
    {
        auto C = S.begin() + *it;
        auto dim = it + 3;
        assert(C + dim[0] * dim[2] <= S.end());
        for (int i = 0; i < dim[0]; i++)
            for (int j = 0; j < dim[2]; j++)
                *(C + i * dim[2] + j) = protocol.finalize_dotprod(dim[1]);
    }

    maybe_check();
}


template<class T>
void SubProcessor<T>::matmulsm(const MemoryPart<T>& source,
        const vector<int>& start)
{
    assert(Proc);

    auto batchStartMatrix = start.begin();
    int batchStartI = 0;
    int batchStartJ = 0;

    protocol.init_dotprod();
    for (auto matmulArgs = start.begin(); matmulArgs < start.end(); matmulArgs += 12) {
        auto output = S.begin() + matmulArgs[0];
        size_t firstFactorBase  = Proc->get_Ci().at(matmulArgs[1]).get();
        size_t secondFactorBase = Proc->get_Ci().at(matmulArgs[2]).get();
        auto resultNumberOfRows = matmulArgs[3];
        auto usedNumberOfFirstFactorColumns = matmulArgs[4];
        auto resultNumberOfColumns = matmulArgs[5];
        auto firstFactorTotalNumberOfColumns = matmulArgs[10];
        auto secondFactorTotalNumberOfColumns = matmulArgs[11];

        assert(output + resultNumberOfRows * resultNumberOfColumns <= S.end());

        for (int j = 0; j < resultNumberOfColumns; j += 1) {
            auto actualSecondFactorColumn =
                    Proc->get_Ci().at(matmulArgs[9] + j).get();
            auto secondBase = source.begin() + secondFactorBase
                    + actualSecondFactorColumn;
            for (auto &x : Range(Proc->get_Ci(), matmulArgs[8],
                    usedNumberOfFirstFactorColumns))
                assert(
                        secondBase + x.get() * secondFactorTotalNumberOfColumns
                                < source.end());
        }

        vector<long> second_factors;
        second_factors.reserve(usedNumberOfFirstFactorColumns);

        for (auto& x : Range(Proc->get_Ci(), matmulArgs[8],
                usedNumberOfFirstFactorColumns))
            second_factors.push_back(x.get() * secondFactorTotalNumberOfColumns);

        for (int i = 0; i < resultNumberOfRows; i += 1) {
            auto actualFirstFactorRow = Proc->get_Ci().at(matmulArgs[6] + i).get();
            auto firstBase = source.begin() + firstFactorBase
                    + actualFirstFactorRow * firstFactorTotalNumberOfColumns;

            for (auto& x : Range(Proc->get_Ci(), matmulArgs[7],
                    usedNumberOfFirstFactorColumns))
                assert(firstBase + x.get() < source.end());

            for (int j = 0; j < resultNumberOfColumns; j += 1) {
                auto actualSecondFactorColumn = Proc->get_Ci().at(matmulArgs[9] + j).get();
                auto secondBase = source.begin() + secondFactorBase
                        + actualSecondFactorColumn;

#ifdef MATMULSM_DEBUG
                cout << "Preparing " << i << "," << j << "(buffer size: " << protocol.get_buffer_size() << ")" << endl;
#endif

                auto second_it = second_factors.begin();

                for (auto& x : Range(Proc->get_Ci(), matmulArgs[7],
                        usedNumberOfFirstFactorColumns))
                {
                    auto actualFirstFactorColumn = x.get();

                    auto first = firstBase + actualFirstFactorColumn;
                    auto second = secondBase + *second_it++;

                    protocol.prepare_dotprod(*first, *second);
                }
                protocol.next_dotprod();

                if (protocol.get_buffer_size() > OnlineOptions::singleton.batch_size) {
                    protocol.exchange();

                    matmulsm_finalize_batch(batchStartMatrix, batchStartI, batchStartJ,
                        matmulArgs, i, j);
                    batchStartMatrix = matmulArgs;
                    batchStartI = i;
                    batchStartJ = j + 1;

                    protocol.init_dotprod();
                }
            }
        }
    }

    protocol.exchange();
    auto lastMatmulsArgs = start.end() - 12;
    auto lastMatrixRows = lastMatmulsArgs[3];
    auto lastMatrixColumns = lastMatmulsArgs[5];
    matmulsm_finalize_batch(batchStartMatrix, batchStartI, batchStartJ,
                        lastMatmulsArgs, lastMatrixRows - 1, lastMatrixColumns - 1);

    maybe_check();
}

template<class T>
void SubProcessor<T>::matmulsm_finalize_batch(vector<int>::const_iterator startMatmul, int startI, int startJ,
    vector<int>::const_iterator endMatmul, int endI, int endJ) {

    for (auto matmulArgs = startMatmul; matmulArgs <= endMatmul; matmulArgs += 12) {
        auto output = S.begin() + matmulArgs[0];
        auto resultNumberOfRows = matmulArgs[3];
        auto usedNumberOfFirstFactorColumns = matmulArgs[4];
        auto resultNumberOfColumns = matmulArgs[5];

        assert(output + resultNumberOfRows * resultNumberOfColumns <= S.end());

        // Finish the first unfinished row in the current matrix.
        int firstRowEndJ = resultNumberOfColumns - 1;
        if (matmulArgs == endMatmul && startI == endI) // For the case that the batch covers only a part of the first row of current matrix or only part of a single row.
            firstRowEndJ = endJ;
            #ifdef MATMULSM_DEBUG
                    cout << "Batch is in single row " << endJ << endl;
            #endif
        for (int j = startJ; j <= firstRowEndJ; j += 1) {
#ifdef MATMULSM_DEBUG
            cout << "Finalizing (first row) " << startI << "," << j << endl;
#endif
            *(output + startI * resultNumberOfColumns + j) = protocol.finalize_dotprod(usedNumberOfFirstFactorColumns);
        }
        if (firstRowEndJ == resultNumberOfColumns - 1) {
            startJ = 0;
            startI += 1;
        }
        else {
            // The whole batch covers only a part of a single row.
            startJ = endJ + 1;
        }

        // Determine the point up until which the batch runs in the current matrix.
        int currentMatrixEndI = resultNumberOfRows - 1;
        int currentMatrixEndJ = resultNumberOfColumns - 1;
        if (matmulArgs == endMatmul) {
            currentMatrixEndI = endI;
            currentMatrixEndJ = endJ;
        }

        // Finish the rows that always are complete, i.e., the second to the "second to last" row.
        for (; startI <= currentMatrixEndI - 1; startI += 1) {
            for (int j = 0; j < resultNumberOfColumns; j += 1) {
#ifdef MATMULSM_DEBUG
                cout << "Finalizing (main part) " << startI << "," << j << endl;
#endif
                *(output + startI * resultNumberOfColumns + j) = protocol.finalize_dotprod(usedNumberOfFirstFactorColumns);
            }
        }

        // (Partially) finish the last row.
        if (startI == currentMatrixEndI) {
            for (; startJ <= currentMatrixEndJ; startJ += 1) {
#ifdef MATMULSM_DEBUG
                cout << "Finalizing (last row) " << startI << "," << startJ << endl;
#endif
                *(output + startI * resultNumberOfColumns + startJ) = protocol.finalize_dotprod(usedNumberOfFirstFactorColumns);
            }
        }
        else {
#ifdef MATMULSM_DEBUG
            // This happens when there is only one row.
            cout << "Skipping final row of matrix because it was handled previously." << endl;
#endif
        }

        if (matmulArgs < endMatmul) {
            // Reset startI and startJ to the beginning of the matrix.
            startI = 0;
            startJ = 0;
        }
    }
}

template<class T>
void SubProcessor<T>::matmulsm_finalize(int i, int j, const vector<int>& dim,
        typename vector<T>::iterator C)
{
#ifdef DEBUG_MATMULSM
            cerr << "matmulsm finalize " << i << " " << j << endl;
#endif
    *(C + i * dim[2] + j) = protocol.finalize_dotprod(dim[1]);
}

template<class T>
void SubProcessor<T>::conv2ds(const Instruction& instruction)
{
    auto& args = instruction.get_start();
    vector<Conv2dTuple> tuples;
    for (size_t i = 0; i < args.size(); i += 15)
        tuples.push_back(Conv2dTuple(args, i));
    size_t done = 0;
    while (done < tuples.size())
    {
        protocol.init_dotprod();
        size_t i;
        for (i = done; i < tuples.size() and protocol.get_buffer_size() <
                OnlineOptions::singleton.batch_size; i++)
            tuples[i].pre(S, protocol);
        protocol.exchange();
        for (; done < i; done++)
            tuples[done].post(S, protocol);
    }

    maybe_check();
}

inline
Conv2dTuple::Conv2dTuple(const vector<int>& arguments, int start)
{
    assert(arguments.size() >= start + 15ul);
    auto args = arguments.data() + start + 3;
    output_h = args[0], output_w = args[1];
    inputs_h = args[2], inputs_w = args[3];
    weights_h = args[4], weights_w = args[5];
    stride_h = args[6], stride_w = args[7];
    n_channels_in = args[8];
    padding_h = args[9];
    padding_w = args[10];
    batch_size = args[11];
    r0 = arguments[start];
    r1 = arguments[start + 1];
    r2 = arguments[start + 2];
    lengths.resize(batch_size, vector<vector<int>>(output_h, vector<int>(output_w)));
    filter_stride_h = 1;
    filter_stride_w = 1;
    if (stride_h < 0)
    {
        filter_stride_h = -stride_h;
        stride_h = 1;
    }
    if (stride_w < 0)
    {
        filter_stride_w = -stride_w;
        stride_w = 1;
    }
}

template<class T>
void Conv2dTuple::pre(StackedVector<T>& S, typename T::Protocol& protocol)
{
    for (int i_batch = 0; i_batch < batch_size; i_batch ++)
    {
        size_t base = r1 + i_batch * inputs_w * inputs_h * n_channels_in;
        assert(base + inputs_w * inputs_h * n_channels_in <= S.size());
        T* input_base = &S[base];
        for (int out_y = 0; out_y < output_h; out_y++)
            for (int out_x = 0; out_x < output_w; out_x++)
            {
                int in_x_origin = (out_x * stride_w) - padding_w;
                int in_y_origin = (out_y * stride_h) - padding_h;

                for (int filter_y = 0; filter_y < weights_h; filter_y++)
                {
                    int in_y = in_y_origin + filter_y * filter_stride_h;
                    if ((0 <= in_y) and (in_y < inputs_h))
                        for (int filter_x = 0; filter_x < weights_w; filter_x++)
                        {
                            int in_x = in_x_origin + filter_x * filter_stride_w;
                            if ((0 <= in_x) and (in_x < inputs_w))
                            {
                                T* pixel_base = &input_base[(in_y * inputs_w
                                        + in_x) * n_channels_in];
                                T* weight_base = &S[r2
                                        + (filter_y * weights_w + filter_x)
                                                * n_channels_in];
                                for (int in_c = 0; in_c < n_channels_in; in_c++)
                                    protocol.prepare_dotprod(pixel_base[in_c],
                                            weight_base[in_c]);
                                lengths[i_batch][out_y][out_x] += n_channels_in;
                            }
                        }
                }

                protocol.next_dotprod();
            }
    }
}

template<class T>
void Conv2dTuple::post(StackedVector<T>& S, typename T::Protocol& protocol)
{
    for (int i_batch = 0; i_batch < batch_size; i_batch ++)
    {
        size_t base = r0 + i_batch * output_h * output_w;
        assert(base + output_h * output_w <= S.size());
        T* output_base = &S[base];
        for (int out_y = 0; out_y < output_h; out_y++)
            for (int out_x = 0; out_x < output_w; out_x++)
            {
                output_base[out_y * output_w + out_x] =
                        protocol.finalize_dotprod(
                                lengths[i_batch][out_y][out_x]);
            }
    }
}

template<class T>
void SubProcessor<T>::secure_shuffle(const Instruction& instruction)
{
    size_t n = instruction.get_size();
    size_t unit_size = instruction.get_n();
    size_t output_base = instruction.get_r(0);
    size_t input_base = instruction.get_r(1);

    typename T::Protocol::Shuffler shuffler(*this);

    typename T::Protocol::Shuffler::shuffle_type shuffle;
    shuffler.generate(n / unit_size, shuffle);

    vector<ShuffleTuple<T>> shuffles{ShuffleTuple<T>(n, output_base,
            input_base, unit_size, shuffle, true)};
    shuffler.apply_multiple(S, shuffles);

    maybe_check();
}

template<class T>
size_t SubProcessor<T>::generate_secure_shuffle(const Instruction& instruction,
    ShuffleStore& shuffle_store)
{
    size_t n = instruction.get_n();
    auto res = shuffle_store.add(n);
    shuffler.generate(n, shuffle_store.get(res).second);
    return res;
}

template<class T>
void SubProcessor<T>::apply_shuffle(const Instruction& instruction,
                                    ShuffleStore& shuffle_store)
{
    const auto& args = instruction.get_start();

    const auto n_shuffles = args.size() / 6;
    vector<ShuffleTuple<T>> shuffles;

    for (size_t i = 0; i < n_shuffles; i++)
    {
        shuffles.push_back(
                ShuffleTuple<T>(args[6 * i], args[6 * i + 1], args[6 * i + 2],
                        args[6 * i + 3],
                        shuffle_store.get(Proc->read_Ci(args[6 * i + 4])),
                        bool(args[6 * i + 5])));
    }

    shuffler.apply_multiple(S, shuffles);

    maybe_check();
}

template<class T>
void SubProcessor<T>::inverse_permutation(const Instruction& instruction) {
    shuffler.inverse_permutation(S, instruction.get_size(), instruction.get_start()[0],
                                 instruction.get_start()[1]);
    maybe_check();
}

template<class T>
void SubProcessor<T>::input_personal(const vector<int>& args)
{
  input.reset_all(P);
  for (size_t i = 0; i < args.size(); i += 4)
    if (input.is_me(args[i + 1]))
      {
        auto begin = C.begin() + args[i + 3];
        auto end = begin + args[i];
        assert(end <= C.end());
        for (auto it = begin; it < end; it++)
          input.add_mine(*it);
      }
    else
      for (int j = 0; j < args[i]; j++)
        input.add_other(args[i + 1]);
  input.exchange();
  for (size_t i = 0; i < args.size(); i += 4)
    {
      auto begin = S.begin() + args[i + 2];
      auto end = begin + args[i];
      assert(end <= S.end());
      for (auto it = begin; it < end; it++)
        *it = input.finalize(args[i + 1]);
    }
}

/**
 *
 * @tparam T
 * @param args Args contains four arguments
 *      a[0] = the size of the input (and output) vector
 *      a[1] = the player to which to reveal the output
 *      a[2] = the memory address of the input vector (sint) (i.e. the value to reveal)
 *      a[3] = the memory address of the output vector (cint) (i.e. the register to store the revealed value)
 * // TODO: When would there be multiple sets of arguments? (for ... i < args.size(); i += 4 ... )
 */
template<class T>
void SubProcessor<T>::private_output(const vector<int>& args)
{
  typename T::PrivateOutput output(*this);
  for (size_t i = 0; i < args.size(); i += 4)
    for (int j = 0; j < args[i]; j++)
      {
        int player = args[i + 1];
        output.prepare_sending(S.at(args[i + 3] + j), player);
      }
  output.exchange();
  for (size_t i = 0; i < args.size(); i += 4)
    for (int j = 0; j < args[i]; j++)
      C.at(args[i + 2] + j) = output.finalize(args[i + 1]);
}

template<class T>
void SubProcessor<T>::send_personal(const vector<int>& args)
{
  octetStreams to_send(P), to_receive(P);
  for (size_t i = 0; i < args.size(); i += 5)
    if (args[i + 3] == P.my_num())
        for (int j = 0; j < args[i]; j++)
          C[args[i + 4] + j].pack(to_send[args[i + 1]]);
  P.send_receive_all(to_send, to_receive);
  for (size_t i = 0; i < args.size(); i += 5)
    if (args[i + 1] == P.my_num())
        for (int j = 0; j < args[i]; j++)
          C[args[i + 2] + j].unpack(to_receive[args[i + 3]]);
}

template<class sint, class sgf2n>
typename sint::clear Processor<sint, sgf2n>::get_inverse2(unsigned m)
{
  for (unsigned i = inverses2m.size(); i <= m; i++)
    inverses2m.push_back((cint(1) << i).invert());
  return inverses2m[m];
}

template<class T, class U>
void fixinput_int(T& proc, const Instruction& instruction, U)
{
  U* x = new U[instruction.get_size()];
  proc.binary_input.read((char*) x, sizeof(U) * instruction.get_size());
  for (int i = 0; i < instruction.get_size(); i++)
    proc.write_Cp(instruction.get_r(0) + i, x[i]);
  delete[] x;
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::fixinput(const Instruction& instruction)
{
  int n = instruction.get_n();
  if (n == P.my_num() or n == -1)
    {
      typename sint::clear tmp;
      bool use_double = false;
      switch (instruction.get_r(2))
      {
      case 0:
      case 1:
        break;
      case 2:
        use_double = true;
        break;
      default:
        throw runtime_error("unknown format for fixed-point input");
      }

      if (not sint::real_shares(P))
        return;

      if (binary_input.fail())
        throw IO_Error(
            "Failure reading from " + binary_input_filename
                + ". You might need to copy it "
                + "from the location of compilation.");

      if (binary_input.peek() == EOF)
        throw IO_Error("not enough inputs in " + binary_input_filename);

      if (instruction.get_r(2) == 0)
        {
          if (instruction.get_r(1) == 1)
            fixinput_int(*this, instruction, int8_t());
          else
            fixinput_int(*this, instruction, int64_t());
        }
      else
        {
          for (int i = 0; i < instruction.get_size(); i++)
            {
              double buf;
              if (use_double)
                binary_input.read((char*) &buf, sizeof(double));
              else
                {
                  float x;
                  binary_input.read((char*) &x, sizeof(float));
                  buf = x;
                }
              tmp = bigint::tmp = round(buf * exp2(instruction.get_r(1)));
              write_Cp(instruction.get_r(0) + i, tmp);
            }
        }

      if (binary_input.fail())
        throw IO_Error("failure reading from " + binary_input_filename);
    }
}

template<class sint, class sgf2n>
long Processor<sint, sgf2n>::sync(long x)
{
  vector<Integer> tmp = {x};
  Procp.protocol.sync(tmp, P);
  return tmp[0].get();
}

template<class sint>
template<class U>
void ProtocolBase<sint>::sync(vector<U>& x, Player& P)
{
  if (not sint::symmetric)
    {
      octetStream os;
      // send number to dealer
      if (P.my_num() == 0)
        {
          os.store(x);
          P.send_to(P.num_players() - 1, os);
        }
      if (not sint::real_shares(P))
        {
          P.receive_player(0, os);
          os.get(x);
        }
    }
}

template<class T>
void SubProcessor<T>::push_stack()
{
  S.push_stack();
  C.push_stack();
}

template<class T>
void SubProcessor<T>::push_args(const vector<int>& args)
{
  auto char2 = T::clear::characteristic_two;
  S.push_args(args, char2 ? SGF2N : SINT);
  C.push_args(args, char2 ? CGF2N : CINT);
}

template<class T>
void SubProcessor<T>::pop_stack(const vector<int>& results)
{
  auto char2 = T::clear::characteristic_two;
  S.pop_stack(results, char2 ? SGF2N : SINT);
  C.pop_stack(results, char2 ? CGF2N : CINT);
}

template<class sint, class sgf2n>
void Processor<sint, sgf2n>::call_tape(int tape_number, int arg,
    const vector<int>& args)
{
  PC_stack.push_back(PC);
  arg_stack.push_back(this->arg);
  Procp.push_stack();
  Proc2.push_stack();
  Procb.push_stack();
  Ci.push_stack();

  auto& tape = machine.progs.at(tape_number);
  reset(tape, arg);

  Procp.push_args(args);
  Proc2.push_args(args);
  Procb.push_args(args);
  Ci.push_args(args, INT);

  tape.execute(*this);

  Procp.pop_stack(args);
  Proc2.pop_stack(args);
  Procb.pop_stack(args);
  Ci.pop_stack(args, INT);

  PC = PC_stack.back();
  PC_stack.pop_back();
  this->arg = arg_stack.back();
  arg_stack.pop_back();
}

template<class sint, class sgf2n>
TimerWithComm Processor<sint, sgf2n>::prep_time()
{
  auto res = DataF.total_time();
  res += Procp.protocol.prep_time();
  res += Proc2.protocol.prep_time();
  return res;
}

#endif
