
#ifndef _Processor
#define _Processor

/* This is a representation of a processing element
 */

#include "Math/Integer.h"
#include "Tools/Exceptions.h"
#include "Networking/Player.h"
#include "Data_Files.h"
#include "Input.h"
#include "PrivateOutput.h"
#include "ExternalClients.h"
#include "Binary_File_IO.h"
#include "Instruction.h"
#include "ProcessorBase.h"
#include "OnlineOptions.h"
#include "Tools/SwitchableOutput.h"
#include "Tools/CheckVector.h"
#include "GC/Processor.h"
#include "GC/ShareThread.h"
#include "Protocols/SecureShuffle.h"
#include "Tools/NamedStats.h"

class Program;

// synchronize in asymmetric protocols
template<class T>
void sync(vector<Integer>& x, Player& P);

template <class T>
class SubProcessor
{
  StackedVector<typename T::clear> C;
  StackedVector<T> S;

  DataPositions bit_usage;
  NamedStats stats;

  Binary_File_IO<T> binary_file_io;

  void resize(size_t size)       { C.resize(size); S.resize(size); }

  void matmulsm_prep(int ii, int j, const MemoryPart<T>& source,
      const vector<int>& dim, size_t a, size_t b);
  void matmulsm_finalize(int i, int j, const vector<int>& dim,
      typename vector<T>::iterator C);

  void maybe_check();

  template<class sint, class sgf2n> friend class Processor;
  template<class U> friend class SPDZ;
  template<class U> friend class ProtocolBase;
  template<class U> friend class Beaver;

  typedef typename T::bit_type::part_type BT;

  typedef typename T::Protocol::Shuffler::store_type ShuffleStore;

public:
  ArithmeticProcessor* Proc;
  typename T::MAC_Check& MC;
  Player& P;
  Preprocessing<T>& DataF;

  typename T::Protocol protocol;
  typename T::Input input;

  typename BT::LivePrep bit_prep;
  vector<typename BT::LivePrep*> personal_bit_preps;

  typename T::Protocol::Shuffler shuffler;

  SubProcessor(ArithmeticProcessor& Proc, typename T::MAC_Check& MC,
      Preprocessing<T>& DataF, Player& P);
  SubProcessor(typename T::MAC_Check& MC, Preprocessing<T>& DataF, Player& P,
      ArithmeticProcessor* Proc = 0);
  ~SubProcessor();

  void check();

  // Access to PO (via calls to POpen start/stop)
  void POpen(const Instruction& inst);

  void muls(const vector<int>& reg);
  void mulrs(const vector<int>& reg);
  void dotprods(const vector<int>& reg, int size);
  void matmuls(const StackedVector<T>& source, const Instruction& instruction);
  void matmulsm(const MemoryPart<T>& source, const vector<int>& args);

  void matmulsm_finalize_batch(vector<int>::const_iterator startMatmul, int startI, int startJ,
                               vector<int>::const_iterator endMatmul,
                               int endI, int endJ);

  void conv2ds(const Instruction& instruction);

  void secure_shuffle(const Instruction& instruction);
  size_t generate_secure_shuffle(const Instruction& instruction,
      ShuffleStore& shuffle_store);
  void apply_shuffle(const Instruction& instruction, ShuffleStore& shuffle_store);
  void inverse_permutation(const Instruction& instruction);

  void input_personal(const vector<int>& args);
  void send_personal(const vector<int>& args);
  void private_output(const vector<int>& args);

  StackedVector<T>& get_S()
  {
    return S;
  }

  StackedVector<typename T::clear>& get_C()
  {
    return C;
  }

  T& get_S_ref(size_t i)
  {
    return S[i];
  }

  typename T::clear& get_C_ref(size_t i)
  {
    return C[i];
  }

  void inverse_permutation(const Instruction &instruction, int handle);

  void push_stack();
  void push_args(const vector<int>& args);
  void pop_stack(const vector<int>& results);

  // Read and write secret numeric data to file (name hardcoded at present)
  template<class U>
  void read_shares_from_file(long start_file_pos, int end_file_pos_register,
      const vector<int>& data_registers, size_t vector_size, U& Proc);
  void write_shares_to_file(long start_pos, const vector<int>& data_registers,
      size_t vector_size);
};

class ArithmeticProcessor : public ProcessorBase
{
protected:
  StackedVector<Integer> Ci;

  ofstream public_output;
  ofstream binary_output;

public:
  int thread_num;

  PRNG secure_prng;
  PRNG shared_prng;

  string private_input_filename;
  string public_input_filename;
  string binary_input_filename;

  ifstream private_input;
  ifstream public_input;
  ifstream binary_input;

  int sent, rounds;

  OnlineOptions opts;

  SwitchableOutput out;

  ArithmeticProcessor() :
      ArithmeticProcessor(OnlineOptions::singleton, BaseMachine::thread_num)
  {
  }
  ArithmeticProcessor(OnlineOptions opts, int thread_num) : thread_num(thread_num),
          sent(0), rounds(0), opts(opts) {}

  virtual ~ArithmeticProcessor()
  {
  }

  bool use_stdin()
  {
    return thread_num == 0 and opts.interactive;
  }

  int get_thread_num()
  {
    return thread_num;
  }

  long read_Ci(size_t i) const
    { return Ci[i].get(); }
  Integer& get_Ci_ref(size_t i)
    { return Ci[i]; }
  void write_Ci(size_t i, const long& x)
    { Ci[i]=x; }
  StackedVector<Integer>& get_Ci()
    { return Ci; }

  virtual ofstream& get_public_output()
  {
    throw not_implemented();
  }
  virtual ofstream& get_binary_output()
  {
    throw not_implemented();
  }

  void shuffle(const Instruction& instruction);
  void bitdecint(const Instruction& instruction);
};

template<class sint, class sgf2n>
class Processor : public ArithmeticProcessor
{
  typedef typename sint::clear cint;

  // Data structure used for reading/writing data to/from a socket (i.e. an external party to SPDZ)
  octetStream socket_stream;

  // avoid re-computation of expensive division
  vector<cint> inverses2m;

  public:
  Data_Files<sint, sgf2n> DataF;
  Player& P;
  typename sgf2n::MAC_Check& MC2;
  typename sint::MAC_Check& MCp;
  Machine<sint, sgf2n>& machine;

  GC::ShareThread<typename sint::bit_type> share_thread;
  GC::Processor<typename sint::bit_type> Procb;
  SubProcessor<sgf2n> Proc2;
  SubProcessor<sint>  Procp;

  unsigned int PC, last_PC;
  TempVars<sint, sgf2n> temp;

  ExternalClients& external_clients;

  CommStats client_stats;
  Timer& client_timer;

  void reset(const Program& program,int arg); // Reset the state of the processor
  string get_filename(const char* basename, bool use_number);

  Processor(int thread_num,Player& P,
          typename sgf2n::MAC_Check& MC2,typename sint::MAC_Check& MCp,
          Machine<sint, sgf2n>& machine,
          const Program& program);
  ~Processor();

    const typename sgf2n::clear& read_C2(size_t i) const
      { return Proc2.C[i]; }
    const sgf2n& read_S2(size_t i) const
      { return Proc2.S[i]; }
    typename sgf2n::clear& get_C2_ref(size_t i)
      { return Proc2.C[i]; }
    sgf2n& get_S2_ref(size_t i)
      { return Proc2.S[i]; }
    void write_C2(size_t i,const typename sgf2n::clear& x)
      { Proc2.C[i]=x; }
    void write_S2(size_t i,const sgf2n& x)
      { Proc2.S[i]=x; }
  
    const typename sint::clear& read_Cp(size_t i) const
      { return Procp.C[i]; }
    const sint & read_Sp(size_t i) const
      { return Procp.S[i]; }
    typename sint::clear& get_Cp_ref(size_t i)
      { return Procp.C[i]; }
    sint & get_Sp_ref(size_t i)
      { return Procp.S[i]; }
    void write_Cp(size_t i,const typename sint::clear& x)
      { Procp.C[i]=x; }
    void write_Sp(size_t i,const sint & x)
      { Procp.S[i]=x; }

  void check();

  void dabit(const Instruction& instruction);
  void edabit(const Instruction& instruction, bool strict = false);

  void convcbitvec(const Instruction& instruction);
  void convcintvec(const Instruction& instruction);
  void convcbit2s(const Instruction& instruction);
  void split(const Instruction& instruction);
  void unsplit(const Instruction& instruction);

  // Access to external client sockets for reading clear/shared data
  void read_socket_ints(int client_id, const vector<int>& registers, int size);

  void write_socket(const RegType reg_type, bool send_macs, int socket_id,
      int message_type, const vector<int>& registers, int size);

  void read_socket_vector(int client_id, const vector<int>& registers,
      int size);
  void read_socket_private(int client_id, const vector<int>& registers,
      int size, bool send_macs);

  cint get_inverse2(unsigned m);

  void fixinput(const Instruction& instruction);

  // synchronize in asymmetric protocols
  long sync(long x);

  ofstream& get_public_output();
  ofstream& get_binary_output();

  void call_tape(int tape_number, int arg, const vector<int>& results);

  TimerWithComm prep_time();

  private:

  template<class T> friend class SPDZ;
  template<class T> friend class SubProcessor;
};

#endif

