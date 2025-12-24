#ifndef _Program
#define _Program

#include "Processor/Instruction.h"
#include "Processor/Data_Files.h"

template<class sint, class sgf2n> class Machine;

/* A program is a vector of instructions */

class Program
{
  vector<Instruction> p;
  // Here we note the number of bits, squares and triples and input
  // data needed
  //  - This is computed for a whole program sequence to enable
  //    the run time to be able to determine which ones to pass to it
  DataPositions offline_data_used;

  // Maximal register used
  unsigned max_reg[MAX_REG_TYPE];

  // Memory size used directly
  size_t max_mem[MAX_REG_TYPE];

  // True if program contains variable-sized loop
  bool unknown_usage;

  string hash;

  string name;

  void compute_constants();

  public:

  bool writes_persistence;

  Program(int nplayers) : offline_data_used(nplayers),
      unknown_usage(false), writes_persistence(false)
    { compute_constants(); }

  size_t size() const { return p.size(); }

  string get_name() const { return name; }

  // Read in a program
  void parse(string filename);
  void parse_with_error(string filename);
  void parse(istream& s);

  DataPositions get_offline_data_used() const { return offline_data_used; }
  void print_offline_cost() const;

  bool usage_unknown() const { return unknown_usage; }

  unsigned num_reg(RegType reg_type) const
    { return max_reg[reg_type]; }

  size_t direct_mem(RegType reg_type) const
    { return max_mem[reg_type]; }

  const string& get_hash() const
    { return hash; }

  friend ostream& operator<<(ostream& s,const Program& P);

  // Execute this program, updateing the processor and memory
  // and streams pointing to the triples etc
  template<class sint, class sgf2n>
  void execute(Processor<sint, sgf2n>& Proc) const;

  template<class sint, class sgf2n>
  void execute_with_errors(Processor<sint, sgf2n>& Proc) const;

  template<class T>
  void mulm_check() const;
};

#endif

