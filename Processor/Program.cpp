
#include "Processor/Program.h"
#include "Processor/Data_Files.h"
#include "Processor/Processor.h"

#include "Processor/Instruction.hpp"

void Program::compute_constants()
{
  bool debug = OnlineOptions::singleton.has_option("debug_alloc");

  for (int reg_type = 0; reg_type < MAX_REG_TYPE; reg_type++)
    {
      max_reg[reg_type] = 0;
      max_mem[reg_type] = 0;
    }
  for (unsigned int i=0; i<p.size(); i++)
    {
      if (!p[i].get_offline_data_usage(offline_data_used))
        unknown_usage = true;
      for (int reg_type = 0; reg_type < MAX_REG_TYPE; reg_type++)
        {
          auto reg = p[i].get_max_reg(reg_type);
          if (debug and reg)
            cerr << i << ": " << reg << endl;
          max_reg[reg_type] = max(max_reg[reg_type], reg);
          max_mem[reg_type] = max(max_mem[reg_type],
              p[i].get_mem(RegType(reg_type)));
        }
      writes_persistence |= (p[i].opcode & 0xFF) == WRITEFILESHARE;
      writes_persistence |= (p[i].opcode & 0xFF) == WRITEFILECLEAR;
    }


  if (not p.empty() and OnlineOptions::singleton.has_option("verbose_alloc"))
    {
      cerr << "Register usage in " << name << ":" << endl;
      for (int reg_type = 0; reg_type < MAX_REG_TYPE; reg_type++)
        if (max_reg[reg_type])
          cerr << "\tType " << reg_type << ": " << max_reg[reg_type] << endl;
    }
}

void Program::parse(string filename)
{
  if (OnlineOptions::singleton.has_option("throw_exceptions"))
      parse_with_error(filename);
  else
    {
      try
      {
          parse_with_error(filename);
      }
      catch(exception& e)
      {
          cerr << "Error in bytecode: " << e.what() << endl;
          exit(1);
      }
    }
}

void Program::parse_with_error(string filename)
{
  name = boost::filesystem::path(filename).stem().string();
  ifstream pinp(filename);
  if (pinp.fail())
    throw file_error(filename);

  try
  {
    parse(pinp);
  }
  catch (bytecode_error& e)
  {
    stringstream os;
    os << "Cannot parse " << filename << " (" << e.what() << ")" << endl;
    os << "Does the compiler version match the virtual machine? "
        << "If in doubt, recompile the VM";
    if (not OnlineOptions::singleton.executable.empty())
      os << " using 'make " << OnlineOptions::singleton.executable << "'";
    os << ".";
    throw bytecode_error(os.str());
  }

  // compute hash
  pinp.clear();
  pinp.seekg(0);
  Hash hasher;
  while (pinp.peek(), !pinp.eof())
    {
      char buf[1024];
      size_t n = pinp.readsome(buf, 1024);
      hasher.update(buf, n);
    }
  hash = hasher.final().str();
}

void Program::parse(istream& s)
{
  p.resize(0);
  Instruction instr;
  s.peek();
  while (!s.eof())
    {
      bool fail = false;
      try
      {
        instr.parse(s, p.size());
      }
      catch (bytecode_error&)
      {
        throw;
      }
      catch (exception&)
      {
        fail = true;
      }
      fail |= s.fail();

      if (fail)
        {
          stringstream os;
          os << "error while parsing " << hex << showbase << instr.opcode
              << " at " << dec << p.size();
          throw bytecode_error(os.str());
        }

      p.push_back(instr);
      //cerr << "\t" << instr << endl;
      s.peek();
    }
  compute_constants();
}

void Program::print_offline_cost() const
{
  if (unknown_usage)
    {
      cerr << "Tape has unknown usage" << endl;
      return;
    }

  cerr << "Cost of first tape:" << endl;
  offline_data_used.print_cost();
}


ostream& operator<<(ostream& s,const Program& P)
{
  for (unsigned int i=0; i<P.p.size(); i++)
    { s << i << " :: " << P.p[i] << endl; }
  return s;
}
