#ifndef PROCESSOR_INSTRUCTION_HPP_
#define PROCESSOR_INSTRUCTION_HPP_

#include "Processor/Instruction.h"
#include "Processor/Machine.h"
#include "Processor/Processor.h"
#include "Processor/IntInput.h"
#include "Processor/FixInput.h"
#include "Processor/FloatInput.h"
#include "Processor/instructions.h"
#include "Tools/Exceptions.h"
#include "Tools/time-func.h"
#include "Tools/parse.h"
#include "GC/Instruction.h"
#include "GC/instructions.h"

#include "Processor/Binary_File_IO.hpp"
#include "Processor/PrivateOutput.hpp"
#include "Math/bigint.hpp"

#include <stdlib.h>
#include <algorithm>
#include <sstream>
#include <map>
#include <iomanip>

#include "Tools/callgrind.h"

inline
void BaseInstruction::parse(istream& s, int inst_pos)
{
  n=0; start.resize(0);
  r[0]=0; r[1]=0; r[2]=0; r[3]=0;

  int pos=s.tellg();
  uint64_t code = get_long(s);
  size = code >> 10;
  opcode = 0x3FF & code;
  
  if (s.fail())
    throw bytecode_error("cannot read opcode");

  if (size==0)
    size=1;

  parse_operands(s, inst_pos, pos);
}

inline
void BaseInstruction::parse_operands(istream& s, int pos, int file_pos)
{
  int num_var_args = 0;
  switch (opcode)
  {
      // instructions with 3 register operands
      case ADDC:
      case ADDCB:
      case ADDS:
      case ADDM:
      case SUBC:
      case SUBS:
      case SUBML:
      case SUBMR:
      case MULC:
      case MULM:
      case DIVC:
      case MODC:
      case FLOORDIVC:
      case TRIPLE:
      case ANDC:
      case XORC:
      case ORC:
      case SHLC:
      case SHRC:
      case GADDC:
      case GADDS:
      case GADDM:
      case GSUBC:
      case GSUBS:
      case GSUBML:
      case GSUBMR:
      case GMULC:
      case GMULM:
      case GDIVC:
      case GTRIPLE:
      case GANDC:
      case GXORC:
      case GORC:
      case LTC:
      case GTC:
      case EQC:
      case ADDINT:
      case SUBINT:
      case MULINT:
      case DIVINT:
      case CONDPRINTPLAIN:
      case INPUTMASKREG:
      case ZIPS:
        get_ints(r, s, 3);
        break;
      // instructions with 2 register operands
      case LDMCI:
      case LDMSI:
      case STMCI:
      case STMSI:
      case LDMSBI:
      case STMSBI:
      case LDMCBI:
      case STMCBI:
      case MOVC:
      case MOVS:
      case MOVINT:
      case LDMINTI:
      case STMINTI:
      case LEGENDREC:
      case SQUARE:
      case INV:
      case GINV:
      case CONVINT:
      case GLDMCI:
      case GLDMSI:
      case GSTMCI:
      case GSTMSI:
      case GMOVC:
      case GMOVS:
      case GSQUARE:
      case GNOTC:
      case GCONVINT:
      case GCONVGF2N:
      case LTZC:
      case EQZC:
      case RAND:
      case DABIT:
      case SHUFFLE:
      case ACCEPTCLIENTCONNECTION:
      case PREFIXSUMS:
      case CMDLINEARG:
        get_ints(r, s, 2);
        break;
      // instructions with 1 register operand
      case BIT:
      case BITB:
      case RANDOMFULLS:
      case PRINTREGPLAIN:
      case PRINTREGPLAINB:
      case PRINTREGPLAINS:
      case PRINTREGPLAINSB:
      case LDTN:
      case LDARG:
      case STARG:
      case JMPI:
      case GBIT:
      case GPRINTREGPLAIN:
      case GPRINTREGPLAINS:
      case JOIN_TAPE:
      case PUSHINT:
      case POPINT:
      case PUBINPUT:
      case RAWOUTPUT:
      case GRAWOUTPUT:
      case PRINTINT:
      case NPLAYERS:
      case THRESHOLD:
      case PLAYERID:
      case LISTEN:
      case CLOSECLIENTCONNECTION:
      case CRASH:
      case DELSHUFFLE:
        r[0]=get_int(s);
        break;
      // instructions with 2 registers + 1 integer operand
      case ADDCI:
      case ADDCBI:
      case ADDSI:
      case SUBCI:
      case SUBSI:
      case SUBCFI:
      case SUBSFI:
      case MULCI:
      case MULCBI:
      case MULSI:
      case DIVCI:
      case MODCI:
      case ANDCI:
      case XORCI:
      case XORCBI:
      case ORCI:
      case SHLCI:
      case SHRCI:
      case SHRSI:
      case SHLCBI:
      case SHRCBI:
      case NOTC:
      case GADDCI:
      case GADDSI:
      case GSUBCI:
      case GSUBSI:
      case GSUBCFI:
      case GSUBSFI:
      case GMULCI:
      case GMULSI:
      case GDIVCI:
      case GANDCI:
      case GXORCI:
      case GORCI:
      case GSHLCI:
      case GSHRCI:
      case GSHRSI:
      case DIGESTC:
      case INPUTMASK:
      case GINPUTMASK:
      case SECSHUFFLE:
      case GSECSHUFFLE:
        get_ints(r, s, 2);
        n = get_int(s);
        break;
      case PICKS:
      case CONVMODP:
        get_ints(r, s, 3);
        n = get_int(s);
        break;
      case USE:
      case USE_INP:
      case USE_EDABIT:
          get_ints(r, s, 2);
          n = get_long(s);
          break;
      case STARTPRIVATEOUTPUT:
      case GSTARTPRIVATEOUTPUT:
      case STOPPRIVATEOUTPUT:
      case GSTOPPRIVATEOUTPUT:
        throw runtime_error("two-stage private output not supported any more");
      case USE_MATMUL:
        get_ints(r, s, 3);
        n = get_long(s);
        break;
      // instructions with 1 register + 1 integer operand
      case LDI:
      case LDSI:
      case JMPNZ:
      case JMPEQZ:
      case GLDI:
      case GLDSI:
      case PRINTREG:
      case PRINTREGB:
      case GPRINTREG:
      case LDINT:
      case INV2M:
      case CONDPRINTSTR:
      case CONDPRINTSTRB:
      case RANDOMS:
      case GENSECSHUFFLE:
      case CALL_ARG:
        r[0]=get_int(s);
        n = get_int(s);
        break;
      // instructions with 1 register + 1 long operand
      case LDMC:
      case LDMS:
      case STMC:
      case STMS:
      case LDMSB:
      case STMSB:
      case LDMCB:
      case STMCB:
      case LDMINT:
      case STMINT:
      case GLDMC:
      case GLDMS:
      case GSTMC:
      case GSTMS:
        r[0] = get_int(s);
        n = get_long(s);
        break;
      // instructions with 1 integer operand
      case PRINTSTR:
      case PRINTCHR:
      case JMP:
      case START:
      case STOP:
      case PRINTFLOATPREC:
        n = get_int(s);
        break;
      // instructions with no operand
      case TIME:
      case STARTGRIND:
      case STOPGRIND:
      case CHECK:
        break;
      // instructions with 5 register operands
      case PRINTFLOATPLAIN:
      case PRINTFLOATPLAINB:
        get_vector(5, start, s);
        break;
      case INCINT:
        r[0]=get_int(s);
        r[1]=get_int(s);
        n = get_int(s);
        get_vector(2, start, s);
        break;
      // instructions with 2 register operands
      case INVPERM:
          get_vector(2, start, s);
          break;
      // open instructions + read/write instructions with variable length args
      case MULS:
      case GMULS:
      case MULRS:
      case GMULRS:
      case DOTPRODS:
      case GDOTPRODS:
      case INPUT:
      case GINPUT:
      case INPUTFIX:
      case INPUTFLOAT:
      case INPUTMIXED:
      case INPUTMIXEDREG:
      case RAWINPUT:
      case GRAWINPUT:
      case INPUTPERSONAL:
      case SENDPERSONAL:
      case PRIVATEOUTPUT:
      case TRUNC_PR:
      case RUN_TAPE:
      case CONV2DS:
      case MATMULS:
      case GMATMULS:
      case APPLYSHUFFLE:
      case MATMULSM:
      case GMATMULSM:
        num_var_args = get_int(s);
        get_vector(num_var_args, start, s);
        break;
      // read from file, input is opcode num_args, 
      //   start_file_posn (read), end_file_posn(write) var1, var2, ...
      case READFILESHARE:
      case GREADFILESHARE:
      case CALL_TAPE:
        num_var_args = get_int(s) - 2;
        r[0] = get_int(s);
        r[1] = get_int(s);
        get_vector(num_var_args, start, s);
        break;

      // read from external client, input is : opcode num_args, client_id, var1, var2 ...
      case READSOCKETC:
      case READSOCKETS:
      case READSOCKETINT:
        num_var_args = get_int(s) - 2;
        r[0] = get_int(s);
        n = get_int(s);
        get_vector(num_var_args, start, s);
        break;

      // write to external client, input is : opcode num_args, client_id, message_type, var1, var2 ...
      case WRITESOCKETC:
      case WRITESOCKETS:
      case WRITESOCKETSHARE:
      case WRITESOCKETINT:
        num_var_args = get_int(s) - 3;
        r[0] = get_int(s);
        r[1] = get_int(s);
        n = get_int(s);
        get_vector(num_var_args, start, s);
        break;
      case INITCLIENTCONNECTION:
        get_ints(r, s, 3);
        get_string(str, s);
        break;
      case INITSECURESOCKET:
      case RESPSECURESOCKET:
        throw runtime_error("VM-controlled encryption not supported any more");
      // raw input
      case STARTINPUT:
      case GSTARTINPUT:
      case STOPINPUT:
      case GSTOPINPUT:
        throw runtime_error("two-stage input not supported any more");
      case PRINTMEM:
      case GPRINTMEM:
        throw runtime_error("memory printing not supported any more");
      case PRINTCHRINT:
      case PRINTSTRINT:
        throw runtime_error("run-time printing not supported any more");
      case PROTECTMEMS:
      case PROTECTMEMC:
      case GPROTECTMEMS:
      case GPROTECTMEMC:
      case PROTECTMEMINT:
        throw runtime_error("memory protection not supported any more");
      case GBITTRIPLE:
      case GBITGF2NTRIPLE:
      case GMULBITC:
      case GMULBITM:
        throw runtime_error("GF(2^n) bit operations not supported any more");
      case GBITDEC:
      case GBITCOM:
        num_var_args = get_int(s) - 2;
        r[0] = get_int(s);
        n = get_int(s);
        get_vector(num_var_args, start, s);
        break;
      case BITDECINT:
      case EDABIT:
      case SEDABIT:
      case WRITEFILESHARE:
      case GWRITEFILESHARE:
      case CONCATS:
      case UNSPLIT:
          num_var_args = get_int(s) - 1;
          r[0] = get_int(s);
          get_vector(num_var_args, start, s);
          break;
      case PREP:
      case GPREP:
      case CISC:
        // subtract extra argument
        num_var_args = get_int(s) - 1;
        s.read((char*)r, sizeof(r));
        get_vector(num_var_args, start, s);
        break;
      case USE_PREP:
      case GUSE_PREP:
        s.read((char*)r, sizeof(r));
        n = get_long(s);
        break;
      case REQBL:
        n = get_int(s);
        BaseMachine::s().reqbl(n);
        break;
      case GREQBL:
        n = get_int(s);
        if (n > 0 && gf2n::degree() < int(n))
          {
            stringstream ss;
            ss << "Tape requires prime of bit length " << n << endl;
            throw Processor_Error(ss.str());
          }
        break;
      case ACTIVE:
        n = get_int(s);
        BaseMachine::s().active(n);
        break;
      case XORM:
      case ANDM:
      case XORCB:
      case FIXINPUT:
        n = get_int(s);
        get_ints(r, s, 3);
        break;
      case LDBITS:
        get_ints(r, s, 2);
        n = get_int(s);
        break;
      case BITDECS:
      case BITCOMS:
      case BITDECC:
      case CONVCINTVEC:
        num_var_args = get_int(s) - 1;
        get_ints(r, s, 1);
        get_vector(num_var_args, start, s);
        break;
      case CONVCINT:
      case CONVCBIT:
        get_ints(r, s, 2);
        break;
      case CONVSINT:
      case CONVCBITVEC:
      case CONVCBIT2S:
      case NOTS:
      case NOTCB:
      case MOVSB:
        n = get_int(s);
        get_ints(r, s, 2);
        break;
      case LDMSDI:
      case STMSDI:
      case LDMSD:
      case STMSD:
      case STMSDCI:
      case XORS:
      case ANDRS:
      case ANDRSVEC:
      case ANDS:
      case INPUTB:
      case INPUTBVEC:
      case REVEAL:
        get_vector(get_int(s), start, s);
        break;
      case PRINTREGSIGNED:
      case INTOUTPUT:
        n = get_int(s);
        get_ints(r, s, 1);
        break;
      case FLOATOUTPUT:
        n = get_int(s);
        get_vector(4, start, s);
        break;
      case OPEN:
      case GOPEN:
      case TRANS:
        num_var_args = get_int(s) - 1;
        n = get_int(s);
        get_vector(num_var_args, start, s);
        break;
      case SPLIT:
        num_var_args = get_int(s) - 2;
        n = get_int(s);
        get_ints(r, s, 1);
        get_vector(num_var_args, start, s);
        break;
      default:
        ostringstream os;
        os << "Invalid instruction " << showbase << hex << opcode << " at " << dec
            << pos << "/" << hex << file_pos << dec;
        throw Invalid_Instruction(os.str());
  }
}

inline
bool Instruction::get_offline_data_usage(DataPositions& usage)
{
  switch (opcode)
  {
    case USE:
      if (r[0] >= N_DATA_FIELD_TYPE)
        throw invalid_program();
      if (r[1] >= N_DTYPE)
        throw invalid_program();
      usage.files[r[0]][r[1]] = n;
      return long(n) >= 0;
    case USE_INP:
      if (r[0] >= N_DATA_FIELD_TYPE)
        throw invalid_program();
      if (usage.inputs.size() != 1)
        {
          if ((unsigned) r[1] >= usage.inputs.size())
            throw Processor_Error("Player number too high");
          usage.inputs[r[1]][r[0]] = n;
        }
      return long(n) >= 0;
    case USE_EDABIT:
      usage.edabits[{r[0], r[1]}] = n;
      return long(n) >= 0;
    case USE_MATMUL:
      usage.matmuls[{{r[0], r[1], r[2]}}] = n;
      return long(n) >= 0;
    case USE_PREP:
      usage.extended[DATA_INT][r] = n;
      return long(n) >= 0;
    case GUSE_PREP:
      usage.extended[gf2n::field_type()][r] = n;
      return long(n) >= 0;
    default:
      return true;
  }
}

inline
int BaseInstruction::get_reg_type() const
{
  switch (opcode & 0x2B0)
  {
    case SECRET_WRITE:
      return SBIT;
    case CLEAR_WRITE:
      return CBIT;
  }

  switch (opcode) {
    case LDMINT:
    case STMINT:
    case LDMINTI:
    case STMINTI:
    case PUSHINT:
    case POPINT:
    case MOVINT:
    case READSOCKETINT:
    case WRITESOCKETINT:
    case INITCLIENTCONNECTION:
    case INITSECURESOCKET:
    case RESPSECURESOCKET:
    case LDARG:
    case LDINT:
    case INCINT:
    case SHUFFLE:
    case CONVMODP:
    case GCONVGF2N:
    case RAND:
    case NPLAYERS:
    case THRESHOLD:
    case PLAYERID:
    case CONVCBIT:
    case CONVCBITVEC:
    case INTOUTPUT:
    case ACCEPTCLIENTCONNECTION:
    case GENSECSHUFFLE:
    case CMDLINEARG:
    case CALL_TAPE:
      return INT;
    case PREP:
    case GPREP:
    case USE_PREP:
    case GUSE_PREP:
    case USE_EDABIT:
    case USE_MATMUL:
    case RUN_TAPE:
      // those use r[] not for registers
      return NONE;
    case LDI:
    case LDMC:
    case STMC:
    case LDMCI:
    case STMCI:
    case MOVC:
    case ADDC:
    case ADDCI:
    case SUBC:
    case SUBCI:
    case SUBCFI:
    case MULC:
    case MULCI:
    case DIVC:
    case DIVCI:
    case MODC:
    case MODCI:
    case LEGENDREC:
    case DIGESTC:
    case INV2M:
    case FLOORDIVC:
    case OPEN:
    case ANDC:
    case XORC:
    case ORC:
    case ANDCI:
    case XORCI:
    case ORCI:
    case NOTC:
    case SHLC:
    case SHRC:
    case SHLCI:
    case SHRCI:
    case CONVINT:
    case PUBINPUT:
    case FLOATOUTPUT:
    case READSOCKETC:
    case PRIVATEOUTPUT:
    case FIXINPUT:
      return CINT;
    case CALL_ARG:
      return n;
    default:
      if (is_gf2n_instruction())
        {
          Instruction tmp;
          tmp.opcode = opcode - 0x100;
          if (tmp.get_reg_type() == CINT)
            return CGF2N;
          else
            return SGF2N;
        }
      else if (opcode >> 4 == 0x9)
        return INT;
      else
        return SINT;
  }
}

inline
unsigned BaseInstruction::get_max_reg(int reg_type) const
{
  int skip = 0;
  int offset = 0;
  int size_offset = 0;
  int size = this->size;
  bool n_prefix = 0;

  // special treatment for instructions writing to different types
  switch (opcode)
  {
  case DABIT:
      if (reg_type == SBIT)
          return r[1] + size;
      else if (reg_type == SINT)
          return r[0] + size;
      else
          return 0;
  case EDABIT:
  case SEDABIT:
      if (reg_type == SBIT)
          skip = 1;
      else if (reg_type == SINT)
          return r[0] + size;
      else
          return 0;
      break;
  case INPUTMASKREG:
      if (reg_type == SINT)
          return r[0] + size;
      else if (reg_type == CINT)
          return r[1] + size;
      else
          return 0;
  case TRANS:
      if (reg_type == SBIT)
      {
          int n_outputs = n;
          auto& args = start;
          int n_inputs = args.size() - n_outputs;
          long long res = 0;
          for (int i = 0; i < n_outputs; i++)
              res = max(res, args[i] + DIV_CEIL(n_inputs, 64));
          for (int j = 0; j < n_inputs; j++)
              res = max(res, args[n_outputs] + DIV_CEIL(n_outputs, 64));
          return res;
      }
      else
          return 0;
  case CALL_TAPE:
  {
      int res = 0;
      for (auto it = start.begin(); it < start.end(); it += 5)
          if (it[1] == reg_type)
              res = max(res, (*it ? it[3] : it[4]) + it[2]);
      return res;
  }
  default:
      if (get_reg_type() != reg_type)
          return 0;
  }

  switch (opcode)
  {
  case CISC:
  {
      int res = 0;
      for (auto it = start.begin(); it < start.end(); it += *it)
      {
          bytecode_assert(it + *it <= start.end());
          res = max(res, it[1] + it[2]);
      }
      return res;
  }
  case MULS:
  case MULRS:
      skip = 4;
      offset = 1;
      size_offset = -1;
      break;
  case DOTPRODS:
  {
      int res = 0;
      auto it = start.begin();
      while (it != start.end())
      {
          bytecode_assert(it < start.end());
          int n = *it;
          res = max(res, *++it + size);
          it += n - 1;
      }
      return res;
  }
  case MATMULS:
  case GMATMULS:
  {
      int res = 0;
      for (auto it = start.begin(); it < start.end(); it += 6)
      {
          int tmp = *it + *(it + 3) * *(it + 5);
          res = max(res, tmp);
      }
      return res;
  }
  case MATMULSM:
  case GMATMULSM:
  {
      int res = 0;
      for (auto it = start.begin(); it < start.end(); it += 12)
      {
          res = max(res, *it + *(it + 3) * *(it + 5));
      }
      return res;
  }
  case CONV2DS:
  {
      unsigned res = 0;
      for (size_t i = 0; i < start.size(); i += 15)
      {
          unsigned tmp = start[i]
                               + start[i + 3] * start[i + 4] * start.at(i + 14);
          res = max(res, tmp);
      }
      return res;
  }
  case OPEN:
      skip = 2;
      break;
  case LDMSD:
  case LDMSDI:
      skip = 3;
      break;
  case STMSD:
  case STMSDI:
      skip = 2;
      break;
  case ANDRS:
  case XORS:
  case ANDS:
      skip = 4;
      offset = 1;
      size_offset = -1;
      break;
  case ANDRSVEC:
      n_prefix = 2;
      break;
  case INPUTB:
      skip = 4;
      offset = 3;
      size_offset = -2;
      break;
  case INPUTBVEC:
      n_prefix = 3;
      break;
  case ANDM:
  case NOTS:
  case NOTCB:
      size = DIV_CEIL(n, 64);
      break;
  case CONVCBIT2S:
      size = DIV_CEIL(n, 64);
      break;
  case CONVCINTVEC:
      size = DIV_CEIL(size, 64);
      break;
  case CONVCBITVEC:
      size = n;
      break;
  case REVEAL:
      size = DIV_CEIL(n, 64);
      skip = 3;
      offset = 1;
      size_offset = -1;
      break;
  case SPLIT:
      size = DIV_CEIL(this->size, 64);
      skip = 1;
      break;
  case INPUTPERSONAL:
  case PRIVATEOUTPUT:
      size_offset = -2;
      offset = 2;
      skip = 4;
      break;
  case SENDPERSONAL:
      size_offset = -2;
      offset = 2;
      skip = 5;
      break;
  case READSOCKETS:
  case READSOCKETC:
  case READSOCKETINT:
  case WRITESOCKETSHARE:
  case WRITESOCKETC:
  case WRITESOCKETINT:
      size = n;
      break;
  }

  if (n_prefix > 0)
  {
      int res = 0;
      auto it = start.begin();
      while (it < start.end())
      {
          int n = *it - n_prefix;
          size = max((long long) size, DIV_CEIL(*(it + 1), 64));
          it += n_prefix;
          bytecode_assert(it + n <= start.end());
          for (int i = 0; i < n; i++)
              res = max(res, *it++ + size);
      }
      return res;
  }

  if (skip > 0)
  {
      unsigned m = 0;
      for (size_t i = offset; i < start.size(); i += skip)
      {
          if (size_offset != 0)
          {
              if (opcode & 0x200)
                  size = DIV_CEIL(start[i + size_offset], 64);
              else
                  size = start[i + size_offset];
          }
          m = max(m, (unsigned)start[i] + size);
      }
      return m;
  }

  unsigned res = 0;
  for (auto x : start)
    res = max(res, (unsigned)x);
  for (auto x : r)
	res = max(res, (unsigned)x);
  return res + size;
}

inline
size_t BaseInstruction::get_mem(RegType reg_type) const
{
  if (get_reg_type() == reg_type and is_direct_memory_access())
    return n + size;
  else
    return 0;
}

inline
bool BaseInstruction::is_direct_memory_access() const
{
  switch (opcode)
  {
  case LDMS:
  case STMS:
  case GLDMS:
  case GSTMS:
  case LDMC:
  case STMC:
  case GLDMC:
  case GSTMC:
  case LDMINT:
  case STMINT:
  case LDMSB:
  case STMSB:
  case LDMCB:
  case STMCB:
    return true;
  default:
    return false;
  }
}


template<class sint, class sgf2n>
inline void Instruction::execute(Processor<sint, sgf2n>& Proc) const
{
  auto& Procp = Proc.Procp;
  auto& Proc2 = Proc.Proc2;

  // optimize some instructions
  switch (opcode)
  {
    case CONVMODP:
      vector<Integer> values;
      values.reserve(size);
      for (int i = 0; i < size; i++)
      {
          auto source = Proc.read_Cp(r[1] + i);
          Integer tmp;
          if (n == 0)
              tmp = Integer::convert_unsigned(source);
          else if (n <= 64)
              tmp = Integer(source, n);
          else
            throw Processor_Error(to_string(n) + "-bit conversion impossible; "
                "integer registers only have 64 bits");
          values.push_back(tmp);
      }
      if (r[2])
          Procp.protocol.sync(values, Proc.P);
      for (int i = 0; i < size; i++)
          Proc.write_Ci(r[0] + i, values[i].get());
      return;
  }

  int r[3] = {this->r[0], this->r[1], this->r[2]};
  int64_t n = this->n;
  for (int i = 0; i < size; i++) 
  { switch (opcode)
    {
      case LDMC:
        Proc.write_Cp(r[0],Proc.machine.Mp.read_C(n));
        n++;
        break;
      case STMC:
        Proc.machine.Mp.write_C(n,Proc.read_Cp(r[0]));
        n++;
        break;
      case MOVC:
        Proc.write_Cp(r[0],Proc.read_Cp(r[1]));
        break;
      case CONCATS:
        {
          auto& S = Proc.Procp.get_S();
          auto dest = S.begin() + r[0];
          for (auto j = start.begin(); j < start.end(); j += 2)
            {
              auto source = S.begin() + *(j + 1);
              bytecode_assert(dest + *j <= S.end());
              bytecode_assert(source + *j <= S.end());
              for (int k = 0; k < *j; k++)
                *dest++ = *source++;
            }
          return;
        }
      case ZIPS:
        {
          auto& S = Proc.Procp.get_S();
          auto dest = S.begin() + r[0];
          for (int i = 0; i < get_size(); i++)
            {
              *dest++ = S[r[1] + i];
              *dest++ = S[r[2] + i];
            }
          return;
        }
      case DIVC:
        Proc.write_Cp(r[0], Proc.read_Cp(r[1]) / sanitize(Proc.Procp, r[2]));
        break;
      case GDIVC:
        Proc.write_C2(r[0], Proc.read_C2(r[1]) / sanitize(Proc.Proc2, r[2]));
        break;
      case FLOORDIVC:
        Proc.temp.aa.from_signed(Proc.read_Cp(r[1]));
        Proc.temp.aa2.from_signed(sanitize(Proc.Procp, r[2]));
        Proc.write_Cp(r[0], bigint(Proc.temp.aa / Proc.temp.aa2));
        break;
      case MODC:
        to_bigint(Proc.temp.aa, Proc.read_Cp(r[1]));
        to_bigint(Proc.temp.aa2, sanitize(Proc.Procp, r[2]));
        mpz_fdiv_r(Proc.temp.aa.get_mpz_t(), Proc.temp.aa.get_mpz_t(), Proc.temp.aa2.get_mpz_t());
        Proc.temp.ansp.convert_destroy(Proc.temp.aa);
        Proc.write_Cp(r[0],Proc.temp.ansp);
        break;
      case LEGENDREC:
        to_bigint(Proc.temp.aa, Proc.read_Cp(r[1]));
        Proc.temp.aa = mpz_legendre(Proc.temp.aa.get_mpz_t(), sint::clear::pr().get_mpz_t());
        to_gfp(Proc.temp.ansp, Proc.temp.aa);
        Proc.write_Cp(r[0], Proc.temp.ansp);
        break;
      case DIGESTC:
      {
        octetStream o;
        to_bigint(Proc.temp.aa, Proc.read_Cp(r[1]));

        to_gfp(Proc.temp.ansp, Proc.temp.aa);
        Proc.temp.ansp.pack(o);
        // keep first n bytes
        to_gfp(Proc.temp.ansp, o.check_sum(n));
        Proc.write_Cp(r[0], Proc.temp.ansp);
      }
        break;
      case DIVCI:
        if (n == 0)
          throw Processor_Error("Division by immediate zero");
        Proc.write_Cp(r[0], Proc.read_Cp(r[1]) / n);
        break;
      case GDIVCI:
        if (n == 0)
          throw Processor_Error("Division by immediate zero");
        Proc.write_C2(r[0], Proc.read_C2(r[1]) / n);
        break;
      case INV2M:
        Proc.write_Cp(r[0], Proc.get_inverse2(n));
        break;
      case MODCI:
        if (n == 0)
          throw Processor_Error("Modulo by immediate zero");
        to_bigint(Proc.temp.aa, Proc.read_Cp(r[1]));
        to_gfp(Proc.temp.ansp, Proc.temp.aa2 = mpz_fdiv_ui(Proc.temp.aa.get_mpz_t(), n));
        Proc.write_Cp(r[0],Proc.temp.ansp);
        break;
      case SQUARE:
        Procp.DataF.get_two(DATA_SQUARE, Proc.get_Sp_ref(r[0]),Proc.get_Sp_ref(r[1]));
        break;
      case GSQUARE:
        Proc2.DataF.get_two(DATA_SQUARE, Proc.get_S2_ref(r[0]),Proc.get_S2_ref(r[1]));
        break;
      case INV:
        Procp.DataF.get_two(DATA_INVERSE, Proc.get_Sp_ref(r[0]),Proc.get_Sp_ref(r[1]));
        break;
      case GINV:
        Proc2.DataF.get_two(DATA_INVERSE, Proc.get_S2_ref(r[0]),Proc.get_S2_ref(r[1]));
        break;
      case RANDOMS:
        Procp.protocol.randoms_inst(Procp.get_S(), *this);
        return;
      case INPUTMASKREG:
        Procp.DataF.get_input(Proc.get_Sp_ref(r[0]), Proc.temp.rrp, Proc.read_Ci(r[2]));
        Proc.write_Cp(r[1], Proc.temp.rrp);
        break;
      case INPUTMASK:
        Procp.DataF.get_input(Proc.get_Sp_ref(r[0]), Proc.temp.rrp, n);
        Proc.write_Cp(r[1], Proc.temp.rrp);
        break;
      case GINPUTMASK:
        Proc2.DataF.get_input(Proc.get_S2_ref(r[0]), Proc.temp.ans2, n);
        Proc.write_C2(r[1], Proc.temp.ans2);
        break;
      case INPUT:
        sint::Input::template input<IntInput<typename sint::clear>>(Proc.Procp, start, size);
        return;
      case GINPUT:
        sgf2n::Input::template input<IntInput<typename sgf2n::clear>>(Proc.Proc2, start, size);
        return;
      case INPUTFIX:
        sint::Input::template input<FixInput>(Proc.Procp, start, size);
        return;
      case INPUTFLOAT:
        sint::Input::template input<FloatInput>(Proc.Procp, start, size);
        return;
      case INPUTMIXED:
        sint::Input::input_mixed(Proc.Procp, start, size, false);
        return;
      case INPUTMIXEDREG:
        sint::Input::input_mixed(Proc.Procp, start, size, true);
        return;
      case RAWINPUT:
        Proc.Procp.input.raw_input(Proc.Procp, start, size);
        return;
      case GRAWINPUT:
        Proc.Proc2.input.raw_input(Proc.Proc2, start, size);
        return;
      case INPUTPERSONAL:
        Proc.Procp.input_personal(start);
        return;
      case SENDPERSONAL:
        Proc.Procp.send_personal(start);
        return;
      case PRIVATEOUTPUT:
        Proc.Procp.check();
        Proc.Procp.private_output(start);
        return;
      // Note: Fp version has different semantics for NOTC than GNOTC
      case NOTC:
        to_bigint(Proc.temp.aa, Proc.read_Cp(r[1]));
        mpz_com(Proc.temp.aa.get_mpz_t(), Proc.temp.aa.get_mpz_t());
        Proc.temp.aa2 = 1;
        Proc.temp.aa2 <<= n;
        Proc.temp.aa += Proc.temp.aa2;
        Proc.temp.ansp.convert_destroy(Proc.temp.aa);
        Proc.write_Cp(r[0],Proc.temp.ansp);
        break;
      case SHRSI:
        sint::shrsi(Procp, *this);
        return;
      case GSHRSI:
        sgf2n::shrsi(Proc2, *this);
        return;
      case OPEN:
        Proc.Procp.POpen(*this);
        return;
      case GOPEN:
        Proc.Proc2.POpen(*this);
        return;
      case MULS:
        Proc.Procp.muls(start);
        return;
      case GMULS:
        Proc.Proc2.muls(start);
        return;
      case MULRS:
        Proc.Procp.mulrs(start);
        return;
      case GMULRS:
        Proc.Proc2.protocol.mulrs(start, Proc.Proc2);
        return;
      case DOTPRODS:
        Proc.Procp.dotprods(start, size);
        return;
      case GDOTPRODS:
        Proc.Proc2.dotprods(start, size);
        return;
      case MATMULS:
        Proc.Procp.matmuls(Proc.Procp.get_S(), *this);
        return;
      case GMATMULS:
        Proc.Proc2.matmuls(Proc.Proc2.get_S(), *this);
        return;
      case MATMULSM:
        Proc.Procp.protocol.matmulsm(Proc.Procp, Proc.machine.Mp.MS, *this);
        return;
      case GMATMULSM:
        Proc.Proc2.protocol.matmulsm(Proc.Proc2, Proc.machine.M2.MS, *this);
        return;
      case CONV2DS:
        Proc.Procp.protocol.conv2ds(Proc.Procp, *this);
        return;
      case TRUNC_PR:
        Proc.Procp.protocol.trunc_pr(start, size, Proc.Procp,
            sint::clear::characteristic_two);
        return;
      case SECSHUFFLE:
        Proc.Procp.secure_shuffle(*this);
        return;
      case GSECSHUFFLE:
        Proc.Proc2.secure_shuffle(*this);
        return;
      case GENSECSHUFFLE:
        Proc.write_Ci(r[0], Proc.Procp.generate_secure_shuffle(*this,
            Proc.machine.shuffle_store));
        return;
      case APPLYSHUFFLE:
        Proc.Procp.apply_shuffle(*this, Proc.machine.shuffle_store);
        return;
      case DELSHUFFLE:
        Proc.machine.shuffle_store.del(Proc.read_Ci(r[0]));
        return;
      case INVPERM:
        Proc.Procp.inverse_permutation(*this);
        return;
      case CHECK:
        {
          CheckJob job;
          if (BaseMachine::thread_num == 0)
            BaseMachine::s().queues.distribute(job, 0);
          Proc.check();
          if (BaseMachine::thread_num == 0)
            BaseMachine::s().queues.wrap_up(job);
          return;
        }
      case JMP:
        Proc.PC += (signed int) n;
        break;
      case JMPI:
        Proc.PC += (signed int) Proc.read_Ci(r[0]);
        break;
      case JMPNZ:
        if (Proc.read_Ci(r[0]) != 0)
          { Proc.PC += (signed int) n; }
        break;
      case JMPEQZ:
        if (Proc.read_Ci(r[0]) == 0)
          { Proc.PC += (signed int) n; }
        break;
      case PRINTREG:
           {
             Proc.out << "Reg[" << r[0] << "] = " << Proc.read_Cp(r[0])
              << " # " << string((char*)&n, 4) << endl;
           }
        break;
      case PRINTREGPLAIN:
        print(Proc.out, &Proc.read_Cp(r[0]));
        return;
      case PRINTREGPLAINS:
        Proc.out << Proc.read_Sp(r[0]);
        return;
      case GPRINTREGPLAINS:
        Proc.out << Proc.read_S2(r[0]);
        return;
      case CONDPRINTPLAIN:
        if (not Proc.read_Cp(r[0]).is_zero())
          {
            print(Proc.out, &Proc.read_Cp(r[1]), &Proc.read_Cp(r[2]));
          }
        return;
      case PRINTFLOATPLAIN:
        print(Proc.out, &Proc.read_Cp(start[0]), &Proc.read_Cp(start[1]),
            &Proc.read_Cp(start[2]), &Proc.read_Cp(start[3]),
            &Proc.read_Cp(start[4]));
        return;
      case CONDPRINTSTR:
          if (not Proc.read_Cp(r[0]).is_zero())
            {
              string str = {(char*)&n, 4};
              size_t n = str.find('\0');
              if (n < 4)
                str.erase(n);
              Proc.out << str << flush;
            }
        break;
      case REQBL:
      case GREQBL:
      case ACTIVE:
      case USE:
      case USE_INP:
      case USE_EDABIT:
      case USE_MATMUL:
      case USE_PREP:
      case GUSE_PREP:
        break;
      case TIME:
        Proc.machine.time();
	break;
      case START:
        Proc.machine.set_thread_comm(Proc.P.total_comm());
        Proc.machine.start(n);
        break;
      case STOP:
        Proc.machine.set_thread_comm(Proc.P.total_comm());
        Proc.machine.stop(n);
        break;
      case RUN_TAPE:
        Proc.machine.run_tapes(start, Proc.DataF);
        break;
      case JOIN_TAPE:
        Proc.machine.join_tape(r[0]);
        break;
      case CALL_TAPE:
        Proc.call_tape(r[0], Proc.read_Ci(r[1]), start);
        break;
      case CRASH:
        if (Proc.read_Ci(r[0]))
          throw crash_requested();
        break;
      case STARTGRIND:
        CALLGRIND_START_INSTRUMENTATION;
        break;
      case STOPGRIND:
        CALLGRIND_STOP_INSTRUMENTATION;
        break;
      case NPLAYERS:
        Proc.write_Ci(r[0], Proc.P.num_players());
        break;
      case THRESHOLD:
        Proc.write_Ci(r[0], sint::threshold(Proc.P.num_players()));
        break;
      case PLAYERID:
        Proc.write_Ci(r[0], Proc.P.my_num());
        break;
      case CMDLINEARG:
        {
          size_t idx = Proc.read_Ci(r[1]);
          auto& args = OnlineOptions::singleton.args;
          if (idx < args.size())
              Proc.write_Ci(r[0], args[idx]);
          else
            {
              cerr << idx << "-th command-line argument not given" << endl;
              exit(1);
            }
          break;
        }
      // ***
      // TODO: read/write shared GF(2^n) data instructions
      // ***
      case LISTEN:
        // listen for connections at port number n
        Proc.external_clients.start_listening(Proc.read_Ci(r[0]));
        break;
      case ACCEPTCLIENTCONNECTION:
      {
        TimeScope _(Proc.client_timer);
        // get client connection at port number n + my_num())
        int client_handle = Proc.external_clients.get_client_connection(
            Proc.read_Ci(r[1]));
        {
          octetStream os;
          os.store(int(sint::open_type::type_char()));
          sint::specification(os);
          sint::clear::specification(os);
          os.Send(Proc.external_clients.get_socket(client_handle));
        }
        Proc.write_Ci(r[0], client_handle);
        break;
      }
      case INITCLIENTCONNECTION:
        Proc.write_Ci(r[0],
            Proc.external_clients.init_client_connection(str,
                Proc.read_Ci(r[1]), Proc.read_Ci(r[2])));
        break;
      case CLOSECLIENTCONNECTION:
        Proc.external_clients.close_connection(Proc.read_Ci(r[0]));
        break;
      case READSOCKETINT:
        Proc.read_socket_ints(Proc.read_Ci(r[0]), start, n);
        break;
      case READSOCKETC:
        Proc.read_socket_vector(Proc.read_Ci(r[0]), start, n);
        break;
      case READSOCKETS:
        // read shares and MAC shares
        Proc.read_socket_private(Proc.read_Ci(r[0]), start, n, true);
        break;
      case WRITESOCKETINT:
        Proc.write_socket(INT, false, Proc.read_Ci(r[0]), r[1], start, n);
        break;
      case WRITESOCKETC:
        Proc.write_socket(CINT, false, Proc.read_Ci(r[0]), r[1], start, n);
        break;
      case WRITESOCKETS:
        // Send shares + MACs
        Proc.write_socket(SINT, true, Proc.read_Ci(r[0]), r[1], start, n);
        break;
      case WRITESOCKETSHARE:
        // Send only shares, no MACs
        // N.B. doesn't make sense to have a corresponding read instruction for this
        Proc.write_socket(SINT, false, Proc.read_Ci(r[0]), r[1], start, n);
        break;
      case WRITEFILESHARE:
        // Write shares to file system
        Procp.write_shares_to_file(Proc.read_Ci(r[0]), start, size);
        return;
      case READFILESHARE:
        // Read shares from file system
        Procp.read_shares_from_file(Proc.read_Ci(r[0]), r[1], start, size,
            Proc);
        return;
      case GWRITEFILESHARE:
        // Write shares to file system
        Proc2.write_shares_to_file(Proc.read_Ci(r[0]), start, size);
        return;
      case GREADFILESHARE:
        // Read shares from file system
        Proc2.read_shares_from_file(Proc.read_Ci(r[0]), r[1], start, size,
            Proc);
        return;
      case PUBINPUT:
        Proc.get_Cp_ref(r[0]) = Proc.template
            get_input<IntInput<typename sint::clear>>(
            Proc.public_input, Proc.public_input_filename, 0).items[0];
        break;
      case RAWOUTPUT:
        Proc.read_Cp(r[0]).output(Proc.get_public_output(), false);
        break;
      case INTOUTPUT:
        if (n == -1 or n == Proc.P.my_num())
          Integer(Proc.read_Ci(r[0])).output(Proc.get_binary_output(), false);
        break;
      case FLOATOUTPUT:
        if (n == -1 or n == Proc.P.my_num())
          {
            double tmp = bigint::get_float(Proc.read_Cp(start[0] + i),
              Proc.read_Cp(start[1] + i), Proc.read_Cp(start[2] + i),
              Proc.read_Cp(start[3] + i)).get_d();
            Proc.get_binary_output().write((char*) &tmp, sizeof(double));
            Proc.get_binary_output().flush();
          }
        break;
      case FIXINPUT:
        Proc.fixinput(*this);
        return;
      case PREP:
        Procp.DataF.get(Proc.Procp.get_S(), r, start, size);
        return;
      case GPREP:
        Proc2.DataF.get(Proc.Proc2.get_S(), r, start, size);
        return;
      case CISC:
        Procp.protocol.cisc(Procp, *this);
        return;
      default:
        throw invalid_opcode(opcode);
        break;
#define X(NAME, CODE) case NAME:
        COMBI_INSTRUCTIONS
#undef X
#define X(NAME, CODE) case NAME: throw no_dynamic_memory();
        DYNAMIC_INSTRUCTIONS
#undef X
#define X(NAME, PRE, CODE) case NAME:
        ARITHMETIC_INSTRUCTIONS
#undef X
#define X(NAME, PRE, CODE) case NAME:
        CLEAR_GF2N_INSTRUCTIONS
#undef X
#define X(NAME, PRE, CODE) case NAME:
        REGINT_INSTRUCTIONS
#undef X
        throw runtime_error("wrong case statement"); return;
    }
  if (size > 1)
    {
      r[0]++; r[1]++; r[2]++;
    }
  }
}

template<class sint, class sgf2n>
void Program::execute(Processor<sint, sgf2n>& Proc) const
{
  if (OnlineOptions::singleton.has_option("throw_exceptions"))
    execute_with_errors(Proc);
  else
    {
      try
      {
          execute_with_errors(Proc);
      }
      catch (exception& e)
      {
          cerr << "Fatal error at " << name << ":" << Proc.last_PC << " ("
              << p[Proc.last_PC].get_name() << "): " << e.what() << endl;
          exit(1);
      }
    }
}

template<class sint, class sgf2n>
void Program::execute_with_errors(Processor<sint, sgf2n>& Proc) const
{
  unsigned int size = p.size();
  Proc.PC=0;

  auto& Procp = Proc.Procp;
  auto& Proc2 = Proc.Proc2;

  // binary instructions
  typedef typename sint::bit_type T;
  auto& processor = Proc.Procb;
  auto& Ci = Proc.get_Ci();

  while (Proc.PC<size)
    {
      Proc.last_PC = Proc.PC;
      auto& instruction = p[Proc.PC];
      auto& r = instruction.r;
      auto& n = instruction.n;
      auto& start = instruction.start;
      auto& size = instruction.size;
      (void) start;

#ifdef COUNT_INSTRUCTIONS
#ifdef TIME_INSTRUCTIONS
      RunningTimer timer;
      int PC = Proc.PC;
#else
      Proc.stats[p[Proc.PC].get_opcode()]++;
#endif
#endif

#ifdef OUTPUT_INSTRUCTIONS
      if (OnlineOptions::singleton.has_option("output_instructions"))
          cerr << instruction << endl;
#endif

      Proc.PC++;

      switch(instruction.get_opcode())
        {
#define X(NAME, PRE, CODE) \
        case NAME: { PRE; for (int i = 0; i < size; i++) { CODE; } } break;
        ARITHMETIC_INSTRUCTIONS
#undef X
#define X(NAME, PRE, CODE) case NAME:
        CLEAR_GF2N_INSTRUCTIONS
        instruction.execute_clear_gf2n(Proc2.get_C(), Proc.machine.M2.MC, Proc); break;
#undef X
#define X(NAME, PRE, CODE) case NAME:
        REGINT_INSTRUCTIONS
        instruction.execute_regint(Proc, Proc.machine.Mi.MC); break;
#undef X
#define X(NAME, CODE) case NAME: CODE; break;
        COMBI_INSTRUCTIONS
#undef X
        default:
          instruction.execute(Proc);
        }

#if defined(COUNT_INSTRUCTIONS) and defined(TIME_INSTRUCTIONS)
      Proc.stats[p[PC].get_opcode()] += timer.elapsed() * 1e9;
#endif
    }
}

template<class T>
void Program::mulm_check() const
{
  if (T::function_dependent
      and not (BaseMachine::allow_mulm()
          or OnlineOptions::singleton.has_option("allow_mulm")))
    throw runtime_error("Mixed multiplication not implemented for function-dependent preprocessing. "
        "Use '-E <protocol>' during compilation or state "
            "'program.use_mulm = False' at the beginning of your high-level program.");
}

template<class T>
void Instruction::print(SwitchableOutput& out, T* v, T* p, T* s, T* z, T* nan) const
{
  if (size > 1)
    out << "[";
  for (int i = 0; i < size; i++)
    {
      if (p == 0 or (*p == 0 and s == 0))
        out.signed_output(v[i]);
      else if (s == 0)
        out << bigint::get_float(v[i], p[i], {}, {});
      else
        {
          assert(z != 0);
          assert(nan != 0);
          bigint::output_float(out, bigint::get_float(v[i], p[i], s[i], z[i]),
              nan[i]);
        }
      if (i < size - 1)
        out << ", ";
    }
  if (size > 1)
    out << "]";
}

template<class T>
typename T::clear Instruction::sanitize(SubProcessor<T>& proc, int reg) const
{
  if (not T::real_shares(proc.P))
    return 1;
  auto& res = proc.get_C_ref(reg);
  if (res.is_zero())
    throw Processor_Error("Division by zero from register");
  return res;
}

#endif
