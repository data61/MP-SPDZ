#ifndef _Instruction
#define _Instruction

/* Class to read and decode an instruction
 */

#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include "Math/bigint.h"

template<class sint, class sgf2n> class Machine;
template<class sint, class sgf2n> class Processor;
template<class T> class SubProcessor;
template<class T> class MemoryPart;
template<class T> class StackedVector;
class ArithmeticProcessor;
class SwitchableOutput;

/* 
 * Opcode constants
 *
 * Whenever these are changed the corresponding dict in Compiler/instructions_base.py
 * MUST also be changed. (+ the documentation)
 */
enum
{
    CISC = 0,
    // Load/store
    LDI = 0x1,
    LDSI = 0x2,
    LDMC = 0x3,
    LDMS = 0x4,
    STMC = 0x5,
    STMS = 0x6,
    LDMCI = 0x7,
    LDMSI = 0x8,
    STMCI = 0x9,
    STMSI = 0xA,
    MOVC = 0xB,
    MOVS = 0xC,
    PROTECTMEMS = 0xD,
    PROTECTMEMC = 0xE,
    PROTECTMEMINT = 0xF,
    LDMINT = 0xCA,
    STMINT = 0xCB,
    LDMINTI = 0xCC,
    STMINTI = 0xCD,
    PUSHINT = 0xCE,
    POPINT = 0xCF,
    MOVINT = 0xD0,
    // Machine
    LDTN = 0x10,
    LDARG = 0x11,
    REQBL = 0x12,
    STARG = 0x13,
    TIME = 0x14,
    START = 0x15,
    STOP = 0x16,
    USE = 0x17,
    USE_INP = 0x18,
    RUN_TAPE = 0x19,
    JOIN_TAPE = 0x1A,
    CRASH = 0x1B,
    USE_PREP = 0x1C,
    STARTGRIND = 0x1D,
    STOPGRIND = 0x1E,
    NPLAYERS = 0xE2,
    THRESHOLD = 0xE3,
    PLAYERID = 0xE4,
    USE_EDABIT = 0xE5,
    USE_MATMUL = 0x1F,
    ACTIVE = 0xE9,
    CMDLINEARG = 0xEB,
    CALL_TAPE = 0xEC,
    CALL_ARG = 0xED,
    // Addition
    ADDC = 0x20,
    ADDS = 0x21,
    ADDM = 0x22,
    ADDCI = 0x23,
    ADDSI = 0x24,
    SUBC = 0x25,
    SUBS = 0x26,
    SUBML = 0x27,
    SUBMR = 0x28,
    SUBCI = 0x29,
    SUBSI = 0x2A,
    SUBCFI = 0x2B,
    SUBSFI = 0x2C,
    PREFIXSUMS = 0x2D,
    PICKS = 0x2E,
    CONCATS = 0x2F,
    ZIPS = 0x3F,
    // Multiplication/division/other arithmetic
    MULC = 0x30,
    MULM = 0x31,
    MULCI = 0x32,
    MULSI = 0x33,
    DIVC = 0x34,
    DIVCI = 0x35,
    MODC = 0x36,
    MODCI = 0x37,
    LEGENDREC = 0x38,
    DIGESTC = 0x39,
    INV2M = 0x3a,
    FLOORDIVC = 0x3b,
    // Open
    OPEN = 0xA5,
    MULS = 0xA6,
    MULRS = 0xA7,
    DOTPRODS = 0xA8,
    TRUNC_PR = 0xA9,
    MATMULS = 0xAA,
    MATMULSM = 0xAB,
    CONV2DS = 0xAC,
    CHECK = 0xAF,
    PRIVATEOUTPUT = 0xAD,
    // Shuffling
    SECSHUFFLE = 0xFA,
    GENSECSHUFFLE = 0xFB,
    APPLYSHUFFLE = 0xFC,
    DELSHUFFLE = 0xFD,
    INVPERM = 0xFE,
    // Data access
    TRIPLE = 0x50,
    BIT = 0x51,
    SQUARE = 0x52,
    INV = 0x53,
    INPUTMASK = 0x56,
    INPUTMASKREG = 0x5C,
    PREP = 0x57,
    DABIT = 0x58,
    EDABIT = 0x59,
    SEDABIT = 0x5A,
    RANDOMS = 0x5B,
    RANDOMFULLS = 0x5D,
    UNSPLIT = 0x5E,
    // Input
    INPUT = 0x60,
    INPUTFIX = 0xF0,
    INPUTFLOAT = 0xF1,
    INPUTMIXED = 0xF2,
    INPUTMIXEDREG = 0xF3,
    RAWINPUT = 0xF4,
    INPUTPERSONAL = 0xF5,
    SENDPERSONAL = 0xF6,
    STARTINPUT = 0x61,
    STOPINPUT = 0x62,
    READSOCKETC = 0x63,
    READSOCKETS = 0x64,
    WRITESOCKETC = 0x65,
    WRITESOCKETS = 0x66,
    READSOCKETINT = 0x69,
    WRITESOCKETINT = 0x6a,
    WRITESOCKETSHARE = 0x6b,
    LISTEN = 0x6c,
    ACCEPTCLIENTCONNECTION = 0x6d,
    CLOSECLIENTCONNECTION = 0x6e,
    INITCLIENTCONNECTION = 0x6f,
    // Bitwise logic
    ANDC = 0x70,
    XORC = 0x71,
    ORC = 0x72,
    ANDCI = 0x73,
    XORCI = 0x74,
    ORCI = 0x75,
    NOTC = 0x76,
    // Bitwise shifts
    SHLC = 0x80,
    SHRC = 0x81,
    SHLCI = 0x82,
    SHRCI = 0x83,
    SHRSI = 0x84,
    // Branching and comparison
    JMP = 0x90,
    JMPNZ = 0x91,
    JMPEQZ = 0x92,
    EQZC = 0x93,
    LTZC = 0x94,
    LTC = 0x95,
    GTC = 0x96,
    EQC = 0x97,
    JMPI = 0x98,
    // Integers
    BITDECINT = 0x99,
    LDINT = 0x9A,
    ADDINT = 0x9B,
    SUBINT = 0x9C,
    MULINT = 0x9D,
    DIVINT = 0x9E,
    PRINTINT = 0x9F,
    INCINT = 0xD1,
    SHUFFLE = 0xD2,
    // Conversion
    CONVINT = 0xC0,
    CONVMODP = 0xC1,

    // IO
    PRINTMEM = 0xB0,
    PRINTREG = 0XB1,
    RAND = 0xB2,
    PRINTREGPLAIN = 0xB3,
    PRINTREGPLAINS = 0xEA,
    PRINTCHR = 0xB4,
    PRINTSTR = 0xB5,
    PUBINPUT = 0xB6,
    RAWOUTPUT = 0xB7,
    STARTPRIVATEOUTPUT = 0xB8,
    STOPPRIVATEOUTPUT = 0xB9,
    PRINTCHRINT = 0xBA,
    PRINTSTRINT = 0xBB,
    PRINTFLOATPLAIN = 0xBC,
    WRITEFILESHARE = 0xBD,
    READFILESHARE = 0xBE,
    WRITEFILECLEAR = 0xC3,
    READFILECLEAR = 0xC4,
    CONDPRINTSTR = 0xBF,
    PRINTFLOATPREC = 0xE0,
    CONDPRINTPLAIN = 0xE1,
    INTOUTPUT = 0xE6,
    FLOATOUTPUT = 0xE7,
    FIXINPUT = 0xE8,

    // GF(2^n) versions
    
    // Load/store
    GLDI = 0x101,
    GLDSI = 0x102,
    GLDMC = 0x103,
    GLDMS = 0x104,
    GSTMC = 0x105,
    GSTMS = 0x106,
    GLDMCI = 0x107,
    GLDMSI = 0x108,
    GSTMCI = 0x109,
    GSTMSI = 0x10A,
    GMOVC = 0x10B,
    GMOVS = 0x10C,
    GPROTECTMEMS = 0x10D,
    GPROTECTMEMC = 0x10E,
    // Machine
    GREQBL = 0x112,
    GUSE_PREP = 0x11C,
    // Addition
    GADDC = 0x120,
    GADDS = 0x121,
    GADDM = 0x122,
    GADDCI = 0x123,
    GADDSI = 0x124,
    GSUBC = 0x125,
    GSUBS = 0x126,
    GSUBML = 0x127,
    GSUBMR = 0x128,
    GSUBCI = 0x129,
    GSUBSI = 0x12A,
    GSUBCFI = 0x12B,
    GSUBSFI = 0x12C,
    // Multiplication/division
    GMULC = 0x130,
    GMULM = 0x131,
    GMULCI = 0x132,
    GMULSI = 0x133,
    GDIVC = 0x134,
    GDIVCI = 0x135,
    GMULBITC = 0x136,
    GMULBITM = 0x137,
    // Open
    GOPEN = 0x1A5,
    GMULS = 0x1A6,
    GMULRS = 0x1A7,
    GDOTPRODS = 0x1A8,
    GMATMULS = 0x1AA,
    GMATMULSM = 0x1AB,
    GSECSHUFFLE = 0x1FA,
    // Data access
    GTRIPLE = 0x150,
    GBIT = 0x151,
    GSQUARE = 0x152,
    GINV = 0x153,
    GBITTRIPLE = 0x154,
    GBITGF2NTRIPLE = 0x155,
    GINPUTMASK = 0x156,
    GPREP = 0x157,
    // Input
    GINPUT = 0x160,
    GSTARTINPUT = 0x161,
    GSTOPINPUT = 0x162,
    GREADSOCKETS = 0x164,
    GWRITESOCKETS = 0x166,
    GRAWINPUT = 0x1F4,
    // Bitwise logic
    GANDC = 0x170,
    GXORC = 0x171,
    GORC = 0x172,
    GANDCI = 0x173,
    GXORCI = 0x174,
    GORCI = 0x175,
    GNOTC = 0x176,
    // Bitwise shifts
    GSHLCI = 0x182,
    GSHRCI = 0x183,
    GSHRSI = 0x184,
    GBITDEC = 0x18A,
    GBITCOM = 0x18B,
    // Conversion
    GCONVINT = 0x1C0,
    GCONVGF2N = 0x1C1,
    // IO
    GPRINTMEM = 0x1B0,
    GPRINTREG = 0X1B1,
    GPRINTREGPLAIN = 0x1B3,
    GPRINTREGPLAINS = 0x1EA,
    GRAWOUTPUT = 0x1B7,
    GSTARTPRIVATEOUTPUT = 0x1B8,
    GSTOPPRIVATEOUTPUT = 0x1B9,
    GWRITEFILESHARE = 0x1BD,
    GREADFILESHARE = 0x1BE,
    // Commsec ops
    INITSECURESOCKET = 0x1BA,
    RESPSECURESOCKET = 0x1BB
};


// Register types
enum RegType {
  INT,
  SBIT,
  CBIT,
  DYN_SBIT,
  SINT,
  CINT,
  SGF2N,
  CGF2N,
  NONE,
  MAX_REG_TYPE,
};

template<class sint, class sgf2n>
struct TempVars {
  typename sgf2n::clear ans2;
  typename sint::clear ansp;
  sint Sansp;
  bigint aa,aa2;
  typename sint::open_type rrp, xip;
};

typedef vector<unsigned> ArgVector;

class BaseInstruction
{
  friend class Program;
  template<class T> friend class RepRingOnlyEdabitPrep;

protected:
  int opcode;         // The code
  int size;           // Vector size
  unsigned r[4];      // Fixed parameter registers
  size_t n;             // Possible immediate value
  ArgVector start;    // Values for extended instructions
  string str;

  void bytecode_assert(bool condition) const;

public:
  BaseInstruction() : opcode(0), size(0), n(0) {}
  virtual ~BaseInstruction() {};

  unsigned get_r(int i) const { return r[i]; }
  size_t get_n() const { return n; }
  const vector<unsigned>& get_start() const { return start; }
  int get_opcode() const { return opcode; }
  int get_size() const { return size; }

  // Reads a single instruction from the istream
  void parse(istream& s, int inst_pos);
  void parse_operands(istream& s, int pos, int file_pos);

  bool is_gf2n_instruction() const { return ((opcode&0x100)!=0); }
  virtual int get_reg_type() const;

  bool is_direct_memory_access() const;

  // Returns the memory size used if applicable and known
  size_t get_mem(RegType reg_type) const;

  // Returns the maximal register used
  unsigned get_max_reg(int reg_type) const;

  string get_name() const;
};

class DataPositions;

class Instruction : public BaseInstruction
{
public:
  // Return whether usage is known
  bool get_offline_data_usage(DataPositions& usage);

  friend ostream& operator<<(ostream& s,const Instruction& instr);

  // Execute this instruction, updateing the processor and memory
  // and streams pointing to the triples etc
  template<class sint, class sgf2n>
  void execute(Processor<sint, sgf2n>& Proc) const;

  template<class cgf2n>
  void execute_clear_gf2n(StackedVector<cgf2n>& registers, MemoryPart<cgf2n>& memory,
      ArithmeticProcessor& Proc) const;

  template<class cgf2n>
  void gbitdec(StackedVector<cgf2n>& registers) const;
  template<class cgf2n>
  void gbitcom(StackedVector<cgf2n>& registers) const;

  void execute_regint(ArithmeticProcessor& Proc, MemoryPart<Integer>& Mi) const;
  void incint(StackedVector<Integer>& Ci) const;

  void shuffle(ArithmeticProcessor& Proc) const;
  void bitdecint(ArithmeticProcessor& Proc) const;

  template<class T>
  void print(SwitchableOutput& out, T* v, T* p = 0, T* s = 0, T* z = 0,
      T* nan = 0) const;

  template<class T>
  typename T::clear sanitize(SubProcessor<T>& proc, int reg) const;
};

#endif

