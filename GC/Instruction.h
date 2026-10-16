/*
 * Instruction.h
 *
 */

#ifndef PROCESSOR_GC_INSTRUCTION_H_
#define PROCESSOR_GC_INSTRUCTION_H_

#include <vector>
#include <iostream>
using namespace std;

#include "Processor/Instruction.h"

namespace GC
{

template<class T> class Processor;

class Instruction : public ::BaseInstruction
{
public:
    Instruction();
    
    // Reads a single instruction from the istream
    void parse(istream& s, int pos);

    // Return whether usage is known
    bool get_offline_data_usage(int& usage);

    // Returns the memory size used if applicable and known
    unsigned get_mem(RegType reg_type) const;
};

} /* namespace GC */

enum
{
    // GC specific
    // write to secret
    SECRET_WRITE = 0x200,
    XORS = 0x200,
    XORM = 0x201,
    ANDRS = 0x202,
    BITDECS = 0x203,
    BITCOMS = 0x204,
    CONVSINT = 0x205,
    LDMSDI = 0x206,
    STMSDI = 0x207,
    LDMSD = 0x208,
    STMSD = 0x209,
    LDBITS = 0x20a,
    ANDS = 0x20b,
    TRANS = 0x20c,
    BITB = 0x20d,
    ANDM = 0x20e,
    NOTS = 0x20f,
    LDMSB = 0x240,
    STMSB = 0x241,
    LDMSBI = 0x242,
    STMSBI = 0x243,
    MOVSB = 0x244,
    INPUTB = 0x246,
    INPUTBVEC = 0x247,
    SPLIT = 0x248,
    CONVCBIT2S = 0x249,
    ANDRSVEC = 0x24a,
    APPLYSHUFFLEB = 0x24b,
    CONCATSB = 0x24c,
    TRANSVEC = 0x24e,
    PICKSB = 0x24f,
    ZIPSB = 0x280,
    // write to clear
    CLEAR_WRITE = 0x210,
    XORCBI = 0x210,
    BITDECC = 0x211,
    NOTCB = 0x212,
    CONVCINT = 0x213,
    REVEAL = 0x214,
    STMSDCI = 0x215,
    LDMCB = 0x217,
    STMCB = 0x218,
    XORCB = 0x219,
    ADDCB = 0x21a,
    ADDCBI = 0x21b,
    MULCBI = 0x21c,
    SHRCBI = 0x21d,
    SHLCBI = 0x21e,
    CONVCINTVEC = 0x21f,
    LDMCBI = 0x258,
    STMCBI = 0x259,
    // don't write
    PRINTREGSIGNED = 0x220,
    PRINTREGB = 0x221,
    PRINTREGPLAINB = 0x222,
    PRINTFLOATPLAINB = 0x223,
    CONDPRINTSTRB = 0x224,
    PRINTREGPLAINSB = 0x225,
    // write to regint
    CONVCBIT = 0x230,
    CONVCBITVEC = 0x231,
    GENSECSHUFFLEB = 0x232,
    DELSHUFFLEB = 0x233,
};

#endif /* PROCESSOR_GC_INSTRUCTION_H_ */
