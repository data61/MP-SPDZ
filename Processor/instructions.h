/*
 * instructions.h
 *
 */

#ifndef PROCESSOR_INSTRUCTIONS_H_
#define PROCESSOR_INSTRUCTIONS_H_

#include "Instruction.h"

#define ARITHMETIC_INSTRUCTIONS \
    X(LDI, auto dest = &Procp.get_C()[r[0]]; typename sint::clear tmp = int(n), \
            *dest++ = tmp) \
    X(LDSI, auto dest = &Procp.get_S()[r[0]]; \
            auto tmp = sint::constant(int(n), Proc.P.my_num(), Procp.MC.get_alphai()), \
            *dest++ = tmp) \
    X(LDMS, auto dest = &Procp.get_S()[r[0]]; auto source = &Proc.machine.Mp.MS[n], \
            *dest++ = *source++) \
    X(STMS, auto source = &Procp.get_S()[r[0]]; auto dest = &Proc.machine.Mp.MS[n], \
            *dest++ = *source++) \
    X(LDMSI, Proc.machine.Mp.MS.indirect_read(instruction, Procp.get_S(), Proc.get_Ci()),) \
    X(STMSI, Proc.machine.Mp.MS.indirect_write(instruction, Procp.get_S(), Proc.get_Ci()),) \
    X(LDMCI, Proc.machine.Mp.MC.indirect_read(instruction, Procp.get_C(), Proc.get_Ci()),) \
    X(STMCI, Proc.machine.Mp.MC.indirect_write(instruction, Procp.get_C(), Proc.get_Ci()),) \
    X(MOVS, auto dest = &Procp.get_S()[r[0]]; auto source = &Procp.get_S()[r[1]], \
            *dest++ = *source++) \
    X(ADDS, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = &Procp.get_S()[r[2]], \
            *dest++ = *op1++ + *op2++) \
    X(ADDM, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ + sint::constant(*op2++, Proc.P.my_num(), Procp.MC.get_alphai())) \
    X(ADDSI, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]], \
            *dest++ = *op1++ + sint::constant(int(n), Proc.P.my_num(), Procp.MC.get_alphai())) \
    X(ADDC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ + *op2++) \
    X(ADDCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ + op2) \
    X(SUBS, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = &Procp.get_S()[r[2]], \
            *dest++ = *op1++ - *op2++) \
    X(SUBSI, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = sint::constant(int(n), Proc.P.my_num(), Procp.MC.get_alphai()), \
            *dest++ = *op1++ - op2) \
    X(SUBSFI, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = sint::constant(int(n), Proc.P.my_num(), Procp.MC.get_alphai()), \
            *dest++ = op2 - *op1++) \
    X(SUBML, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ - sint::constant(*op2++, Proc.P.my_num(), Procp.MC.get_alphai())) \
    X(SUBMR, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_S()[r[2]], \
            *dest++ = sint::constant(*op1++, Proc.P.my_num(), Procp.MC.get_alphai()) - *op2++) \
    X(SUBC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ - *op2++) \
    X(SUBCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ - op2) \
    X(SUBCFI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = op2 - *op1++) \
    X(PREFIXSUMS, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            sint s, \
            s += *op1++; *dest++ = s) \
    X(PICKS, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1] + r[2]], \
            *dest++ = *op1; op1 += int(n)) \
    X(MULM, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]]; mulm_check<sint>(), \
            *dest++ = *op1++ * *op2++) \
    X(MULC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ * *op2++) \
    X(MULCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ * op2) \
    X(MULSI, auto dest = &Procp.get_S()[r[0]]; auto op1 = &Procp.get_S()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ * op2) \
    X(ANDC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ & *op2++) \
    X(XORC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ ^ *op2++) \
    X(ORC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ | *op2++) \
    X(ANDCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ & op2) \
    X(XORCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ ^ op2) \
    X(ORCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            typename sint::clear op2 = int(n), \
            *dest++ = *op1++ | op2) \
    X(SHLC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ << *op2++) \
    X(SHRC, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]]; \
            auto op2 = &Procp.get_C()[r[2]], \
            *dest++ = *op1++ >> *op2++) \
    X(SHLCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]], \
            *dest++ = *op1++ << n) \
    X(SHRCI, auto dest = &Procp.get_C()[r[0]]; auto op1 = &Procp.get_C()[r[1]], \
            *dest++ = *op1++ >> n) \
    X(TRIPLE, auto a = &Procp.get_S()[r[0]]; auto b = &Procp.get_S()[r[1]]; \
            auto c = &Procp.get_S()[r[2]], \
            Procp.DataF.get_three(DATA_TRIPLE, *a++, *b++, *c++)) \
    X(BIT, auto dest = &Procp.get_S()[r[0]], \
            Procp.DataF.get_one(DATA_BIT, *dest++)) \
    X(RANDOMFULLS, auto dest = &Procp.get_S()[r[0]], \
            *dest++ = Procp.DataF.get_random()) \
    X(GLDSI, auto dest = &Proc2.get_S()[r[0]]; \
            auto tmp = sgf2n::constant(int(n), Proc.P.my_num(), Proc2.MC.get_alphai()), \
            *dest++ = tmp) \
    X(GLDMS, auto dest = &Proc2.get_S()[r[0]]; auto source = &Proc.machine.M2.MS[n], \
            *dest++ = *source++) \
    X(GSTMS, auto source = &Proc2.get_S()[r[0]]; auto dest = &Proc.machine.M2.MS[n], \
            *dest++ = *source++) \
    X(GLDMSI, Proc.machine.M2.MS.indirect_read(instruction, Proc2.get_S(), Proc.get_Ci()),) \
    X(GSTMSI, Proc.machine.M2.MS.indirect_write(instruction, Proc2.get_S(), Proc.get_Ci()),) \
    X(GMOVS, auto dest = &Proc2.get_S()[r[0]]; auto source = &Proc2.get_S()[r[1]], \
            *dest++ = *source++) \
    X(GADDS, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = &Proc2.get_S()[r[2]], \
            *dest++ = *op1++ + *op2++) \
    X(GADDM, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = &Proc2.get_C()[r[2]], \
            *dest++ = *op1++ + sgf2n::constant(*op2++, Proc.P.my_num(), Proc2.MC.get_alphai())) \
    X(GADDSI, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]], \
            *dest++ = *op1++ + sgf2n::constant(int(n), Proc.P.my_num(), Proc2.MC.get_alphai())) \
    X(GSUBS, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = &Proc2.get_S()[r[2]], \
            *dest++ = *op1++ - *op2++) \
    X(GSUBSI, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = sgf2n::constant(int(n), Proc.P.my_num(), Proc2.MC.get_alphai()), \
            *dest++ = *op1++ - op2) \
    X(GSUBSFI, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = sgf2n::constant(int(n), Proc.P.my_num(), Proc2.MC.get_alphai()), \
            *dest++ = op2 - *op1++) \
    X(GSUBML, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = &Proc2.get_C()[r[2]], \
            *dest++ = *op1++ - sgf2n::constant(*op2++, Proc.P.my_num(), Proc2.MC.get_alphai())) \
    X(GSUBMR, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_C()[r[1]]; \
            auto op2 = &Proc2.get_S()[r[2]], \
            *dest++ = sgf2n::constant(*op1++, Proc.P.my_num(), Proc2.MC.get_alphai()) - *op2++) \
    X(GMULM, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            auto op2 = &Proc2.get_C()[r[2]]; mulm_check<sgf2n>(), \
            *dest++ = *op1++ * *op2++) \
    X(GMULSI, auto dest = &Proc2.get_S()[r[0]]; auto op1 = &Proc2.get_S()[r[1]]; \
            typename sgf2n::clear op2 = int(n), \
            *dest++ = *op1++ * op2) \
    X(GTRIPLE, auto a = &Proc2.get_S()[r[0]]; auto b = &Proc2.get_S()[r[1]]; \
            auto c = &Proc2.get_S()[r[2]], \
            Proc2.DataF.get_three(DATA_TRIPLE, *a++, *b++, *c++)) \
    X(GBIT, auto dest = &Proc2.get_S()[r[0]], \
            Proc2.DataF.get_one(DATA_BIT, *dest++)) \
    X(CONVINT, auto dest = &Procp.get_C()[r[0]]; auto source = &Proc.get_Ci()[r[1]], \
            *dest++ = *source++) \
    X(GCONVINT, auto dest = &Proc2.get_C()[r[0]]; auto source = &Proc.get_Ci()[r[1]], \
            *dest++ = *source++) \

#define REGINT_INSTRUCTIONS \
    X(LDMINT, auto dest = &Proc.get_Ci()[r[0]]; auto source = &Mi[n], \
            *dest++ = (*source).get(); source++) \
    X(STMINT, auto dest = &Mi[n]; auto source = &Proc.get_Ci()[r[0]], \
            *dest++ = *source++) \
    X(LDMINTI, Mi.indirect_read(*this, Proc.get_Ci(), Proc.get_Ci()),) \
    X(STMINTI, Mi.indirect_write(*this, Proc.get_Ci(), Proc.get_Ci()),) \
    X(MOVINT, auto dest = &Proc.get_Ci()[r[0]]; auto source = &Ci[r[1]], \
            *dest++ = *source++) \
    X(PUSHINT, Proc.pushi(Ci[r[0]]),) \
    X(POPINT, auto dest = &Ci[r[0]], Proc.popi(*dest++)) \
    X(LDTN, auto dest = &Ci[r[0]], *dest++ = Proc.get_thread_num()) \
    X(LDARG, auto dest = &Ci[r[0]], *dest++ = Proc.get_arg()) \
    X(STARG, Proc.set_arg(Ci[r[0]]),) \
    X(LDINT, auto dest = &Proc.get_Ci()[r[0]], \
            *dest++ = int(n)) \
    X(ADDINT, auto dest = &Proc.get_Ci()[r[0]]; auto op1 = &Proc.get_Ci()[r[1]]; \
            auto op2 = &Proc.get_Ci()[r[2]], \
            *dest++ = *op1++ + *op2++) \
    X(SUBINT, auto dest = &Proc.get_Ci()[r[0]]; auto op1 = &Proc.get_Ci()[r[1]]; \
            auto op2 = &Proc.get_Ci()[r[2]], \
            *dest++ = *op1++ - *op2++) \
    X(MULINT, auto dest = &Proc.get_Ci()[r[0]]; auto op1 = &Proc.get_Ci()[r[1]]; \
            auto op2 = &Proc.get_Ci()[r[2]], \
            *dest++ = *op1++ * *op2++) \
    X(DIVINT, auto dest = &Proc.get_Ci()[r[0]]; auto op1 = &Proc.get_Ci()[r[1]]; \
            auto op2 = &Proc.get_Ci()[r[2]], \
            if (*op2 == 0) throw division_by_zero(); *dest++ = *op1++ / *op2++) \
    X(INCINT, auto dest = &Proc.get_Ci()[r[0]]; auto base = Proc.get_Ci()[r[1]], \
            int inc = (i / start[0]) % start[1]; *dest++ = base + inc * int(n)) \
    X(EQZC, auto dest = &Ci[r[0]]; auto source = &Ci[r[1]], *dest++ = *source++ == 0) \
    X(LTZC, auto dest = &Ci[r[0]]; auto source = &Ci[r[1]], *dest++ = *source++ < 0) \
    X(LTC, auto dest = &Ci[r[0]]; auto op1 = &Ci[r[1]]; auto op2 = &Ci[r[2]], \
            *dest++ = *op1++ < *op2++) \
    X(GTC, auto dest = &Ci[r[0]]; auto op1 = &Ci[r[1]]; auto op2 = &Ci[r[2]], \
            *dest++ = *op1++ > *op2++) \
    X(EQC, auto dest = &Ci[r[0]]; auto op1 = &Ci[r[1]]; auto op2 = &Ci[r[2]], \
            *dest++ = *op1++ == *op2++) \
    X(PRINTINT, print(Proc.out, &Proc.get_Ci_ref(r[0])),) \
    X(PRINTFLOATPREC, Proc.out << setprecision(n),) \
    X(PRINTSTR, Proc.out << string((char*)&n,4) << flush,) \
    X(PRINTCHR, Proc.out << string((char*)&n,1) << flush,) \
    X(SHUFFLE, shuffle(Proc),) \
    X(BITDECINT, bitdecint(Proc),) \
    X(RAND, auto dest = &Ci[r[0]]; auto source = &Ci[r[1]], \
            *dest++ = Proc.shared_prng.get_uint() % (1 << (*source++).get())) \

#define CLEAR_GF2N_INSTRUCTIONS \
    X(GLDI, auto dest = &C2[r[0]]; cgf2n tmp = int(n), \
            *dest++ = tmp) \
    X(GLDMC, auto dest = &C2[r[0]]; auto source = &M2C[n], \
            *dest++ = (*source).get(); source++) \
    X(GSTMC, auto dest = &M2C[n]; auto source = &C2[r[0]], \
            *dest++ = *source++) \
    X(GLDMCI, M2C.indirect_read(*this, C2, Proc.get_Ci()),) \
    X(GSTMCI, M2C.indirect_write(*this, C2, Proc.get_Ci()),) \
    X(GMOVC, auto dest = &C2[r[0]]; auto source = &C2[r[1]], \
            *dest++ = *source++) \
    X(GADDC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ + *op2++) \
    X(GADDCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ + op2) \
    X(GSUBC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ - *op2++) \
    X(GSUBCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ - op2) \
    X(GSUBCFI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = op2 - *op1++) \
    X(GMULC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ * *op2++) \
    X(GMULCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ * op2) \
    X(GANDC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ & *op2++) \
    X(GXORC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ ^ *op2++) \
    X(GORC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            auto op2 = &C2[r[2]], \
            *dest++ = *op1++ | *op2++) \
    X(GANDCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ & op2) \
    X(GXORCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ ^ op2) \
    X(GORCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]]; \
            cgf2n op2 = int(n), \
            *dest++ = *op1++ | op2) \
    X(GNOTC, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]], \
            *dest++ = ~*op1++) \
    X(GSHLCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]], \
            *dest++ = *op1++ << n) \
    X(GSHRCI, auto dest = &C2[r[0]]; auto op1 = &C2[r[1]], \
            *dest++ = *op1++ >> n) \
    X(GPRINTREG, auto source = &C2[r[0]], \
            Proc.out << "Reg[" << r[0] << "] = " << *source++ \
            << " # " << string((char*)&n, 4) << endl) \
    X(GPRINTREGPLAIN, auto source = &C2[r[0]], \
            Proc.out << *source++ << flush) \
    X(GBITDEC, gbitdec(C2),) \
    X(GBITCOM, gbitcom(C2),) \
    X(GCONVGF2N, auto dest = &Proc.get_Ci()[r[0]]; auto source = &C2[r[1]], \
            *dest++ = source->get_word(); source++) \
    X(GRAWOUTPUT, auto source = &C2[r[0]], \
            (*source++).output(Proc.get_public_output(), false)) \

#define REMAINING_INSTRUCTIONS \
    X(CONVMODP, throw not_implemented(),) \
    X(LDMC, throw not_implemented(),) \
    X(STMC, throw not_implemented(),) \
    X(MOVC, throw not_implemented(),) \
    X(DIVC, throw not_implemented(),) \
    X(GDIVC, throw not_implemented(),) \
    X(FLOORDIVC, throw not_implemented(),) \
    X(MODC, throw not_implemented(),) \
    X(LEGENDREC, throw not_implemented(),) \
    X(DIGESTC, throw not_implemented(),) \
    X(DIVCI, throw not_implemented(),) \
    X(GDIVCI, throw not_implemented(),) \
    X(INV2M, throw not_implemented(),) \
    X(MODCI, throw not_implemented(),) \
    X(SQUARE, throw not_implemented(),) \
    X(GSQUARE, throw not_implemented(),) \
    X(INV, throw not_implemented(),) \
    X(GINV, throw not_implemented(),) \
    X(RANDOMS, throw not_implemented(),) \
    X(INPUTMASKREG, throw not_implemented(),) \
    X(INPUTMASK, throw not_implemented(),) \
    X(GINPUTMASK, throw not_implemented(),) \
    X(INPUT, throw not_implemented(),) \
    X(GINPUT, throw not_implemented(),) \
    X(INPUTFIX, throw not_implemented(),) \
    X(INPUTFLOAT, throw not_implemented(),) \
    X(INPUTMIXED, throw not_implemented(),) \
    X(INPUTMIXEDREG, throw not_implemented(),) \
    X(RAWINPUT, throw not_implemented(),) \
    X(GRAWINPUT, throw not_implemented(),) \
    X(INPUTPERSONAL, throw not_implemented(),) \
    X(NOTC, throw not_implemented(),) \
    X(SHRSI, throw not_implemented(),) \
    X(OPEN, throw not_implemented(),) \
    X(GOPEN, throw not_implemented(),) \
    X(MULS, throw not_implemented(),) \
    X(GMULS, throw not_implemented(),) \
    X(MULRS, throw not_implemented(),) \
    X(GMULRS, throw not_implemented(),) \
    X(DOTPRODS, throw not_implemented(),) \
    X(GDOTPRODS, throw not_implemented(),) \
    X(MATMULS, throw not_implemented(),) \
    X(MATMULSM, throw not_implemented(),) \
    X(CONV2DS, throw not_implemented(),) \
    X(TRUNC_PR, throw not_implemented(),) \
    X(CHECK, throw not_implemented(),) \
    X(JMP, throw not_implemented(),) \
    X(JMPI, throw not_implemented(),) \
    X(JMPNZ, throw not_implemented(),) \
    X(JMPEQZ, throw not_implemented(),) \
    X(PRINTREG, throw not_implemented(),) \
    X(PRINTREGPLAIN, throw not_implemented(),) \
    X(CONDPRINTPLAIN, throw not_implemented(),) \
    X(PRINTFLOATPLAIN, throw not_implemented(),) \
    X(CONDPRINTSTR, throw not_implemented(),) \
    X(REQBL, throw not_implemented(),) \
    X(GREQBL, throw not_implemented(),) \
    X(USE, throw not_implemented(),) \
    X(USE_INP, throw not_implemented(),) \
    X(USE_EDABIT, throw not_implemented(),) \
    X(USE_MATMUL, throw not_implemented(),) \
    X(USE_PREP, throw not_implemented(),) \
    X(GUSE_PREP, throw not_implemented(),) \
    X(TIME, throw not_implemented(),) \
    X(START, throw not_implemented(),) \
    X(STOP, throw not_implemented(),) \
    X(RUN_TAPE, throw not_implemented(),) \
    X(JOIN_TAPE, throw not_implemented(),) \
    X(CRASH, throw not_implemented(),) \
    X(STARTGRIND, throw not_implemented(),) \
    X(STOPGRIND, throw not_implemented(),) \
    X(NPLAYERS, throw not_implemented(),) \
    X(THRESHOLD, throw not_implemented(),) \
    X(PLAYERID, throw not_implemented(),) \
    X(LISTEN, throw not_implemented(),) \
    X(ACCEPTCLIENTCONNECTION, throw not_implemented(),) \
    X(CLOSECLIENTCONNECTION, throw not_implemented(),) \
    X(READSOCKETINT, throw not_implemented(),) \
    X(READSOCKETC, throw not_implemented(),) \
    X(READSOCKETS, throw not_implemented(),) \
    X(WRITESOCKETINT, throw not_implemented(),) \
    X(WRITESOCKETC, throw not_implemented(),) \
    X(WRITESOCKETS, throw not_implemented(),) \
    X(WRITESOCKETSHARE, throw not_implemented(),) \
    X(WRITEFILESHARE, throw not_implemented(),) \
    X(READFILESHARE, throw not_implemented(),) \
    X(PUBINPUT, throw not_implemented(),) \
    X(RAWOUTPUT, throw not_implemented(),) \
    X(INTOUTPUT, throw not_implemented(),) \
    X(FLOATOUTPUT, throw not_implemented(),) \
    X(STARTPRIVATEOUTPUT, throw not_implemented(),) \
    X(GSTARTPRIVATEOUTPUT, throw not_implemented(),) \
    X(STOPPRIVATEOUTPUT, throw not_implemented(),) \
    X(GSTOPPRIVATEOUTPUT, throw not_implemented(),) \
    X(PREP, throw not_implemented(),) \
    X(GPREP, throw not_implemented(),) \
    X(CISC, throw not_implemented(),) \
    X(SECSHUFFLE, throw not_implemented(),) \
    X(GENSECSHUFFLE, throw not_implemented(),) \
    X(APPLYSHUFFLE, throw not_implemented(),) \
    X(DELSHUFFLE, throw not_implemented(),) \
    X(ACTIVE, throw not_implemented(),) \
    X(FIXINPUT, throw not_implemented(),) \
    X(CONCATS, throw not_implemented(),) \
    X(ZIPS, throw not_implemented(),) \
    X(GMATMULS, throw not_implemented(),) \
    X(GMATMULSM, throw not_implemented(),) \
    X(PRINTREGPLAINS, throw not_implemented(),) \
    X(GPRINTREGPLAINS, throw not_implemented(),) \
    X(CALL_TAPE, throw not_implemented(),) \
    X(CMDLINEARG, throw not_implemented(),) \
    X(INITCLIENTCONNECTION, throw not_implemented(),) \
    X(GWRITEFILESHARE, throw not_implemented(),) \
    X(GREADFILESHARE, throw not_implemented(),) \

#define ALL_INSTRUCTIONS ARITHMETIC_INSTRUCTIONS REGINT_INSTRUCTIONS \
    CLEAR_GF2N_INSTRUCTIONS REMAINING_INSTRUCTIONS

#endif /* PROCESSOR_INSTRUCTIONS_H_ */
