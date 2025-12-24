"""
This module constrains instructions for binary circuits. Unlike
arithmetic instructions, they generally do not use the vector size in
the instruction code field. Instead the number of bits affected is
given as an extra argument.  Also note that a register holds 64 values
instead of just one as is the case for arithmetic
instructions. Therefore, an instruction for 65-128 bits will affect
two registers etc. Similarly, a memory cell holds 64 bits.
"""

import Compiler.instructions_base as base
import Compiler.instructions as spdz
import Compiler.tools as tools
import collections
import itertools
import math

class SecretBitsAF(base.RegisterArgFormat):
    reg_type = 'sb'
    name = 'sbit'
class ClearBitsAF(base.RegisterArgFormat):
    reg_type = 'cb'
    name = 'cbit'

base.ArgFormats['sb'] = SecretBitsAF
base.ArgFormats['sbw'] = SecretBitsAF
base.ArgFormats['cb'] = ClearBitsAF
base.ArgFormats['cbw'] = ClearBitsAF

opcodes = dict(
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
    LDMCBI = 0x258,
    STMCBI = 0x259,
    CONVCINTVEC = 0x21f,
    PRINTREGSIGNED = 0x220,
    PRINTREGB = 0x221,
    PRINTREGPLAINB = 0x222,
    PRINTFLOATPLAINB = 0x223,
    CONDPRINTSTRB = 0x224,
    PRINTREGPLAINSB = 0x225,
    CONVCBIT = 0x230,
    CONVCBITVEC = 0x231,
)

class BinaryCiscable(base.Ciscable):
    pass

class BinaryVectorInstruction(BinaryCiscable):
    is_vec = lambda self: True

class NonVectorInstruction(base.Instruction):
    is_vec = lambda self: False

    def __init__(self, *args, **kwargs):
        assert(args[0].n is None or args[0].n <= args[0].unit)
        super(NonVectorInstruction, self).__init__(*args, **kwargs)

class NonVectorInstruction1(base.Instruction):
    is_vec = lambda self: False

    def __init__(self, *args, **kwargs):
        assert(args[1].n <= args[1].unit)
        super(NonVectorInstruction1, self).__init__(*args, **kwargs)

class xors(BinaryVectorInstruction):
    """ Bitwise XOR of secret bit register vectors.

    :param: number of arguments to follow (multiple of four)
    :param: number of bits (int)
    :param: result (sbit)
    :param: operand (sbit)
    :param: operand (sbit)
    :param: (repeat from number of bits)...
    """
    code = opcodes['XORS']
    arg_format = tools.cycle(['int','sbw','sb','sb'])

class xorm(NonVectorInstruction):
    """ Bitwise XOR of single secret and clear bit registers.

    :param: number of bits (less or equal 64)
    :param: result (sbit)
    :param: operand (sbit)
    :param: operand (cbit)
    """
    code = opcodes['XORM']
    arg_format = ['int','sbw','sb','cb']

class xorcb(BinaryVectorInstruction):
    """ Bitwise XOR of two single clear bit registers.

    :param: result (cbit)
    :param: operand (cbit)
    :param: operand (cbit)
    """
    code = opcodes['XORCB']
    arg_format = ['int','cbw','cb','cb']

class xorcbi(NonVectorInstruction):
    """ Bitwise XOR of single clear bit register and immediate.

    :param: result (cbit)
    :param: operand (cbit)
    :param: immediate (int)
    """
    code = opcodes['XORCBI']
    arg_format = ['cbw','cb','int']

class andrs(BinaryVectorInstruction):
    """ Constant-vector AND of secret bit registers.

    :param: number of arguments to follow (multiple of four)
    :param: number of bits (int)
    :param: result vector (sbit)
    :param: vector operand (sbit)
    :param: single operand (sbit)
    :param: (repeat from number of bits)...
    """
    code = opcodes['ANDRS']
    arg_format = tools.cycle(['int','sbw','sb','sb'])

    def add_usage(self, req_node):
        req_node.increment(('bit', 'triple'), sum(self.args[::4]))
        req_node.increment(('bit', 'mixed'),
                           sum(int(math.ceil(x / 64)) for x in self.args[::4]))

class andrsvec(base.VarArgsInstruction, base.Mergeable,
               base.DynFormatInstruction, BinaryCiscable):
    """ Constant-vector AND of secret bit registers (vectorized version).

    :param: total number of arguments to follow (int)
    :param: number of arguments to follow for one operation /
      operation vector size plus three (int)
    :param: vector size (int)
    :param: result vector (sbit)
    :param: (repeat)...
    :param: constant operand (sbits)
    :param: vector operand
    :param: (repeat)...
    :param: (repeat from number of arguments to follow for one operation)...

    """
    code = opcodes['ANDRSVEC']

    def __init__(self, *args, **kwargs):
        super(andrsvec, self).__init__(*args, **kwargs)
        for i, n in self.bases(iter(self.args)):
            size = self.args[i + 1]
            for x in self.args[i + 2:i + n]:
                assert x.n == size

    @classmethod
    def dynamic_arg_format(cls, args):
        yield 'int'
        for i, n in cls.bases(args):
            yield 'int'
            n_args = (n - 3) // 2
            assert n_args > 0
            for j in range(n_args):
                yield 'sbw'
            for j in range(n_args + 1):
                yield 'sb'
            yield 'int'

    def add_usage(self, req_node):
        for i, n in self.bases(iter(self.args)):
            size = self.args[i + 1]
            n = (n - 3) // 2
            req_node.increment(('bit', 'triple'), size * n)
            if n > 1:
                req_node.increment(('bit', 'mixed'), size * ((n + 63) // 64))

    def copy(self, size, subs):
        return type(self)(*self.get_new_args(size, subs))

class ands(BinaryVectorInstruction):
    """ Bitwise AND of secret bit register vector.

    :param: number of arguments to follow (multiple of four)
    :param: number of bits (int)
    :param: result (sbit)
    :param: operand (sbit)
    :param: operand (sbit)
    :param: (repeat from number of bits)...
    """
    code = opcodes['ANDS']
    arg_format = tools.cycle(['int','sbw','sb','sb'])

    def add_usage(self, req_node):
        req_node.increment(('bit', 'triple'), sum(self.args[::4]))

class andm(BinaryVectorInstruction):
    """ Bitwise AND of single secret and clear bit registers.

    :param: number of bits (less or equal 64)
    :param: result (sbit)
    :param: operand (sbit)
    :param: operand (cbit)
    """
    code = opcodes['ANDM']
    arg_format = ['int','sbw','sb','cb']

class nots(BinaryVectorInstruction):
    """ Bitwise NOT of secret register vector.

    :param: number of bits (less or equal 64)
    :param: result (sbit)
    :param: operand (sbit)
    """
    code = opcodes['NOTS']
    arg_format = ['int','sbw','sb']

class notcb(BinaryVectorInstruction):
    """ Bitwise NOT of secret register vector.

    :param: number of bits
    :param: result (cbit)
    :param: operand (cbit)
    """
    code = opcodes['NOTCB']
    arg_format = ['int','cbw','cb']

class addcb(NonVectorInstruction):
    """ Integer addition two single clear bit registers.

    :param: result (cbit)
    :param: summand (cbit)
    :param: summand (cbit)
    """
    code = opcodes['ADDCB']
    arg_format = ['cbw','cb','cb']

class addcbi(NonVectorInstruction):
    """ Integer addition single clear bit register and immediate.

    :param: result (cbit)
    :param: summand (cbit)
    :param: summand (int)
    """
    code = opcodes['ADDCBI']
    arg_format = ['cbw','cb','int']

class mulcbi(NonVectorInstruction):
    """ Integer multiplication single clear bit register and immediate.

    :param: result (cbit)
    :param: factor (cbit)
    :param: factor (int)
    """
    code = opcodes['MULCBI']
    arg_format = ['cbw','cb','int']

class bitdecs(NonVectorInstruction, base.VarArgsInstruction):
    """ Secret bit register decomposition.

    :param: number of arguments to follow / number of bits plus one (int)
    :param: source (sbit)
    :param: destination for least significant bit (sbit)
    :param: (destination for one bit higher)...
    """
    code = opcodes['BITDECS']
    arg_format = tools.chain(['sb'], itertools.repeat('sbw'))

class bitcoms(NonVectorInstruction, base.VarArgsInstruction):
    """ Secret bit register decomposition.

    :param: number of arguments to follow / number of bits plus one (int)
    :param: destination (sbit)
    :param: source for least significant bit (sbit)
    :param: (source for one bit higher)...
    """
    code = opcodes['BITCOMS']
    arg_format = tools.chain(['sbw'], itertools.repeat('sb'))

class bitdecc(NonVectorInstruction, base.VarArgsInstruction):
    """ Clear bit register decomposition.

    :param: number of arguments to follow / number of bits plus one (int)
    :param: source (sbit)
    :param: destination for least significant bit (sbit)
    :param: (destination for one bit higher)...
    """
    code = opcodes['BITDECC']
    arg_format = tools.chain(['cb'], itertools.repeat('cbw'))

class shrcbi(NonVectorInstruction):
    """ Right shift of clear bit register by immediate.

    :param: destination (cbit)
    :param: source (cbit)
    :param: number of bits to shift (int)
    """
    code = opcodes['SHRCBI']
    arg_format = ['cbw','cb','int']

class shlcbi(NonVectorInstruction):
    """ Left shift of clear bit register by immediate.

    :param: destination (cbit)
    :param: source (cbit)
    :param: number of bits to shift (int)
    """
    code = opcodes['SHLCBI']
    arg_format = ['cbw','cb','int']

class ldbits(NonVectorInstruction):
    """ Store immediate in secret bit register.

    :param: destination (sbit)
    :param: number of bits (int)
    :param: immediate (int)
    """
    code = opcodes['LDBITS']
    arg_format = ['sbw','i','i']

class ldmsb(base.DirectMemoryInstruction, base.ReadMemoryInstruction,
            base.VectorInstruction):
    """ Copy secret bit memory cell with compile-time address to secret bit
    register.

    :param: destination (sbit)
    :param: memory address (int)
    """
    code = opcodes['LDMSB']
    arg_format = ['sbw','long']

class stmsb(base.DirectMemoryWriteInstruction, base.VectorInstruction):
    """ Copy secret bit register to secret bit memory cell with compile-time
    address.

    :param: source (sbit)
    :param: memory address (int)
    """
    code = opcodes['STMSB']
    arg_format = ['sb','long']
    # def __init__(self, *args, **kwargs):
    #     super(type(self), self).__init__(*args, **kwargs)
    #     import inspect
    #     self.caller = [frame[1:] for frame in inspect.stack()[1:]]

class ldmcb(base.DirectMemoryInstruction, base.ReadMemoryInstruction,
            base.VectorInstruction):
    """ Copy clear bit memory cell with compile-time address to clear bit
    register.

    :param: destination (cbit)
    :param: memory address (int)
    """
    code = opcodes['LDMCB']
    arg_format = ['cbw','long']

class stmcb(base.DirectMemoryWriteInstruction, base.VectorInstruction):
    """ Copy clear bit register to clear bit memory cell with compile-time
    address.

    :param: source (cbit)
    :param: memory address (int)
    """
    code = opcodes['STMCB']
    arg_format = ['cb','long']

class ldmsbi(base.ReadMemoryInstruction, base.VectorInstruction,
             base.IndirectMemoryInstruction):
    """ Copy secret bit memory cell with run-time address to secret bit
    register.

    :param: destination (sbit)
    :param: memory address (regint)
    """
    code = opcodes['LDMSBI']
    arg_format = ['sbw','ci']
    direct = staticmethod(ldmsb)

class stmsbi(base.WriteMemoryInstruction, base.VectorInstruction,
             base.IndirectMemoryInstruction):
    """ Copy secret bit register to secret bit memory cell with run-time
    address.

    :param: source (sbit)
    :param: memory address (regint)
    """
    code = opcodes['STMSBI']
    arg_format = ['sb','ci']
    direct = staticmethod(stmsb)

class ldmcbi(base.ReadMemoryInstruction, base.VectorInstruction,
             base.IndirectMemoryInstruction):
    """ Copy clear bit memory cell with run-time address to clear bit
    register.

    :param: destination (cbit)
    :param: memory address (regint)
    """
    code = opcodes['LDMCBI']
    arg_format = ['cbw','ci']
    direct = staticmethod(ldmcb)

class stmcbi(base.WriteMemoryInstruction, base.VectorInstruction,
             base.IndirectMemoryInstruction):
    """ Copy clear bit register to clear bit memory cell with run-time
    address.

    :param: source (cbit)
    :param: memory address (regint)
    """
    code = opcodes['STMCBI']
    arg_format = ['cb','ci']
    direct = staticmethod(stmcb)

class ldmsdi(base.ReadMemoryInstruction):
    code = opcodes['LDMSDI']
    arg_format = tools.cycle(['sbw','cb','int'])

class stmsdi(base.WriteMemoryInstruction):
    code = opcodes['STMSDI']
    arg_format = tools.cycle(['sb','cb'])

class ldmsd(base.ReadMemoryInstruction):
    code = opcodes['LDMSD']
    arg_format = tools.cycle(['sbw','int','int'])

class stmsd(base.WriteMemoryInstruction):
    code = opcodes['STMSD']
    arg_format = tools.cycle(['sb','int'])

class stmsdci(base.WriteMemoryInstruction):
    code = opcodes['STMSDCI']
    arg_format = tools.cycle(['cb','cb'])

class convsint(NonVectorInstruction1):
    """ Copy clear integer register to secret bit register.

    :param: number of bits (int)
    :param: destination (sbit)
    :param: source (regint)
    """
    code = opcodes['CONVSINT']
    arg_format = ['int','sbw','ci']

class convcint(NonVectorInstruction):
    """ Copy clear integer register to clear bit register.

    :param: number of bits (int)
    :param: destination (cbit)
    :param: source (regint)
    """
    code = opcodes['CONVCINT']
    arg_format = ['cbw','ci']

class convcbit(NonVectorInstruction1):
    """ Copy clear bit register to clear integer register.

    :param: destination (regint)
    :param: source (cbit)
    """
    code = opcodes['CONVCBIT']
    arg_format = ['ciw','cb']

@base.vectorize
class convcintvec(base.Instruction):
    """ Copy clear register vector by bit to clear bit register
    vectors. This means that the first destination will hold the least
    significant bits of all inputs etc.

    :param: number of arguments to follow / number of bits plus one (int)
    :param: source (cint)
    :param: destination for least significant bits (sbit)
    :param: (destination for bits one step higher)...
    """
    code = opcodes['CONVCINTVEC']
    arg_format = tools.chain(['c'], tools.cycle(['cbw']))

class convcbitvec(BinaryVectorInstruction):
    """ Copy clear bit register vector to clear register by bit. This means
    that every element of the destination register vector will hold one bit.

    :param: number of bits / vector length (int)
    :param: destination (regint)
    :param: source (cbit)
    """
    code = opcodes['CONVCBITVEC']
    arg_format = ['int','ciw','cb']
    def __init__(self, *args, **kwargs):
        super(convcbitvec, self).__init__(*args, **kwargs)
        assert(args[2].n == args[0])
        args[1].set_size(args[0])

class convcbit2s(BinaryVectorInstruction):
    """ Copy clear bit register vector to secret bit register vector.

    :param: number of bits (int)
    :param: destination (sbit)
    :param: source (cbit)
    """
    code = opcodes['CONVCBIT2S']
    arg_format = ['int','sbw','cb']

@base.vectorize
class split(base.Instruction):
    """ Local share conversion. This instruction use the vector length in the
    instruction code field.

    :param: number of arguments to follow (number of bits times number of additive shares plus one)
    :param: source (sint)
    :param: first share of least significant bit (sbit)
    :param: second share of least significant bit (sbit)
    :param: (remaining share of least significant bit)...
    :param: (repeat from first share for bit one step higher)...
    """
    code = opcodes['SPLIT']
    arg_format = tools.chain(['int','s'], tools.cycle(['sbw']))
    def __init__(self, *args, **kwargs):
        super(split_class, self).__init__(*args, **kwargs)
        assert (len(args) - 2) % args[0] == 0

    def add_usage(self, req_node):
        req_node.increment(('modp', '%d-way split' % self.args[0]),
                           self.get_size())
        req_node.increment(('modp', '%d-way split round' % self.args[0]), 1)

class movsb(BinaryVectorInstruction):
    """ Copy secret bit register.

    :param: destination (sbit)
    :param: source (sbit)
    """
    code = opcodes['MOVSB']
    arg_format = ['int', 'sbw','sb']

class trans(base.VarArgsInstruction, base.DynFormatInstruction):
    """ Secret bit register vector transpose. The first destination vector
    will contain the least significant bits of all source vectors etc.

    :param: number of arguments to follow (int)
    :param: number of outputs (int)
    :param: destination for least significant bits (sbit)
    :param: (destination for bits one step higher)...
    :param: source (sbit)
    :param: (source)...
    """
    code = opcodes['TRANS']
    is_vec = lambda self: True

    @classmethod
    def dynamic_arg_format(cls, args):
        yield 'int'
        n = next(args)
        for i in range(n):
            yield 'sbw'
            next(args)
        while True:
            try:
                yield 'sb'
                next(args)
            except StopIteration:
                break

class bitb(NonVectorInstruction):
    """ Copy fresh secret random bit to secret bit register.

    :param: destination (sbit)
    """
    code = opcodes['BITB']
    arg_format = ['sbw']

    def add_usage(self, req_node):
        req_node.increment(('bit', 'bit'), 1)

class reveal(BinaryVectorInstruction, base.VarArgsInstruction, base.Mergeable):
    """ Reveal secret bit register vectors and copy result to clear bit
    register vectors.

    :param: number of arguments to follow (multiple of three)
    :param: number of bits (int)
    :param: destination (cbit)
    :param: source (sbit)
    :param: (repeat from number of bits)...
    """
    code = opcodes['REVEAL']
    arg_format = tools.cycle(['int','cbw','sb'])

    def add_usage(self, req_node):
        req_node.increment(('bit', 'open'), sum(
            int(math.ceil(x / 64)) * 8 for x in self.args[0::3]))

class inputb(base.DoNotEliminateInstruction, base.VarArgsInstruction):
    """ Copy private input to secret bit register vectors. The input is
    read as floating-point number, multiplied by a power of two, and then
    rounded to an integer.

    :param: number of arguments to follow (multiple of four)
    :param: player number (int)
    :param: number of bits in output (int)
    :param: exponent to power of two factor (int)
    :param: destination (sbit)
    """
    __slots__ = []
    code = opcodes['INPUTB']
    arg_format = tools.cycle(['p','int','int','sbw'])
    is_vec = lambda self: True

    def add_usage(self, req_node):
        for i in range(0, len(self.args), 4):
            req_node.increment(('bit', 'input', self.args[i]), self.args[i + 1])

class inputbvec(base.DoNotEliminateInstruction, base.VarArgsInstruction,
                base.Mergeable, base.DynFormatInstruction):
    """ Copy private input to secret bit registers bit by bit. The input is
    read as floating-point number, multiplied by a power of two, rounded to an
    integer, and then decomposed into bits.

    :param: total number of arguments to follow (int)
    :param: number of arguments to follow for one input / number of bits plus three (int)
    :param: exponent to power of two factor (int)
    :param: player number (int)
    :param: destination for least significant bit (sbit)
    :param: (destination for one bit higher)...
    :param: (repeat from number of arguments to follow for one input)...
    """
    __slots__ = []
    code = opcodes['INPUTBVEC']

    def __init__(self, *args, **kwargs):
        super(inputbvec, self).__init__(*args, **kwargs)

    @classmethod
    def dynamic_arg_format(cls, args):
        yield 'int'
        for i, n in cls.bases(args):
            yield 'int'
            yield 'p'
            assert n > 3
            for j in range(n - 3):
                yield 'sbw'
            yield 'int'

    @staticmethod
    def get_arg_tuples(args):
        i = 0
        while i < len(args):
            yield args[i:i+args[i]]
            i += args[i]
        assert i == len(args)

    def add_usage(self, req_node):
        for x in self.get_arg_tuples(self.args):
            req_node.increment(('bit', 'input', x[2]), x[0] - 3)

class print_regb(base.VectorInstruction, base.IOInstruction):
    """ Debug output of clear bit register.

    :param: source (cbit)
    :param: comment (4 bytes / 1 unit)
    """
    code = opcodes['PRINTREGB']
    arg_format = ['cb','i']
    def __init__(self, reg, comment=''):
        super(print_regb, self).__init__(reg, self.str_to_int(comment))

class print_reg_plainb(NonVectorInstruction, base.IOInstruction):
    """ Output clear bit register.

    :param: source (cbit)
    """
    code = opcodes['PRINTREGPLAINB']
    arg_format = ['cb']

class print_reg_plainsb(NonVectorInstruction, base.IOInstruction):
    """ Output secret bit register.

    :param: source (sbit)
    """
    code = opcodes['PRINTREGPLAINSB']
    arg_format = ['sb']

class print_reg_signed(base.IOInstruction):
    """ Signed output of clear bit register.

    :param: bit length (int)
    :param: source (cbit)
    """
    code = opcodes['PRINTREGSIGNED']
    arg_format = ['int','cb']
    is_vec = lambda self: True

class print_float_plainb(base.IOInstruction):
    """ Output floating-number from clear bit registers.

    :param: significand (cbit)
    :param: exponent (cbit)
    :param: zero bit (cbit, zero output if bit is one)
    :param: sign bit (cbit, negative output if bit is one)
    :param: NaN (cbit, regular number if zero)
    """
    __slots__ = []
    code = opcodes['PRINTFLOATPLAINB']
    arg_format = ['cb', 'cb', 'cb', 'cb', 'cb']

class cond_print_strb(base.IOInstruction):
    """ Conditionally output four bytes.

    :param: condition (cbit, no output if zero)
    :param: four bytes (int)
    """
    code = opcodes['CONDPRINTSTRB']
    arg_format = ['cb', 'int']

    def __init__(self, cond, val):
        super(cond_print_strb, self).__init__(cond, self.str_to_int(val))
