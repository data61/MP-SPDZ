"""
This module contains all instruction types for arithmetic computation
and general control of the virtual machine such as control flow.

The parameter descriptions refer to the instruction arguments in the
right order.
"""

# All base classes, utility functions etc. should go in
# instructions_base.py instead. This is for two reasons:
# 1) Easier generation of documentation
# 2) Ensures that 'from instructions import *' will only import assembly
# instructions and nothing else.
#
# Note: every instruction should have a suitable docstring for
# auto-generation of documentation

import itertools
import operator
import math
import re
from . import tools
from random import randint
from functools import reduce
from Compiler.config import *
from Compiler.exceptions import *
import Compiler.instructions_base as base


# avoid naming collision with input instruction
_python_input = input

###
### Load and store instructions
###

@base.gf2n
@base.vectorize
class ldi(base.Instruction):
    """ Assign (constant) immediate value to clear register (vector).

    :param: destination (cint)
    :param: value (int)
    """
    __slots__ = []
    code = base.opcodes['LDI']
    arg_format = ['cw','i']

@base.gf2n
@base.vectorize
class ldsi(base.Instruction):
    """ Assign (constant) immediate value to secret register (vector).

    :param: destination (sint)
    :param: value (int)
    """
    __slots__ = []
    code = base.opcodes['LDSI']
    arg_format = ['sw','i']

@base.gf2n
@base.vectorize
class ldmc(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    """ Assign clear memory value(s) to clear register (vector) by
    immediate address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: destination (cint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['LDMC']
    arg_format = ['cw','long']

@base.gf2n
@base.vectorize
class ldms(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    """ Assign secret memory value(s) to secret register (vector) by
    immediate address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: destination (sint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['LDMS']
    arg_format = ['sw','long']

@base.gf2n
@base.vectorize
class stmc(base.DirectMemoryWriteInstruction):
    """ Assign clear register (vector) to clear memory value(s) by
    immediate address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: source (cint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['STMC']
    arg_format = ['c','long']

@base.gf2n
@base.vectorize
class stms(base.DirectMemoryWriteInstruction):
    """ Assign secret register (vector) to secret memory value(s) by
    immediate address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: source (sint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['STMS']
    arg_format = ['s','long']

@base.vectorize
class ldmint(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    """ Assign clear integer memory value(s) to clear integer register
    (vector) by immediate address. The vectorized version starts at
    the base address and then iterates the memory address.

    :param: destination (regint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['LDMINT']
    arg_format = ['ciw','long']

@base.vectorize
class stmint(base.DirectMemoryWriteInstruction):
    """ Assign clear integer register (vector) to clear integer memory
    value(s) by immediate address. The vectorized version starts at
    the base address and then iterates the memory address.

    :param: source (regint)
    :param: memory address base (int)

    """
    __slots__ = []
    code = base.opcodes['STMINT']
    arg_format = ['ci','long']

@base.vectorize
class ldmci(base.ReadMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign clear memory value(s) to clear register (vector) by
    register address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: destination (cint)
    :param: memory address base (regint)

    """
    code = base.opcodes['LDMCI']
    arg_format = ['cw','ci']
    direct = staticmethod(ldmc)

@base.vectorize
class ldmsi(base.ReadMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign secret memory value(s) to secret register (vector) by
    register address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: destination (sint)
    :param: memory address base (regint)

    """
    code = base.opcodes['LDMSI']
    arg_format = ['sw','ci']
    direct = staticmethod(ldms)

@base.vectorize
class stmci(base.WriteMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign clear register (vector) to clear memory value(s) by
    register address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: source (cint)
    :param: memory address base (regint)

    """
    code = base.opcodes['STMCI']
    arg_format = ['c','ci']
    direct = staticmethod(stmc)

@base.vectorize
class stmsi(base.WriteMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign secret register (vector) to secret memory value(s) by
    register address. The vectorized version starts at the base
    address and then iterates the memory address.

    :param: source (sint)
    :param: memory address base (regint)

    """
    code = base.opcodes['STMSI']
    arg_format = ['s','ci']
    direct = staticmethod(stms)

@base.vectorize
class ldminti(base.ReadMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign clear integer memory value(s) to clear integer register
    (vector) by register address. The vectorized version starts at the
    base address and then iterates the memory address.

    :param: destination (regint)
    :param: memory address base (regint)

    """
    code = base.opcodes['LDMINTI']
    arg_format = ['ciw','ci']
    direct = staticmethod(ldmint)

@base.vectorize
class stminti(base.WriteMemoryInstruction, base.IndirectMemoryInstruction):
    """ Assign clear integer register (vector) to clear integer memory
    value(s) by register address. The vectorized version starts at the
    base address and then iterates the memory address.

    :param: source (regint)
    :param: memory address base (regint)

    """
    code = base.opcodes['STMINTI']
    arg_format = ['ci','ci']
    direct = staticmethod(stmint)

@base.vectorize
class gldmci(base.ReadMemoryInstruction, base.IndirectMemoryInstruction):
    r""" Assigns register $c_i$ the value in memory \verb+C[cj]+. """
    code = base.opcodes['LDMCI'] + 0x100
    arg_format = ['cgw','ci']
    direct = staticmethod(gldmc)

@base.vectorize
class gldmsi(base.ReadMemoryInstruction, base.IndirectMemoryInstruction):
    r""" Assigns register $s_i$ the value in memory \verb+S[cj]+. """
    code = base.opcodes['LDMSI'] + 0x100
    arg_format = ['sgw','ci']
    direct = staticmethod(gldms)

@base.vectorize
class gstmci(base.WriteMemoryInstruction, base.IndirectMemoryInstruction):
    r""" Sets \verb+C[cj]+ to be the value $c_i$. """
    code = base.opcodes['STMCI'] + 0x100
    arg_format = ['cg','ci']
    direct = staticmethod(gstmc)

@base.vectorize
class gstmsi(base.WriteMemoryInstruction, base.IndirectMemoryInstruction):
    r""" Sets \verb+S[cj]+ to be the value $s_i$. """
    code = base.opcodes['STMSI'] + 0x100
    arg_format = ['sg','ci']
    direct = staticmethod(gstms)

@base.gf2n
@base.vectorize
class movc(base.Instruction):
    """ Copy clear register (vector).

    :param: destination (cint)
    :param: source (cint)
    """
    __slots__ = []
    code = base.opcodes['MOVC']
    arg_format = ['cw','c']

@base.gf2n
@base.vectorize
class movs(base.Instruction):
    """ Copy secret register (vector).

    :param: destination (cint)
    :param: source (cint)
    """
    __slots__ = []
    code = base.opcodes['MOVS']
    arg_format = ['sw','s']

@base.vectorize
class movint(base.Instruction):
    """ Copy clear integer register (vector).

    :param: destination (regint)
    :param: source (regint)
    """
    __slots__ = []
    code = base.opcodes['MOVINT']
    arg_format = ['ciw','ci']

@base.vectorize
class pushint(base.StackInstruction):
    """ Pushes clear integer register to the thread-local stack.
    Considered obsolete.

    :param: source (regint)
    """
    code = base.opcodes['PUSHINT']
    arg_format = ['ci']

@base.vectorize
class popint(base.StackInstruction):
    """ Pops from the thread-local stack to clear integer register.
    Considered obsolete.

    :param: destination (regint)
    """
    code = base.opcodes['POPINT']
    arg_format = ['ciw']


###
### Machine
###

@base.vectorize
class ldtn(base.Instruction):
    """ Store the number of the current thread in clear integer register.

    :param: destination (regint)
    """
    code = base.opcodes['LDTN']
    arg_format = ['ciw']

@base.vectorize
class ldarg(base.Instruction):
    """ Store the argument passed to the current thread in clear integer
    register.

    :param: destination (regint)
    """
    code = base.opcodes['LDARG']
    arg_format = ['ciw']

@base.vectorize
class starg(base.Instruction):
    """ Copy clear integer register to the thread argument.

    :param: source (regint)
    """
    code = base.opcodes['STARG']
    arg_format = ['ci']

@base.vectorize
class cmdlinearg(base.Instruction):
    """ Load command-line argument.

    :param: dest (regint)
    :param: index (regint)

    """
    code = base.opcodes['CMDLINEARG']
    arg_format = ['ciw','ci']

@base.gf2n
class reqbl(base.Instruction):
    """ Requirement on computation modulus. Minimal bit length of prime if
    positive, minus exact bit length of power of two if negative.


    :param: requirement (int)
    """
    code = base.opcodes['REQBL']
    arg_format = ['int']

class active(base.Instruction):
    """ Indicate whether program is compatible with malicious-security
    protocols.

    :param: 0 for no, 1 for yes
    """
    code = base.opcodes['ACTIVE']
    arg_format = ['int']

class time(base.IOInstruction):

    """ Output time since start of computation. """
    code = base.opcodes['TIME']
    arg_format = []

class start(base.Instruction):
    """ Start timer.

    :param: timer number (int)
    """
    code = base.opcodes['START']
    arg_format = ['i']

class stop(base.Instruction):
    """ Stop timer.

    :param: timer number (int)
    """
    code = base.opcodes['STOP']
    arg_format = ['i']

class use(base.Instruction):
    r""" Offline data usage. Necessary to avoid reusage while using
    preprocessing from files. Also used to multithreading for expensive
    preprocessing.

    :param: domain (0: integer, 1: :math:`\mathrm{GF}(2^n)`, 2: bit)
    :param: type (0: triple, 1: square, 2: bit, 3: inverse, 6: daBit)
    :param: number (int, -1 for unknown)
    """
    code = base.opcodes['USE']
    arg_format = ['int','int','long']

    @classmethod
    def get_usage(cls, args):
        from .program import field_types, data_types
        from .util import find_in_dict
        return {(find_in_dict(field_types, args[0].i),
                 find_in_dict(data_types, args[1].i)):
                 args[2].i}

class use_inp(base.Instruction):
    r""" Input usage.  Necessary to avoid reusage while using
    preprocessing from files.

    :param: domain (0: integer, 1: :math:`\mathrm{GF}(2^n)`, 2: bit)
    :param: input player (int)
    :param: number (int, -1 for unknown)
    """
    code = base.opcodes['USE_INP']
    arg_format = ['int','int','long']

    @classmethod
    def get_usage(cls, args):
        from .program import field_types, data_types
        from .util import find_in_dict
        return {(find_in_dict(field_types, args[0].i), 'input', args[1].i):
                 args[2].i}

class use_edabit(base.Instruction):
    """ edaBit usage. Necessary to avoid reusage while using
    preprocessing from files. Also used to multithreading for expensive
    preprocessing.

    :param: loose/strict (0/1)
    :param: length (int)
    :param: number (int, -1 for unknown)
    """
    code = base.opcodes['USE_EDABIT']
    arg_format = ['int','int','long']

    @classmethod
    def get_usage(cls, args):
        return {('sedabit' if args[0].i else 'edabit', args[1].i): args[2].i}

class use_matmul(base.Instruction):
    """ Matrix multiplication usage. Used for multithreading of
    preprocessing.

    :param: number of left-hand rows (int)
    :param: number of left-hand columns/right-hand rows (int)
    :param: number of right-hand columns (int)
    :param: number (int, -1 for unknown)
    """
    code = base.opcodes['USE_MATMUL']
    arg_format = ['int','int','int','long']

    @classmethod
    def get_usage(cls, args):
        return {('matmul', tuple(arg.i for arg in args[:3])): args[3].i}

class run_tape(base.Instruction):
    """ Start tape/bytecode file in another thread.

    :param: number of arguments to follow (multiple of three)
    :param: virtual machine thread number (int)
    :param: tape number (int)
    :param: tape argument (int)
    :param: (repeat the last three)...
    """
    code = base.opcodes['RUN_TAPE']
    arg_format = tools.cycle(['int','int','int'])

class join_tape(base.Instruction):
    """ Join thread.

    :param: virtual machine thread number (int)
    """
    code = base.opcodes['JOIN_TAPE']
    arg_format = ['int']

class call_tape(base.DoNotEliminateInstruction):
    """ Start tape/bytecode file in same thread. Arguments/return values
    starting from :py:obj:`direction` are optional.

    :param: tape number (int)
    :param: arg (regint)
    :param: direction (0 for argument, 1 for return value)
    :param: register type (see :py:obj:`vm_types`)
    :param: register size (int)
    :param: destination register
    :param: source register
    :param: (repeat from direction)

    """
    code = base.opcodes['CALL_TAPE']
    arg_format = tools.chain(['int', 'ci'],
                             tools.cycle(['int','int','int','*w','*']))

    @staticmethod
    def type_check(reg, type_id):
        assert base.vm_types[reg.reg_type] == type_id

    def __init__(self, *args, **kwargs):
        super(call_tape, self).__init__(*args, **kwargs)
        for i in range(2, len(args), 5):
            for reg in args[i + 3:i + 5]:
                self.type_check(reg, args[i + 1])
                assert reg.size == args[i + 2]
            assert args[i] in (0, 1)
            assert args[i + 4 - args[i]].program == program.curr_tape
            assert args[i + 3 + args[i]].program == program.tapes[args[0]]

    def get_def(self):
        # hide registers from called tape
        for i in range(2, len(self.args), 5):
            if self.args[i]:
                yield self.args[i + 3]

    def get_used(self):
        # hide registers from called tape
        yield self.args[1]
        for i in range(2, len(self.args), 5):
            if not self.args[i]:
                yield self.args[i + 4]

    def add_usage(self, req_node):
        req_node.num += program.tapes[self.args[0]].req_tree.aggregate()

class call_arg(base.DoNotEliminateInstruction, base.VectorInstruction):
    """ Pseudo instruction for arguments in connection with
    :py:class:`call_tape`.

    :param: destination (register)
    :param: register type (see :py:obj:`vm_types`)

    """
    code = base.opcodes['CALL_ARG']
    arg_format = ['*w','int']

    def __init__(self, *args, **kwargs):
        super(call_arg, self).__init__(*args, **kwargs)
        for i in range(0, len(args), 2):
            call_tape.type_check(args[i], args[i + 1])

class crash(base.IOInstruction):
    """ Crash runtime if the value in the register is not zero.

    :param: Crash condition (regint)"""
    code = base.opcodes['CRASH']
    arg_format = ['ci']

class start_grind(base.IOInstruction):
    code = base.opcodes['STARTGRIND']
    arg_format = []

class stop_grind(base.IOInstruction):
    code = base.opcodes['STOPGRIND']
    arg_format = []

@base.gf2n
class use_prep(base.Instruction):
    """ Custom preprocessed data usage.

    :param: tag (16 bytes / 4 units, cut off at first zero byte)
    :param: number of items to use (int, -1 for unknown)
    """
    code = base.opcodes['USE_PREP']
    arg_format = ['str','long']

    @classmethod
    def get_usage(cls, args):
        return {('gf2n' if cls.__name__ == 'guse_prep' else 'modp',
                 args[0].str): args[1].i}

class nplayers(base.Instruction):
    """ Store number of players in clear integer register.

    :param: destination (regint)
    """
    code = base.opcodes['NPLAYERS']
    arg_format = ['ciw']

class threshold(base.Instruction):
    """ Store maximal number of corrupt players in clear integer register.

    :param: destination (regint)
    """
    code = base.opcodes['THRESHOLD']
    arg_format = ['ciw']

class playerid(base.Instruction):
    """ Store current player number in clear integer register.

    :param: destination (regint)
    """
    code = base.opcodes['PLAYERID']
    arg_format = ['ciw']

###
### Basic arithmetic
###

@base.gf2n
@base.vectorize
class addc(base.AddBase):
    """ Clear addition.

    :param: result (cint)
    :param: summand (cint)
    :param: summand (cint)
    """
    __slots__ = []
    code = base.opcodes['ADDC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class adds(base.AddBase):
    """ Secret addition.

    :param: result (sint)
    :param: summand (sint)
    :param: summand (sint)
    """
    __slots__ = []
    code = base.opcodes['ADDS']
    arg_format = ['sw','s','s']

@base.gf2n
@base.vectorize
class addm(base.AddBase):
    """ Mixed addition.

    :param: result (sint)
    :param: summand (sint)
    :param: summand (cint)
    """
    __slots__ = []
    code = base.opcodes['ADDM']
    arg_format = ['sw','s','c']

@base.gf2n
@base.vectorize
class subc(base.SubBase):
    """ Clear subtraction.

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (cint)
    """
    __slots__ = []
    code = base.opcodes['SUBC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class subs(base.SubBase):
    """ Secret subtraction.

    :param: result (sint)
    :param: first operand (sint)
    :param: second operand (sint)
    """
    __slots__ = []
    code = base.opcodes['SUBS']
    arg_format = ['sw','s','s']

@base.gf2n
@base.vectorize
class subml(base.SubBase):
    """ Subtract clear from secret value.

    :param: result (sint)
    :param: first operand (sint)
    :param: second operand (cint)
    """
    __slots__ = []
    code = base.opcodes['SUBML']
    arg_format = ['sw','s','c']

@base.gf2n
@base.vectorize
class submr(base.SubBase):
    """ Subtract secret from clear value.

    :param: result (sint)
    :param: first operand (cint)
    :param: second operand (sint)
    """
    __slots__ = []
    code = base.opcodes['SUBMR']
    arg_format = ['sw','c','s']

@base.vectorize
class prefixsums(base.Instruction):
    """ Prefix sum.

    :param: result (sint)
    :param: input (sint)

    """
    __slots__ = []
    code = base.opcodes['PREFIXSUMS']
    arg_format = ['sw','s']

class picks(base.VectorInstruction):
    """ Extract part of vector.

    :param: result (sint)
    :param: input (sint)
    :param: start offset (int)
    :param: step

    """
    __slots__ = []
    code = base.opcodes['PICKS']
    arg_format = ['sw','s','int','int']

    def __init__(self, *args):
        super(picks, self).__init__(*args)
        assert 0 <= args[2] < len(args[1])
        assert 0 <= args[2] + args[3] * (len(args[0]) - 1) < len(args[1])

class concats(base.VectorInstruction):
    """ Concatenate vectors.

    :param: result (sint)
    :param: start offset (int)
    :param: input (sint)
    :param: (repeat from offset)...

    """
    __slots__ = []
    code = base.opcodes['CONCATS']
    arg_format = tools.chain(['sw'], tools.cycle(['int','s']))

    def __init__(self, *args):
        super(concats, self).__init__(*args)
        assert len(args) % 2 == 1
        assert len(args[0]) == sum(args[1::2])
        for i in range(1, len(args), 2):
            assert args[i] == len(args[i + 1])

class zips(base.Instruction):
    """ Zip vectors.

    :param: result (sint)
    :param: operand (sint)
    :param: operand (sint)

    """
    __slots__ = []
    code = base.opcodes['ZIPS']
    arg_format = ['sw','s','s']
    is_vec = lambda self: True

    def __init__(self, *args):
        super(zips, self).__init__(*args)
        assert len(args[0]) == len(args[1]) + len(args[2])
        assert len(args[1]) == len(args[2])

    def get_code(self):
        return super(zips, self).get_code(len(self.args[1]))

@base.gf2n
@base.vectorize
class mulc(base.MulBase):
    """ Clear multiplication.

    :param: result (cint)
    :param: factor (cint)
    :param: factor (cint)
    """
    __slots__ = []
    code = base.opcodes['MULC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class mulm(base.MulBase):
    """ Multiply secret and clear value.

    :param: result (sint)
    :param: factor (sint)
    :param: factor (cint)
    """
    __slots__ = []
    code = base.opcodes['MULM']
    arg_format = ['sw','s','c']

@base.gf2n
@base.vectorize
class divc(base.InvertInstruction):
    """ Clear division.

    :param: result (cint)
    :param: dividend (cint)
    :param: divisor (cint)
    """
    __slots__ = []
    code = base.opcodes['DIVC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class floordivc(base.Instruction):
    """ Clear integer floor division.

    :param: result (cint)
    :param: dividend (cint)
    :param: divisor (cint)
    """
    __slots__ = []
    code = base.opcodes['FLOORDIVC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class modc(base.Instruction):
    """ Clear modular reduction.

    :param: result (cint)
    :param: dividend (cint)
    :param: divisor (cint)
    """
    __slots__ = []
    code = base.opcodes['MODC']
    arg_format = ['cw','c','c']

@base.vectorize
class inv2m(base.InvertInstruction):
    """ Inverse of power of two modulo prime (the computation modulus).

    :param: result (cint)
    :param: exponent (int)
    """
    __slots__ = []
    code = base.opcodes['INV2M']
    arg_format = ['cw','int']

@base.vectorize
class legendrec(base.Instruction):
    """ Clear Legendre symbol computation (a/p) over prime p
    (the computation modulus).

    :param: result (cint)
    :param: a (int)
    """
    __slots__ = []
    code = base.opcodes['LEGENDREC']
    arg_format = ['cw','c']

@base.vectorize
class digestc(base.Instruction):
    """ Clear truncated hash computation.

    :param: result (cint)
    :param: input (cint)
    :param: byte length of hash value used (int)
    """
    __slots__ = []
    code = base.opcodes['DIGESTC']
    arg_format = ['cw','c','int']

###
### Bitwise operations
###

@base.gf2n
@base.vectorize
class andc(base.Instruction):
    """ Logical AND of clear (vector) registers.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (cint)
    """
    __slots__ = []
    code = base.opcodes['ANDC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class orc(base.Instruction):
    """ Logical OR of clear (vector) registers.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (cint)
    """
    __slots__ = []
    code = base.opcodes['ORC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class xorc(base.Instruction):
    """ Logical XOR of clear (vector) registers.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (cint)
    """
    __slots__ = []
    code = base.opcodes['XORC']
    arg_format = ['cw','c','c']

@base.vectorize
class notc(base.Instruction):
    """ Clear logical NOT of a constant number of bits of clear
    (vector) register.

    :param: result (cint)
    :param: operand (cint)
    :param: bit length (int)
    """
    __slots__ = []
    code = base.opcodes['NOTC']
    arg_format = ['cw','c', 'int']

@base.vectorize
class gnotc(base.Instruction):
    r""" Clear logical NOT $cg_i = \lnot cg_j$ """
    __slots__ = []
    code = (1 << 8) + base.opcodes['NOTC']
    arg_format = ['cgw','cg']

    def is_gf2n(self):
        return True

@base.vectorize
class gbitdec(base.Instruction):
    r""" Store every $n$-th bit of $cg_i$ in $cg_j, \dots$. """
    __slots__ = []
    code = base.opcodes['GBITDEC']
    arg_format = tools.chain(['cg', 'int'], itertools.repeat('cgw'))

    def is_g2fn(self):
        return True

    def has_var_args(self):
        return True

@base.vectorize
class gbitcom(base.Instruction):
    r""" Store the bits $cg_j, \dots$ as every $n$-th bit of $cg_i$. """
    __slots__ = []
    code = base.opcodes['GBITCOM']
    arg_format = tools.chain(['cgw', 'int'], itertools.repeat('cg'))

    def is_g2fn(self):
        return True

    def has_var_args(self):
        return True


###
### Arithmetic with immediate values
###

@base.gf2n
@base.vectorize
class addci(base.ClearImmediate):
    """ Addition of clear register (vector) and (constant) immediate value.

    :param: result (cint)
    :param: summand (cint)
    :param: summand (int)
    """
    __slots__ = []
    code = base.opcodes['ADDCI']
    op = '__add__'

@base.gf2n
@base.vectorize
class addsi(base.SharedImmediate):
    """ Addition of secret register (vector)  and (constant) immediate value.

    :param: result (cint)
    :param: summand (cint)
    :param: summand (int)
    """
    __slots__ = []
    code = base.opcodes['ADDSI']
    op = '__add__'

@base.gf2n
@base.vectorize
class subci(base.ClearImmediate):
    """ Subtraction of (constant) immediate value from clear register (vector).

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (int)
    """
    __slots__ = []
    code = base.opcodes['SUBCI']
    op = '__sub__'

@base.gf2n
@base.vectorize
class subsi(base.SharedImmediate):
    """ Subtraction of (constant) immediate value from secret
    register (vector).

    :param: result (sint)
    :param: first operand (sint)
    :param: second operand (int)
    """
    __slots__ = []
    code = base.opcodes['SUBSI']
    op = '__sub__'

@base.gf2n
@base.vectorize
class subcfi(base.ClearImmediate):
    """ Subtraction of clear register (vector) from (constant)
    immediate value.

    :param: result (cint)
    :param: first operand (int)
    :param: second operand (cint)
    """
    __slots__ = []
    code = base.opcodes['SUBCFI']
    op = '__rsub__'

@base.gf2n
@base.vectorize
class subsfi(base.SharedImmediate):
    """ Subtraction of secret register (vector) from (constant)
    immediate value.

    :param: result (sint)
    :param: first operand (int)
    :param: second operand (sint)
    """
    __slots__ = []
    code = base.opcodes['SUBSFI']
    op = '__rsub__'

@base.gf2n
@base.vectorize
class mulci(base.ClearImmediate):
    """ Multiplication of clear register (vector) and (constant)
    immediate value.

    :param: result (cint)
    :param: factor (cint)
    :param: factor (int)
    """
    __slots__ = []
    code = base.opcodes['MULCI']
    op = '__mul__'

@base.gf2n
@base.vectorize
class mulsi(base.SharedImmediate):
    """ Multiplication of secret register (vector) and (constant)
    immediate value.

    :param: result (sint)
    :param: factor (sint)
    :param: factor (int)

    """
    __slots__ = []
    code = base.opcodes['MULSI']
    op = '__mul__'

@base.gf2n
@base.vectorize
class divci(base.InvertInstruction, base.ClearImmediate):
    """ Division of secret register (vector) and (constant) immediate value.

    :param: result (cint)
    :param: dividend (cint)
    :param: divisor (int)
    """
    __slots__ = []
    code = base.opcodes['DIVCI']

@base.gf2n
@base.vectorize
class modci(base.ClearImmediate):
    """ Modular reduction of clear register (vector) and (constant)
    immediate value.

    :param: result (cint)
    :param: dividend (cint)
    :param: divisor (int)

    """
    __slots__ = []
    code = base.opcodes['MODCI']
    op = '__mod__'

@base.gf2n
@base.vectorize
class andci(base.ClearImmediate):
    """ Logical AND of clear register (vector) and (constant)
    immediate value.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (int)
    """
    __slots__ = []
    code = base.opcodes['ANDCI']
    op = '__and__'

@base.gf2n
@base.vectorize
class xorci(base.ClearImmediate):
    """ Logical XOR of clear register (vector) and (constant)
    immediate value.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (int)
    """
    __slots__ = []
    code = base.opcodes['XORCI']
    op = '__xor__'

@base.gf2n
@base.vectorize
class orci(base.ClearImmediate):
    """ Logical OR of clear register (vector) and (constant)
    immediate value.

    :param: result (cint)
    :param: operand (cint)
    :param: operand (int)
    """
    __slots__ = []
    code = base.opcodes['ORCI']
    op = '__or__'


###
### Shift instructions
###

@base.gf2n
@base.vectorize
class shlc(base.Instruction):
    """ Bitwise left shift of clear register (vector).

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (cint)
    """
    __slots__ = []
    code = base.opcodes['SHLC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class shrc(base.Instruction):
    """ Bitwise right shift of clear register (vector).

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (cint)
    """
    __slots__ = []
    code = base.opcodes['SHRC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class shlci(base.ClearShiftInstruction):
    """ Bitwise left shift of clear register (vector) by (constant)
    immediate value.

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (int)

    """
    __slots__ = []
    code = base.opcodes['SHLCI']
    op = '__lshift__'

@base.gf2n
@base.vectorize
class shrci(base.ClearShiftInstruction):
    """ Bitwise right shift of clear register (vector) by (constant)
    immediate value.

    :param: result (cint)
    :param: first operand (cint)
    :param: second operand (int)

    """
    __slots__ = []
    code = base.opcodes['SHRCI']
    op = '__rshift__'

@base.gf2n
@base.vectorize
class shrsi(base.ClearShiftInstruction):
    """ Bitwise right shift of secret register (vector) by (constant)
    immediate value. This only makes sense in connection with
    protocols allowing local share conversion (i.e., based on additive
    secret sharing modulo a power of two). Moreover, the result is not
    a secret sharing of the right shift of the secret value but needs
    to be corrected using the overflow. This is explained by `Dalskov
    et al. <https://eprint.iacr.org/2020/1330>`_ in the appendix.

    :param: result (sint)
    :param: first operand (sint)
    :param: second operand (int)

    """
    __slots__ = []
    code = base.opcodes['SHRSI']
    arg_format = ['sw','s','i']

###
### Data access instructions
###

@base.gf2n
@base.vectorize
class triple(base.DataInstruction):
    """ Store fresh random triple(s) in secret register (vectors).

    :param: factor (sint)
    :param: factor (sint)
    :param: product (sint)
    """
    __slots__ = []
    code = base.opcodes['TRIPLE']
    arg_format = ['sw','sw','sw']
    data_type = 'triple'

@base.vectorize
class gbittriple(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next GF(2) multiplication triple. """
    __slots__ = []
    code = base.opcodes['GBITTRIPLE']
    arg_format = ['sgw','sgw','sgw']
    data_type = 'bittriple'
    field_type = 'gf2n'

    def is_gf2n(self):
        return True

@base.vectorize
class gbitgf2ntriple(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next GF(2) and GF(2^n) multiplication triple. """
    code = base.opcodes['GBITGF2NTRIPLE']
    arg_format = ['sgw','sgw','sgw']
    data_type = 'bitgf2ntriple'
    field_type = 'gf2n'

    def is_gf2n(self):
        return True

@base.gf2n
@base.vectorize
class bit(base.DataInstruction):
    """ Store fresh random triple(s) in secret register (vectors).

    :param: destination (sint)
    """
    __slots__ = []
    code = base.opcodes['BIT']
    arg_format = ['sw']
    data_type = 'bit'

@base.vectorize
class dabit(base.DataInstruction):
    """ Store fresh random daBit(s) in secret register (vectors).

    :param: arithmetic part (sint)
    :param: binary part (sbit)
    """
    __slots__ = []
    code = base.opcodes['DABIT']
    arg_format = ['sw', 'sbw']
    field_type = 'modp'
    data_type = 'dabit'

@base.vectorize
class edabit(base.Instruction):
    """ Store fresh random loose edaBit(s) in secret register (vectors).
    The length is the first argument minus one.

    :param: number of arguments to follow / number of bits plus two (int)
    :param: arithmetic (sint)
    :param: binary (sbit)
    :param: (binary)...
    """
    __slots__ = []
    code = base.opcodes['EDABIT']
    arg_format = tools.chain(['sw'], itertools.repeat('sbw'))
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment(('edabit', len(self.args) - 1), self.get_size())

@base.vectorize
class sedabit(base.Instruction):
    """ Store fresh random strict edaBit(s) in secret register (vectors).
    The length is the first argument minus one.

    :param: number of arguments to follow / number of bits plus two (int)
    :param: arithmetic (sint)
    :param: binary (sbit)
    :param: (binary)...
    """
    __slots__ = []
    code = base.opcodes['SEDABIT']
    arg_format = tools.chain(['sw'], itertools.repeat('sbw'))
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment(('sedabit', len(self.args) - 1), self.get_size())

@base.vectorize
class randoms(base.Instruction):
    """ Store fresh length-restricted random shares(s) in secret register
    (vectors). This is only implemented for protocols that also implement
    local share conversion with :py:obj:`~Compiler.GC.instructions.split`.

    :param: destination (sint)
    :param: length (int)
    """
    __slots__ = []
    code = base.opcodes['RANDOMS']
    arg_format = ['sw','int']
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'cut random'), self.get_size())

@base.vectorize
class randomfulls(base.DataInstruction):
    """ Store share(s) of a fresh secret random element in secret
    register (vectors).

    :param: destination (sint)
    """
    __slots__ = []
    code = base.opcodes['RANDOMFULLS']
    arg_format = ['sw']
    field_type = 'modp'
    data_type = 'random'

    def get_repeat(self):
        return len(self.args)

class unsplit(base.VectorInstruction, base.Ciscable):
    """ Bit injection (conversion from binary to arithmetic).

    :param: destination (sint)
    :param: source (sbits)

    """
    __slots__ = []
    code = base.opcodes['UNSPLIT']
    arg_format = tools.chain(['sb'], itertools.repeat('sw'))
    vector_index = 1

    def add_usage(self, req_node):
        n = len(self.args) - 1
        if n == 1:
            name = 'bit2A'
        else:
            name = '%d-way unsplit' % n
        req_node.increment(('modp', name), len(self.args[1]))
        req_node.increment(('modp', '%s round' % name), 1)

@base.gf2n
@base.vectorize
class square(base.DataInstruction):
    """ Store fresh random square(s) in secret register (vectors).

    :param: value (sint)
    :param: square (sint)
    """
    __slots__ = []
    code = base.opcodes['SQUARE']
    arg_format = ['sw','sw']
    data_type = 'square'

@base.gf2n
@base.vectorize
class inverse(base.DataInstruction):
    """ Store fresh random inverse(s) in secret register (vectors).

    :param: value (sint)
    :param: inverse (sint)
    """
    __slots__ = []
    code = base.opcodes['INV']
    arg_format = ['sw','sw']
    data_type = 'inverse'

    def __init__(self, *args, **kwargs):
        if program.options.ring and not self.is_gf2n():
            raise CompilerError('random inverse in ring not implemented')
        base.DataInstruction.__init__(self, *args, **kwargs)

@base.gf2n
@base.vectorize
class inputmask(base.Instruction):
    """ Store fresh random input mask(s) in secret register (vector) and clear
    register (vector) of the relevant player.

    :param: mask (sint)
    :param: mask (cint, player only)
    :param: player (int)
    """
    __slots__ = []
    code = base.opcodes['INPUTMASK']
    arg_format = ['sw', 'cw', 'p']
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'input', self.args[2]), \
                               self.get_size())

@base.vectorize
class inputmaskreg(base.Instruction):
    """ Store fresh random input mask(s) in secret register (vector) and clear
    register (vector) of the relevant player.

    :param: mask (sint)
    :param: mask (cint, player only)
    :param: player (regint)
    """
    __slots__ = []
    code = base.opcodes['INPUTMASKREG']
    arg_format = ['sw', 'cw', 'ci']
    field_type = 'modp'

    def add_usage(self, req_node):
        # player 0 as proxy
        req_node.increment((self.field_type, 'input', 0), float('inf'))

@base.gf2n
@base.vectorize
class prep(base.Instruction):
    """ Store custom preprocessed data in secret register (vectors).

    :param: number of arguments to follow (int)
    :param: tag (16 bytes / 4 units, cut off at first zero byte)
    :param: destination (sint)
    :param: (repeat destination)...
    """
    __slots__ = []
    code = base.opcodes['PREP']
    arg_format = tools.chain(['str'], itertools.repeat('sw'))
    gf2n_arg_format = tools.chain(['str'], itertools.repeat('sgw'))
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'prep', self.args[0]),
                           self.get_size())

    def has_var_args(self):
        return True

###
### I/O
###

@base.gf2n
@base.vectorize
class asm_input(base.TextInputInstruction):
    r""" Receive input from player $p$ and put in register $s_i$. """
    __slots__ = []
    code = base.opcodes['INPUT']
    arg_format = tools.cycle(['sw', 'p'])
    field_type = 'modp'

    def get_players(self):
        return self.args[1::2]

@base.vectorize
class inputfix(base.TextInputInstruction):
    __slots__ = []
    code = base.opcodes['INPUTFIX']
    arg_format = tools.cycle(['sw', 'int', 'p'])
    field_type = 'modp'

    def get_players(self):
        return self.args[2::3]

@base.vectorize
class inputfloat(base.TextInputInstruction):
    __slots__ = []
    code = base.opcodes['INPUTFLOAT']
    arg_format = tools.cycle(['sw', 'sw', 'sw', 'sw', 'int', 'p'])
    field_type = 'modp'

    def add_usage(self, req_node):
        for player in self.args[5::6]:
            req_node.increment((self.field_type, 'input', player), \
                               4 * self.get_size())

class inputmixed_base(base.TextInputInstruction, base.DynFormatInstruction):
    __slots__ = []
    field_type = 'modp'
    # the following has to match TYPE: (N_DEST, N_PARAM)
    types = {
        0: (1, 0),
        1: (1, 1),
        2: (4, 1)
    }
    type_ids = {
        'int': 0,
        'fix': 1,
        'float': 2
    }

    def __init__(self, name, *args):
        type_id = self.type_ids[name]
        super(inputmixed_base, self).__init__(type_id, *args)

    @classmethod
    def dynamic_arg_format(self, args):
        yield 'int'
        for i, t in self.bases(iter(args)):
            for j in range(self.types[t][0]):
                yield 'sw'
            for j in range(self.types[t][1]):
                yield 'int'
            yield self.player_arg_type
            yield 'int'

    @classmethod
    def bases(self, args):
        i = 0
        while True:
            try:
                t = next(args)
            except StopIteration:
                return
            yield i, t
            n = sum(self.types[t])
            i += n + 2
            for j in range(n + 1):
                next(args)

@base.vectorize
class inputmixed(inputmixed_base):
    """ Store private input in secret registers (vectors). The input is
    read as integer or floating-point number and the latter is then
    converted to the internal representation using the given precision.
    This instruction uses compile-time player numbers.

    :param: number of arguments to follow (int)
    :param: type (0: integer, 1: fixed-point, 2: floating-point)
    :param: destination (sint)
    :param: destination (sint, only for floating-point)
    :param: destination (sint, only for floating-point)
    :param: destination (sint, only for floating-point)
    :param: fixed-point precision or precision of floating-point significand (int, not with integer)
    :param: input player (int)
    :param: (repeat from type parameter)...

    """
    code = base.opcodes['INPUTMIXED']
    player_arg_type = 'p'

    def add_usage(self, req_node):
        for i, t in self.bases(iter(self.args)):
            player = self.args[i + sum(self.types[t]) + 1]
            n_dest = self.types[t][0]
            req_node.increment((self.field_type, 'input', player), \
                               n_dest * self.get_size())

    def get_players(self):
        for i, t in self.bases(iter(self.args)):
            yield self.args[i + sum(self.types[t]) + 1]

class inputmixedreg(inputmixed_base):
    """ Store private input in secret registers (vectors). The input is
    read as integer or floating-point number and the latter is then
    converted to the internal representation using the given precision.
    This instruction uses run-time player numbers.

    :param: number of arguments to follow (int)
    :param: type (0: integer, 1: fixed-point, 2: floating-point)
    :param: destination (sint)
    :param: destination (sint, only for floating-point)
    :param: destination (sint, only for floating-point)
    :param: destination (sint, only for floating-point)
    :param: fixed-point precision or precision of floating-point significand (int, not with integer)
    :param: input player (regint)
    :param: (repeat from type parameter)...

    """
    code = base.opcodes['INPUTMIXEDREG']
    player_arg_type = 'ci'
    is_vec = lambda self: True

    def __init__(self, *args):
        inputmixed_base.__init__(self, *args)
        for i, t in self.bases(iter(self.args)):
            n = self.types[t][0]
            for j in range(i + 1, i + 1 + n):
                assert args[j].size == self.get_size()

    def get_size(self):
        return self.args[1].size

    def get_code(self):
        return inputmixed_base.get_code(
            self, self.get_size() if self.get_size() > 1 else 0)

    def add_usage(self, req_node):
        # player 0 as proxy
        req_node.increment((self.field_type, 'input', 0), float('inf'))

    def get_players(self):
        pass

@base.gf2n
@base.vectorize
class rawinput(base.RawInputInstruction, base.Mergeable):
    """ Store private input in secret registers (vectors). The input is
    read in the internal binary format according to the protocol.

    :param: number of arguments to follow (multiple of two)
    :param: player number (int)
    :param: destination (sint)
    """
    __slots__ = []
    code = base.opcodes['RAWINPUT']
    arg_format = tools.cycle(['p','sw'])
    field_type = 'modp'

    def add_usage(self, req_node):
        for i in range(0, len(self.args), 2):
            player = self.args[i]
            req_node.increment((self.field_type, 'input', player), \
                               self.get_size())

class personal_base(base.Instruction, base.Mergeable):
    __slots__ = []
    field_type = 'modp'

    def __init__(self, *args):
        super(personal_base, self).__init__(*args)
        for i in range(0, len(args), 4):
            assert args[i + 2].size == args[i]
            assert args[i + 3].size == args[i]

    def add_usage(self, req_node):
        for i in range(0, len(self.args), 4):
            player = self.args[i + 1]
            req_node.increment((self.field_type, 'input', player), \
                               self.args[i])

class inputpersonal(personal_base):
    """ Private input from cint.

    :param: vector size (int)
    :param: player (int)
    :param: destination (sint)
    :param: source (cint)
    :param: (repeat from vector size)...
    """
    __slots__ = []
    code = base.opcodes['INPUTPERSONAL']
    arg_format = tools.cycle(['int','p','sw','c'])

class privateoutput(personal_base, base.DataInstruction):
    """ Private output to cint.

    :param: vector size (int)
    :param: player (int)
    :param: destination (cint)
    :param: source (sint)
    :param: (repeat from vector size)...
    """
    __slots__ = []
    code = base.opcodes['PRIVATEOUTPUT']
    arg_format = tools.cycle(['int','p','cw','s'])
    data_type = 'open'

    def add_usage(self, req_node):
        personal_base.add_usage(self, req_node)
        base.DataInstruction.add_usage(self, req_node)

    def get_repeat(self):
        return sum(self.args[::4])

class sendpersonal(base.Instruction, base.Mergeable):
    """ Private input from cint.

    :param: vector size (int)
    :param: destination player (int)
    :param: destination (cint)
    :param: source player (int)
    :param: source (cint)
    :param: (repeat from vector size)...
    """
    __slots__ = []
    code = base.opcodes['SENDPERSONAL']
    arg_format = tools.cycle(['int','p','cw','p','c'])

    def __init__(self, *args):
        super(sendpersonal, self).__init__(*args)
        for i in range(0, len(args), 5):
            assert args[i + 2].size == args[i]
            assert args[i + 4].size == args[i]

@base.gf2n
@base.vectorize
class print_reg(base.IOInstruction):
    """ Debugging output of clear register (vector).

    :param: source (cint)
    :param: comment (4 bytes / 1 unit)
    """
    __slots__ = []
    code = base.opcodes['PRINTREG']
    arg_format = ['c','i']
    
    def __init__(self, reg, comment=''):
        super(print_reg_class, self).__init__(reg, self.str_to_int(comment))

@base.gf2n
@base.vectorize
class print_reg_plain(base.IOInstruction):
    """ Output clear register.

    :param: source (cint)
    """
    __slots__ = []
    code = base.opcodes['PRINTREGPLAIN']
    arg_format = ['c']

@base.gf2n
class print_reg_plains(base.IOInstruction):
    """ Output secret register.

    :param: source (sint)

    """
    __slots__ = []
    code = base.opcodes['PRINTREGPLAINS']
    arg_format = ['s']

class cond_print_plain(base.IOInstruction):
    r""" Conditionally output clear register (with precision).
    Outputs :math:`x \cdot 2^p` where :math:`p` is the precision.

    :param: condition (cint, no output if zero)
    :param: source (cint)
    :param: precision (cint)
    """
    code = base.opcodes['CONDPRINTPLAIN']
    arg_format = ['c', 'c', 'c']

    def __init__(self, *args, **kwargs):
        base.Instruction.__init__(self, *args, **kwargs)
        self.size = args[1].size
        args[2].set_size(self.size)

    def get_code(self):
        return base.Instruction.get_code(self, self.size)

class print_int(base.IOInstruction):
    """ Output clear integer register.

    :param: source (regint)
    """
    __slots__ = []
    code = base.opcodes['PRINTINT']
    arg_format = ['ci']

@base.vectorize
class print_float_plain(base.IOInstruction):
    """ Output floating-number from clear registers.

    :param: significand (cint)
    :param: exponent (cint)
    :param: zero bit (cint, zero output if bit is one)
    :param: sign bit (cint, negative output if bit is one)
    :param: NaN (cint, regular number if zero)
    """
    __slots__ = []
    code = base.opcodes['PRINTFLOATPLAIN']
    arg_format = ['c', 'c', 'c', 'c', 'c']

class print_float_prec(base.IOInstruction):
    """ Set number of digits after decimal point for
    :py:obj:`~Compiler.instructions.print_float_plain`.

    :param: number of digits (int)
    """
    __slots__ = []
    code = base.opcodes['PRINTFLOATPREC']
    arg_format = ['int']

class print_char(base.IOInstruction):
    """ Output a single byte.

    :param: byte (int)
    """
    code = base.opcodes['PRINTCHR']
    arg_format = ['int']

    def __init__(self, ch):
        super(print_char, self).__init__(ch)

class print_char4(base.IOInstruction):
    """ Output four bytes.

    :param: four bytes (int)
    """
    code = base.opcodes['PRINTSTR']
    arg_format = ['int']

    def __init__(self, val):
        super(print_char4, self).__init__(self.str_to_int(val))

class cond_print_str(base.IOInstruction):
    """ Conditionally output four bytes.

    :param: condition (cint, no output if zero)
    :param: four bytes (int)
    """
    code = base.opcodes['CONDPRINTSTR']
    arg_format = ['c', 'int']

    def __init__(self, cond, val):
        super(cond_print_str, self).__init__(cond, self.str_to_int(val))

@base.vectorize
class pubinput(base.PublicFileIOInstruction):
    """ Store public input in clear register (vector).

    :param: destination (cint)
    """
    __slots__ = []
    code = base.opcodes['PUBINPUT']
    arg_format = ['cw']

class readsocketc(base.IOInstruction):
    """ Read a variable number of clear values in internal representation
    from socket for a specified client id and store them in clear registers.

    :param: number of arguments to follow / number of inputs minus one (int)
    :param: client id (regint)
    :param: vector size (int)
    :param: destination (cint)
    :param: (repeat destination)...
    """
    __slots__ = []
    code = base.opcodes['READSOCKETC']
    arg_format = tools.chain(['ci','int'], itertools.repeat('cw'))

    def has_var_args(self):
        return True

class readsockets(base.IOInstruction):
    """ Read a variable number of secret shares (potentially with MAC)
    from a socket for a client id and store them in registers. If the
    protocol uses MACs, the client should be different for every party.

    :param: client id (regint)
    :param: vector size (int)
    :param: source (sint)
    :param: (repeat source)...

    """
    __slots__ = []
    code = base.opcodes['READSOCKETS']
    arg_format = tools.chain(['ci','int'], itertools.repeat('sw'))

    def has_var_args(self):
        return True

class readsocketint(base.IOInstruction):
    """ Read a variable number of 32-bit integers from socket for a
    specified client id and store them in clear integer registers.

    :param: number of arguments to follow / number of inputs minus one (int)
    :param: client id (regint)
    :param: vector size (int)
    :param: destination (regint)
    :param: (repeat destination)...
    """
    __slots__ = []
    code = base.opcodes['READSOCKETINT']
    arg_format = tools.chain(['ci','int'], itertools.repeat('ciw'))

    def has_var_args(self):
        return True

class writesocketc(base.IOInstruction):
    """
    Write a variable number of clear GF(p) values from registers into socket 
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETC']
    arg_format = tools.chain(['ci', 'int', 'int'], itertools.repeat('c'))

    def has_var_args(self):
        return True

class writesockets(base.IOInstruction):
    """ Write a variable number of secret shares (potentially with MAC)
    from registers into a socket for a specified client id. If the
    protocol uses MACs, the client should be different for every party.

    :param: number of arguments to follow
    :param: client id (regint)
    :param: message type (must be 0)
    :param: vector size (int)
    :param: source (sint)
    :param: (repeat source)...

    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETS']
    arg_format = tools.chain(['ci', 'int', 'int'], itertools.repeat('s'))

    def has_var_args(self):
        return True

class writesocketshare(base.IOInstruction):
    """ Write a variable number of shares (without MACs) from secret
    registers into socket for a specified client id.

    :param: client id (regint)
    :param: message type (must be 0)
    :param: vector size (int)
    :param: source (sint)
    :param: (repeat source)...
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETSHARE']
    arg_format = tools.chain(['ci', 'int', 'int'], itertools.repeat('s'))

    def has_var_args(self):
        return True

class writesocketint(base.IOInstruction):
    """
    Write a variable number of 32-bit ints from registers into socket
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETINT']
    arg_format = tools.chain(['ci', 'int', 'int'], itertools.repeat('ci'))

    def has_var_args(self):
        return True

class listen(base.IOInstruction):
    """ Open a server socket on a party-specific port number and listen for
    client connections (non-blocking).

    :param: port number (regint)
    """
    __slots__ = []
    code = base.opcodes['LISTEN']
    arg_format = ['ci']

class acceptclientconnection(base.IOInstruction):
    """ Wait for a connection at the given port and write socket handle
    to clear integer register.

    :param: client id destination (regint)
    :param: port number (regint)
    """
    __slots__ = []
    code = base.opcodes['ACCEPTCLIENTCONNECTION']
    arg_format = ['ciw', 'ci']

class initclientconnection(base.IOInstruction):
    """ Initialize connection.

    :param: client id destination (regint)
    :param: port number (regint)
    :param: my client id (regint)
    :param: hostname (variable string)

    """
    __slots__ = []
    code = base.opcodes['INITCLIENTCONNECTION']
    arg_format = ['ciw', 'ci', 'ci', 'varstr']

class closeclientconnection(base.IOInstruction):
    """ Close connection to client.

    :param: client id (regint)
    """
    __slots__ = []
    code = base.opcodes['CLOSECLIENTCONNECTION']
    arg_format = ['ci']

@base.gf2n
class writesharestofile(base.VectorInstruction, base.IOInstruction):
    """ Write shares to ``Persistence/Transactions-P<playerno>.data``
    (appending at the end).

    :param: number of arguments to follow / number of shares plus one (int)
    :param: position (regint, -1 for appending)
    :param: source (sint)
    :param: (repeat from source)...

    """
    __slots__ = []
    code = base.opcodes['WRITEFILESHARE']
    arg_format = tools.chain(['ci'], tools.cycle(['s']))
    vector_index = 1

    def has_var_args(self):
        return True

@base.gf2n
class readsharesfromfile(base.VectorInstruction, base.IOInstruction):
    """ Read shares from ``Persistence/Transactions-P<playerno>.data``.

    :param: number of arguments to follow / number of shares plus two (int)
    :param: starting position in number of shares from beginning (regint)
    :param: destination for final position, -1 for eof reached, or -2 for file not found (regint)
    :param: destination for share (sint)
    :param: (repeat from destination for share)...
    """
    __slots__ = []
    code = base.opcodes['READFILESHARE']
    arg_format = tools.chain(['ci', 'ciw'], tools.cycle(['sw']))
    vector_index = 2

    def has_var_args(self):
        return True

@base.gf2n
@base.vectorize
class raw_output(base.PublicFileIOInstruction):
    r""" Raw output of register \verb|ci| to file. """
    __slots__ = []
    code = base.opcodes['RAWOUTPUT']
    arg_format = ['c']

@base.vectorize
class intoutput(base.PublicFileIOInstruction):
    """ Binary integer output.

    :param: player (int)
    :param: regint
    """
    __slots__ = []
    code = base.opcodes['INTOUTPUT']
    arg_format = ['p','ci']

@base.vectorize
class floatoutput(base.PublicFileIOInstruction):
    """ Binary floating-point output.

    :param: player (int)
    :param: significand (cint)
    :param: exponent (cint)
    :param: zero bit (cint)
    :param: sign bit (cint)
    """
    __slots__ = []
    code = base.opcodes['FLOATOUTPUT']
    arg_format = ['p','c','c','c','c']

@base.vectorize
class fixinput(base.PublicFileIOInstruction):
    """ Binary fixed-point input.

    :param: player (int)
    :param: destination (cint)
    :param: exponent (int, for float/double) / byte length (1/8, for integer)
    :param: input type (0: 64-bit integer, 1: float, 2: double)

    """
    __slots__ = []
    code = base.opcodes['FIXINPUT']
    arg_format = ['p','cw','int','int']

@base.vectorize
class rand(base.Instruction):
    """ Store insecure random value of specified length in clear integer
    register (vector).

    :param: destination (regint)
    :param: length (regint)
    """
    __slots__ = []
    code = base.opcodes['RAND']
    arg_format = ['ciw','ci']

###
### Integer operations
### 

@base.vectorize
class ldint(base.Instruction):
    """ Store (constant) immediate value in clear integer register (vector).

    :param: destination (regint)
    :param: immediate (int)
    """
    __slots__ = []
    code = base.opcodes['LDINT']
    arg_format = ['ciw', 'i']

@base.vectorize
class addint(base.IntegerInstruction):
    """ Clear integer register (vector) addition.

    :param: result (regint)
    :param: summand (regint)
    :param: summand (regint)
    """
    __slots__ = []
    code = base.opcodes['ADDINT']
    op = operator.add

@base.vectorize
class subint(base.IntegerInstruction):
    """ Clear integer register (vector) subtraction.

    :param: result (regint)
    :param: first operand (regint)
    :param: second operand (regint)
    """
    __slots__ = []
    code = base.opcodes['SUBINT']
    op = operator.sub

@base.vectorize
class mulint(base.IntegerInstruction):
    """ Clear integer register (element-wise vector) multiplication.

    :param: result (regint)
    :param: factor (regint)
    :param: factor (regint)
    """
    __slots__ = []
    code = base.opcodes['MULINT']
    op = operator.mul

@base.vectorize
class divint(base.IntegerInstruction):
    """ Clear integer register (element-wise vector) division with floor
    rounding.

    :param: result (regint)
    :param: dividend (regint)
    :param: divisor (regint)
    """
    __slots__ = []
    code = base.opcodes['DIVINT']
    op = operator.floordiv

@base.vectorize
class bitdecint(base.Instruction):
    """ Clear integer bit decomposition.

    :param: number of arguments to follow / number of bits minus one (int)
    :param: source (regint)
    :param: destination for least significant bit (regint)
    :param: (destination for one bit higher)...
    """
    __slots__ = []
    code = base.opcodes['BITDECINT']
    arg_format = tools.chain(['ci'], itertools.repeat('ciw'))

class incint(base.VectorInstruction):
    """ Create incremental clear integer vector. For example, vector size 10,
    base 1, increment 2, repeat 3, and wrap 2 produces the following::

        (1, 1, 1, 3, 3, 3, 1, 1, 1, 3)

    This is because the first number is always the :py:obj:`base`,
    every number is repeated :py:obj:`repeat` times, after which
    :py:obj:`increment` is added, and after :py:obj:`wrap` increments
    the number returns to :py:obj:`base`.

    :param: destination (regint)
    :param: base (non-vector regint)
    :param: increment (int)
    :param: repeat (int)
    :param: wrap (int)

    """
    __slots__ = []
    code = base.opcodes['INCINT']
    arg_format = ['ciw', 'ci', 'i', 'i', 'i']

    def __init__(self, *args, **kwargs):
        assert len(args[1]) == 1
        if len(args) == 3:
            args = list(args) + [1, len(args[0])]
        super(incint, self).__init__(*args, **kwargs)

class shuffle(base.VectorInstruction):
    """ Randomly shuffles clear integer vector with public randomness.

    :param: destination (regint)
    :param: source (regint)
    """
    __slots__ = []
    code = base.opcodes['SHUFFLE']
    arg_format = ['ciw','ci']

    def __init__(self, *args, **kwargs):
        super(shuffle, self).__init__(*args, **kwargs)
        assert len(args[0]) == len(args[1])

###
### Clear comparison instructions
###

@base.vectorize
class eqzc(base.UnaryComparisonInstruction):
    """ Clear integer zero test. The result is 1 for true and 0 for false.

    :param: destination (regint)
    :param: operand (regint)
    """
    __slots__ = []
    code = base.opcodes['EQZC']

@base.vectorize
class ltzc(base.UnaryComparisonInstruction):
    """ Clear integer less than zero test. The result is 1 for true
    and 0 for false.

    :param: destination (regint)
    :param: operand (regint)
    """
    __slots__ = []
    code = base.opcodes['LTZC']

@base.vectorize
class ltc(base.IntegerInstruction):
    """ Clear integer less-than comparison. The result is 1 if the
    first operand is less and 0 otherwise.

    :param: destination (regint)
    :param: first operand (regint)
    :param: second operand (regint)
    """
    __slots__ = []
    code = base.opcodes['LTC']
    op = operator.lt

@base.vectorize
class gtc(base.IntegerInstruction):
    """ Clear integer greater-than comparison. The result is 1 if the
    first operand is greater and 0 otherwise.

    :param: destination (regint)
    :param: first operand (regint)
    :param: second operand (regint)
    """
    __slots__ = []
    code = base.opcodes['GTC']
    op = operator.gt

@base.vectorize
class eqc(base.IntegerInstruction):
    """ Clear integer equality test. The result is 1 if the operands
    are equal and 0 otherwise.

    :param: destination (regint)
    :param: first operand (regint)
    :param: second operand (regint)
    """
    __slots__ = []
    code = base.opcodes['EQC']
    op = operator.eq


###
### Jumps etc
###

class jmp(base.JumpInstruction):
    """ Unconditional relative jump in the bytecode (compile-time parameter).
    The parameter is added to the regular jump of one after every
    instruction. This means that a jump of 0 results in a no-op while
    a jump of -1 results in an infinite loop.

    :param: number of instructions (int)
    """
    __slots__ = []
    code = base.opcodes['JMP']
    arg_format = ['int']
    jump_arg = 0

class jmpi(base.JumpInstruction):
    """ Unconditional relative jump in the bytecode (run-time parameter).
    The parameter is added to the regular jump of one after every
    instruction. This means that a jump of 0 results in a no-op while
    a jump of -1 results in an infinite loop.

    :param: number of instructions (regint)
    """
    __slots__ = []
    code = base.opcodes['JMPI']
    arg_format = ['ci']
    jump_arg = 0

class jmpnz(base.JumpInstruction):
    """ Conditional relative jump in the bytecode.
    The parameter is added to the regular jump of one after every
    instruction. This means that a jump of 0 results in a no-op while
    a jump of -1 results in an infinite loop.

    :param: condition (regint, only jump if not zero)
    :param: number of instructions (int)
    """
    __slots__ = []
    code = base.opcodes['JMPNZ']
    arg_format = ['ci', 'int']
    jump_arg = 1

class jmpeqz(base.JumpInstruction):
    """ Conditional relative jump in the bytecode.
    The parameter is added to the regular jump of one after every
    instruction. This means that a jump of 0 results in a no-op while
    a jump of -1 results in an infinite loop.

    :param: condition (regint, only jump if zero)
    :param: number of instructions (int)
    """
    __slots__ = []
    code = base.opcodes['JMPEQZ']
    arg_format = ['ci', 'int']
    jump_arg = 1

###
### Conversions
###

@base.gf2n
@base.vectorize
class convint(base.Instruction):
    """ Convert clear integer register (vector) to clear register (vector).

    :param: destination (cint)
    :param: source (regint)
    """
    __slots__ =  []
    code = base.opcodes['CONVINT']
    arg_format = ['cw', 'ci']

@base.vectorize
class convmodp(base.Instruction):
    r""" Convert clear integer register (vector) to clear register
    (vector). If the bit length is zero, the unsigned conversion is
    used, otherwise signed conversion is used. This makes a difference
    when computing modulo a prime :math:`p`. Signed conversion of
    :math:`p-1` results in -1 while signed conversion results in
    :math:`(p-1) \mod 2^{64}`.

    :param: destination (regint)
    :param: source (cint)
    :param: synchronize (int)
    :param: bit length (int)

    """
    __slots__ =  []
    code = base.opcodes['CONVMODP']
    arg_format = ['ciw', 'c', 'int', 'int']
    def __init__(self, *args, **kwargs):
        if len(args) == len(self.arg_format):
            super(convmodp_class, self).__init__(*args)
            return
        bitlength = kwargs.get('bitlength')
        bitlength = program.bit_length if bitlength is None else bitlength
        if bitlength > 64:
            raise CompilerError('%d-bit conversion requested ' \
                                'but integer registers only have 64 bits' % \
                                bitlength)
        super(convmodp_class, self).__init__(*(args + (bitlength,)))

@base.vectorize
class gconvgf2n(base.Instruction):
    """ Convert from clear modp register $c_j$ to integer register $ci_i$. """
    __slots__ =  []
    code = base.opcodes['GCONVGF2N']
    arg_format = ['ciw', 'cg']

###
### Other instructions
###

# rename 'open' to avoid conflict with built-in open function
@base.gf2n
@base.vectorize
class asm_open(base.VarArgsInstruction, base.DataInstruction):
    """ Reveal secret registers (vectors) to clear registers (vectors).

    :param: number of argument to follow (odd number)
    :param: check after opening (0/1)
    :param: destination (cint)
    :param: source (sint)
    :param: (repeat the last two)...
    """
    __slots__ = []
    code = base.opcodes['OPEN']
    arg_format = tools.chain(['int'], tools.cycle(['cw','s']))
    data_type = 'open'

    def get_repeat(self):
        return (len(self.args) - 1) // 2

    def merge(self, other):
        self.args[0] |= other.args[0]
        self.args += other.args[1:]

class mul_base(base.VarArgsInstruction, base.DataInstruction):
    def add_usage(self, req_node):
        super(mul_base, self).add_usage(req_node)
        req_node.increment((self.field_type, 'simple multiplication'),
                           self.get_repeat() * self.get_size())

@base.gf2n
class muls(mul_base, base.Ciscable):
    """ (Element-wise) multiplication of secret registers (vectors).

    :param: number of arguments to follow (multiple of four)
    :param: vector size (int)
    :param: result (sint)
    :param: factor (sint)
    :param: factor (sint)
    :param: (repeat the last four)...
    """
    __slots__ = []
    code = base.opcodes['MULS']
    arg_format = tools.cycle(['int','sw','s','s'])
    data_type = 'triple'
    is_vec = lambda self: True

    def __init__(self, *args, **kwargs):
        super(muls_class, self).__init__(*args, **kwargs)
        for i in range(0, len(args), 4):
            for j in range(3):
                assert args[i + j + 1].size == args[i]

    def get_repeat(self):
        return sum(self.args[::4])

    # def expand(self):
    #     s = [program.curr_block.new_reg('s') for i in range(9)]
    #     c = [program.curr_block.new_reg('c') for i in range(3)]
    #     triple(s[0], s[1], s[2])
    #     subs(s[3], self.args[1], s[0])
    #     subs(s[4], self.args[2], s[1])
    #     asm_open(c[0], s[3])
    #     asm_open(c[1], s[4])
    #     mulm(s[5], s[1], c[0])
    #     mulm(s[6], s[0], c[1])
    #     mulc(c[2], c[0], c[1])
    #     adds(s[7], s[2], s[5])
    #     adds(s[8], s[7], s[6])
    #     addm(self.args[0], s[8], c[2])

# compatibility
try:
    vmuls = muls_class
    muls_bak = muls
    muls = lambda *args: muls_bak(args[0].size, *args)
    vgmuls = gmuls_class = gmuls
    gmuls = lambda *args: gmuls_class(args[0].size, *args)
except NameError:
    pass

@base.gf2n
class mulrs(mul_base):
    """ Constant-vector multiplication of secret registers.

    :param: number of arguments to follow (multiple of four)
    :param: vector size (int)
    :param: result (sint)
    :param: vector factor (sint)
    :param: constant factor (sint)
    :param: (repeat the last four)...
    """
    __slots__ = []
    code = base.opcodes['MULRS']
    arg_format = tools.cycle(['int','sw','s','s'])
    data_type = 'triple'
    is_vec = lambda self: True

    def __init__(self, res, x, y):
        assert y.size == 1
        assert res.size == x.size
        base.Instruction.__init__(self, res.size, res, x, y)

    def get_repeat(self):
        return sum(self.args[::4])

    def get_def(self):
        return sum((arg.get_all() for arg in self.args[1::4]), [])

    def get_used(self):
        return sum((arg.get_all()
                    for arg in self.args[2::4] + self.args[3::4]), [])

@base.gf2n
@base.vectorize
class dotprods(base.VarArgsInstruction, base.DataInstruction,
               base.DynFormatInstruction):
    """ Dot product of secret registers (vectors).
    Note that the vectorized version works element-wise.

    :param: number of arguments to follow (int)
    :param: twice the dot product length plus two (I know...)
    :param: result (sint)
    :param: first factor (sint)
    :param: first factor (sint)
    :param: second factor (sint)
    :param: second factor (sint)
    :param: (remaining factors)...
    :param: (repeat from dot product length)...
    """
    __slots__ = []
    code = base.opcodes['DOTPRODS']
    data_type = 'triple'

    def __init__(self, *args):
        flat_args = []
        for i in range(0, len(args), 3):
            res, x, y = args[i:i+3]
            assert len(x) == len(y)
            flat_args += [2 * len(x) + 2, res]
            for x, y in zip(x, y):
                flat_args += [x, y]
        base.Instruction.__init__(self, *flat_args)

    @classmethod
    def dynamic_arg_format(self, args):
        field = 'g' if self.is_gf2n() else ''
        yield 'int'
        for i, n in self.bases(args):
            yield 's' + field + 'w'
            assert n > 2
            for j in range(n - 2):
                yield 's' + field
            yield 'int'

    def get_repeat(self):
        return sum(self.args[i] // 2 - 1
                   for i, n in self.bases(iter(self.args)))

    def get_def(self):
        return [self.args[i + 1] for i, n in self.bases(iter(self.args))]

    def get_used(self):
        for i, n in self.bases(iter(self.args)):
            for reg in self.args[i + 2:i + self.args[i]]:
                yield reg

    def add_usage(self, req_num):
        base.DataInstruction.add_usage(self, req_num)
        req_num.increment(
            (self.field_type, 'dot product'),
            self.get_size() * len(list(self.bases(iter(self.args)))))

class matmul_base(base.DataInstruction):
    data_type = 'triple'
    is_vec = lambda self: True

    def get_repeat(self):
        return reduce(operator.mul, self.args[3:6])

@base.gf2n
class matmuls(matmul_base, base.Mergeable):
    """ Secret matrix multiplication from registers. All matrices are
    represented as vectors in row-first order.

    :param: result (sint vector)
    :param: first factor (sint vector)
    :param: second factor (sint vector)
    :param: number of rows in first factor and result (int)
    :param: number of columns in first factor and rows in second factor (int)
    :param: number of columns in second factor and result (int)
    """
    code = base.opcodes['MATMULS']
    arg_format = tools.cycle(['sw','s','s','int','int','int'])

    def get_repeat(self):
        return sum(reduce(operator.mul, self.args[i + 3:i + 6])
                   for i in range(0, len(self.args), 6))

    def add_usage(self, req_node):
        super(matmuls_class, self).add_usage(req_node)
        for i in range(0, len(self.args), 6):
            req_node.increment(('matmul', (self.args[i + 3], self.args[i + 4],
                                           self.args[i + 5])), 1)
            req_node.increment(('modp', 'dot product'),
                               self.args[i + 3] * self.args[i + 5])

@base.gf2n
class matmulsm(matmul_base, base.Mergeable):
    """ Secret matrix multiplication reading directly from memory.

    :param: result (sint vector in row-first order)
    :param: base address of first factor (regint value)
    :param: base address of second factor (regint value)
    :param: number of rows in first factor and result (int)
    :param: number of columns in first factor and rows in second factor (int)
    :param: number of columns in second factor and result (int)
    :param: rows of first factor to use (regint vector, length as number of rows in first factor)
    :param: columns of first factor to use (regint vector, length as number of columns in the first factor)
    :param: rows of second factor to use (regint vector, length as number of columns in the first factor)
    :param: columns of second factor to use (regint vector, length as number of columns in the second factor)
    :param: total number of columns in the first factor, equal to used number of columns when all columns are used (int)
    :param: total number of columns in the second factor, equal to used number of columns when all columns are used (int)
    """
    code = base.opcodes['MATMULSM']
    arg_format = tools.cycle(['sw','ci','ci','int','int','int','ci','ci','ci','ci',
                              'int','int'])

    def __init__(self, *args,
                 first_factor_base_addresses=None,
                 second_factor_base_addresses=None,
                 indices_values=None,
                 **kwargs):
        matmul_base.__init__(self, *args, **kwargs)
        for matmul_index in range(len(args) // 12):
            for i in range(2):
                assert args[12 * matmul_index + 6 + i].size == args[12 * matmul_index + 3 + i]
            for i in range(2):
                assert args[12 * matmul_index + 8 + i].size == args[12 * matmul_index + 4 + i]

        # These are used to reconstruct that accessed memory addresses in the allocator.
        self.first_factor_base_addresses = first_factor_base_addresses
        self.second_factor_base_addresses = second_factor_base_addresses
        self.indices_values = indices_values

        if first_factor_base_addresses is not None:
            assert len(first_factor_base_addresses) == len(second_factor_base_addresses)
            if indices_values is not None:
                assert len(indices_values) == 4 * len(first_factor_base_addresses)

    def add_usage(self, req_node):
        super(matmulsm_class, self).add_usage(req_node)
        for i in range(0, len(self.args), 12):
            req_node.increment(('matmul', (self.args[i + 3], self.args[i + 4], self.args[i + 5])), 1)
            req_node.increment(('modp', 'dot product'),
                               self.args[i + 3] * self.args[i + 5])

    def get_repeat(self):
        return sum(reduce(operator.mul, self.args[i + 3:i + 6])
                   for i in range(0, len(self.args), 12))

class conv2ds(base.DataInstruction, base.VarArgsInstruction, base.Mergeable):
    """ Secret 2D convolution.

    :param: number of arguments to follow (int)
    :param: result (sint vector in row-first order)
    :param: inputs (sint vector in row-first order)
    :param: weights (sint vector in row-first order)
    :param: output height (int)
    :param: output width (int)
    :param: input height (int)
    :param: input width (int)
    :param: weight height (int)
    :param: weight width (int)
    :param: stride height (int)
    :param: stride width (int)
    :param: number of channels (int)
    :param: padding height (int)
    :param: padding width (int)
    :param: batch size (int)
    :param: repeat from result...

    """
    code = base.opcodes['CONV2DS']
    arg_format = itertools.cycle(['sw','s','s','int','int','int','int','int',
                                  'int','int','int','int','int','int','int'])
    data_type = 'triple'
    is_vec = lambda self: True

    def __init__(self, *args, **kwargs):
        super(conv2ds, self).__init__(*args, **kwargs)
        assert args[0].size == args[3] * args[4] * args[14]
        assert args[1].size == args[5] * args[6] * args[11] * args[14]
        assert args[2].size == args[7] * args[8] * args[11]

    def get_repeat(self):
        args = self.args
        return sum(args[i+3] * args[i+4] * args[i+7] * args[i+8] * \
            args[i+11] * args[i+14] for i in range(0, len(args), 15))

    def add_usage(self, req_node):
        super(conv2ds, self).add_usage(req_node)
        for i in range(0, len(self.args), 15):
            args = self.args[i:i + 15]
            req_node.increment(('matmul', (1, args[7] * args[8] * args[11],
                                           args[14] * args[3] * args[4])), 1)
            req_node.increment(('modp', 'dot product'),
                               args[14] * args[3] * args[4])

@base.vectorize
class trunc_pr(base.VarArgsInstruction):
    """ Probabilistic truncation if supported by the protocol.

    :param: number of arguments to follow (multiple of four)
    :param: destination (sint)
    :param: source (sint)
    :param: bit length of source (int)
    :param: number of bits to truncate (int)
    """
    __slots__ = []
    code = base.opcodes['TRUNC_PR']
    arg_format = tools.cycle(['sw','s','int','int'])

    def add_usage(self, req_node):
        req_node.increment(('modp', 'probabilistic truncation'),
                           self.get_size() * len(self.args) // 4)

class shuffle_base(base.DataInstruction):
    n_relevant_parties = 2

    def __init__(self, *args, **kwargs):
        super(shuffle_base, self).__init__(*args, **kwargs)
        prog = base.program
        if re.match('ring|rep-field|sy-rep.*', prog.options.execute or ''):
            ref = 'AHIK+22', 'Protocol 3.2'
        elif prog.options.execute:
            ref = 'KS14', 'Section 4.3'
        else:
            ref = ('AHIK+22', 'KS14'), None
        base.program.reading('secure shuffling', *ref)

    @staticmethod
    def logn(n):
        return int(math.ceil(math.log(n, 2)))

    @classmethod
    def n_swaps(cls, n):
        logn = cls.logn(n)
        return logn * 2 ** logn - 2 ** logn + 1

    @classmethod
    def add_gen_usage(self, req_node, n, add_shuffles=True, malicious=True,
                      n_relevant_parties=None):
        # hack for unknown usage
        req_node.increment(('bit', 'inverse'), float('inf'))
        # minimal usage with two relevant parties
        logn = self.logn(n)
        n_switches = self.n_swaps(n)
        n_relevant_parties = n_relevant_parties or self.n_relevant_parties
        for i in range(n_relevant_parties):
            req_node.increment((self.field_type, 'input', i), n_switches)
        if malicious:
            # multiplications for bit check
            req_node.increment((self.field_type, 'triple'),
                               n_switches * n_relevant_parties)
        if add_shuffles:
            req_node.increment((self.field_type, 'shuffle generation', n))

    @classmethod
    def add_apply_usage(self, req_node, n, record_size, add_shuffles=True,
                        malicious=True, n_relevant_parties=None):
        req_node.increment(('bit', 'inverse'), float('inf'))
        logn = self.logn(n)
        n_switches = self.n_swaps(n) * \
            (n_relevant_parties or self.n_relevant_parties)
        real_record_size = record_size
        if n != 2 ** logn and malicious:
            record_size += 1
        req_node.increment((self.field_type, 'triple'),
                           n_switches * record_size)
        if add_shuffles:
            req_node.increment(
                (self.field_type, 'shuffle application', n, real_record_size))

@base.gf2n
class secshuffle(base.VectorInstruction, shuffle_base):
    """ Secure shuffling.

    :param: destination (sint)
    :param: source (sint)
    """
    __slots__ = []
    code = base.opcodes['SECSHUFFLE']
    arg_format = ['sw','s','int']

    def __init__(self, *args, **kwargs):
        super(secshuffle_class, self).__init__(*args, **kwargs)
        assert len(args[0]) == len(args[1])
        assert len(args[0]) > args[2]

    def add_usage(self, req_node):
        self.add_gen_usage(req_node, len(self.args[0]))
        self.add_apply_usage(req_node, len(self.args[0]), self.args[2])

class gensecshuffle(shuffle_base):
    """ Generate secure shuffle to bit used several times.

    :param: destination (regint)
    :param: size (int)

    """
    __slots__ = []
    code = base.opcodes['GENSECSHUFFLE']
    arg_format = ['ciw','int']

    def add_usage(self, req_node):
        self.add_gen_usage(req_node, self.args[1])

class applyshuffle(shuffle_base, base.Mergeable):
    """ Generate secure shuffle to bit used several times.

    :param: vector size (int)
    :param: destination (sint)
    :param: source (sint)
    :param: number of elements to be treated as one (int)
    :param: handle (regint)
    :param: reverse (0/1)

    """
    __slots__ = []
    code = base.opcodes['APPLYSHUFFLE']
    arg_format = itertools.cycle(['int', 'sw','s','int','ci','int'])
    is_vec = lambda self: True # Ensures dead-code elimination works.

    def __init__(self, *args, **kwargs):
        super(applyshuffle, self).__init__(*args, **kwargs)
        assert (len(args) % 6) == 0
        for i in range(0, len(args), 6):
            assert args[i] == len(args[i+1])
            assert args[i] == len(args[i + 2])
            assert args[i] > args[i + 3]

    def add_usage(self, req_node):
        for i in range(0, len(self.args), 6):
            self.add_apply_usage(req_node, self.args[i], self.args[i + 3])

    def handles(self):
        return self.args[::4]

class delshuffle(base.Instruction):
    """ Delete secure shuffle.

    :param: handle (regint)

    """
    code = base.opcodes['DELSHUFFLE']
    arg_format = ['ci']

class inverse_permutation(base.VectorInstruction, shuffle_base):
    """ Calculate the inverse permutation of a secret permutation.

    :param: destination (sint)
    :param: source (sint)

    """
    __slots__ = []
    code = base.opcodes['INVPERM']
    arg_format = ['sw', 's']

    def __init__(self, *args, **kwargs):
        super(inverse_permutation, self).__init__(*args, **kwargs)
        assert len(args[0]) == len(args[1])

    def add_usage(self, req_node):
        self.add_gen_usage(req_node, len(self.args[0]))
        self.add_apply_usage(req_node, len(self.args[0]), 1)


class check(base.Instruction):
    """
    Force MAC check in current thread and all idle thread if current
    thread is the main thread.
    """
    __slots__ = []
    code = base.opcodes['CHECK']
    arg_format = []

###
### CISC-style instructions
###

@base.gf2n
@base.vectorize
class sqrs(base.CISC):
    r""" Secret squaring $s_i = s_j \cdot s_j$. """
    __slots__ = []
    arg_format = ['sw', 's']
    
    def expand(self):
        s = [type(self.args[0])() for i in range(6)]
        c = [self.args[0].clear_type() for i in range(2)]
        square(s[0], s[1])
        subs(s[2], self.args[1], s[0])
        asm_open(False, c[0], s[2])
        mulc(c[1], c[0], c[0])
        comparison.maybe_mulm(s[3], self.args[1], c[0])
        adds(s[4], s[3], s[3])
        adds(s[5], s[1], s[4])
        subml(self.args[0], s[5], c[1])


# placeholder for documentation
class cisc:
    """ Meta instruction for emulation. This instruction is only generated
    when using ``-K`` with ``compile.py``. The header looks as follows:

    :param: number of arguments after name plus one
    :param: name (16 bytes, zero-padded)

    Currently, the following names are supported:

    LTZ
      Less than zero.

      :param: number of arguments in this unit (must be 6)
      :param: vector size
      :param: result (sint)
      :param: input (sint)
      :param: bit length
      :param: (ignored)
      :param: (repeat)...

    Trunc
      Truncation.

      :param: number of arguments in this unit (must be 8)
      :param: vector size
      :param: result (sint)
      :param: input (sint)
      :param: bit length
      :param: number of bits to truncate
      :param: (ignored)
      :param: 0 for unsigned or 1 for signed
      :param: (repeat)...

    FPDiv
      Fixed-point division. Division by zero results in zero without error.

      :param: number of arguments in this unit (must be at least 7)
      :param: vector size
      :param: result (sint)
      :param: dividend (sint)
      :param: divisor (sint)
      :param: (ignored)
      :param: fixed-point precision
      :param: (repeat)...

    exp2_fx
      Fixed-point power of two.

      :param: number of arguments in this unit (must be at least 6)
      :param: vector size
      :param: result (sint)
      :param: exponent (sint)
      :param: (ignored)
      :param: fixed-point precision
      :param: (repeat)...

    log2_fx
      Fixed-point logarithm with base 2.

      :param: number of arguments in this unit (must be at least 6)
      :param: vector size
      :param: result (sint)
      :param: input (sint)
      :param: (ignored)
      :param: fixed-point precision
      :param: (repeat)...

    """
    code = base.opcodes['CISC']

# hack for circular dependency
from Compiler import comparison
