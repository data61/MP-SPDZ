"""
This modules contains basic types for binary circuits. The
fixed-length types obtained by :py:obj:`get_type(n)` are the preferred
way of using them, and in some cases required in connection with
container types.

Computation using these types will always be executed as a binary
circuit. See :ref:`protocol-pairs` for the exact protocols.
"""

from Compiler.types import MemValue, read_mem_value, regint, Array, cint
from Compiler.types import _bitint, _number, _fix, _structure, _bit, _vec, sint, sintbit
from Compiler.types import vectorized_classmethod
from Compiler.program import Tape, Program
from Compiler.exceptions import *
from Compiler import util, oram, floatingpoint, library, comparison
from Compiler import instructions_base
import Compiler.GC.instructions as inst
import operator
import math
import itertools
from functools import reduce

class _binary:
    def __or__(self, other):
        return self ^ other ^ (self & other)
    __ror__ = __or__
    def reveal_to(self, *args, **kwargs):
        raise CompilerError(
            '%s does not support revealing to individual players' % type(self))
    @staticmethod
    def direct_matrix_mul(*args, **kwargs):
        raise AttributeError('direct matrix multiplication only supported '
                             'in arithmetic circuits')

class bits(Tape.Register, _structure, _bit, _binary):
    n = 40
    unit = 64
    PreOp = staticmethod(floatingpoint.PreOpN)
    decomposed = None
    @staticmethod
    def PreOR(l):
        return [1 - x for x in \
                floatingpoint.PreOpN(operator.mul, \
                                     [1 - x for x in l])]
    @classmethod
    def get_type(cls, length):
        """ Returns a fixed-length type. """
        if length == 1:
            return cls.bit_type
        if length not in cls.types:
            class bitsn(cls):
                n = length
            cls.types[length] = bitsn
            bitsn.clear_type = cbits.get_type(length)
            bitsn.__name__ = cls.__name__ + str(length)
        return cls.types[length]
    @classmethod
    def conv(cls, other):
        if isinstance(other, cls) and cls.n == other.n:
            return other
        elif isinstance(other, MemValue):
            return cls.conv(other.read())
        else:
            res = cls()
            res.load_other(other)
            return res
    hard_conv = conv
    @classmethod
    def compose(cls, items, bit_length=1):
        return cls.bit_compose(sum([util.bit_decompose(item, bit_length) for item in items], []))
    @classmethod
    def bit_compose(cls, bits):
        bits = list(bits)
        if len(bits) == 1 and isinstance(bits[0], cls):
            return cls(bits[0])
        bits = list(bits)
        for i in range(len(bits)):
            if util.is_constant(bits[i]):
                bits[i] = cls.bit_type(bits[i])
        res = cls.new(n=len(bits))
        if len(bits) <= cls.unit:
            cls.bitcom(res, *(sbit.conv(bit) for bit in bits))
        else:
            n_bak = bits[0].n
            bits[0].n = 1
            res = cls.trans(bits)[0]
            bits[0].n = n_bak
        res.decomposed = bits
        return res
    def bit_decompose(self, bit_length=None):
        n = bit_length or self.n
        suffix = [0] * (n - self.n)
        if n == 1 and self.n == 1:
            return [self]
        n = min(n, self.n)
        if self.decomposed is None or len(self.decomposed) < n:
            if n <= self.unit:
                res = [self.bit_type() for i in range(n)]
                self.bitdec(self, *res)
            else:
                res = self.bit_type.trans([self])
            self.decomposed = res
            return res + suffix
        else:
            return self.decomposed[:n] + suffix
    @staticmethod
    def bit_decompose_clear(a, n_bits):
        res = [cbits.get_type(a.size)() for i in range(n_bits)]
        cbits.conv_cint_vec(a, *res)
        return res
    @classmethod
    def malloc(cls, size, creator_tape=None, **kwargs):
        return Program.prog.malloc(size, cls, creator_tape=creator_tape,
                                   **kwargs)
    @staticmethod
    def n_elements():
        return 1
    @classmethod
    def mem_size(cls):
        return math.ceil(cls.n / cls.unit)
    @classmethod
    def load_mem(cls, address, mem_type=None, size=None):
        if size not in (None, 1):
            v = [cls.load_mem(address + i) for i in range(size)]
            return cls.vec(v)
        res = cls()
        if mem_type == 'sd':
            return cls.load_dynamic_mem(address)
        else:
            cls.mem_op(cls.load_inst, res, address)
            return res
    def store_in_mem(self, address):
        self.mem_op(self.store_inst, self, address)
    @staticmethod
    def mem_op(inst, reg, address):
        direct = isinstance(address, int)
        if not direct:
            address = regint.conv(address)
        inst[direct](reg, address)
    @classmethod
    def new(cls, value=None, n=None):
        if util.is_constant(value):
            n = value.bit_length()
        return cls.get_type(n)(value)
    @classmethod
    def same_type(cls, size=None):
        assert size is None or size == math.ceil(self.n / self.unit)
        return cls()
    def __init__(self, value=None, n=None, size=None):
        assert n == self.n or n is None
        if size != 1 and size is not None:
            raise Exception('invalid size for bit type: %s' % size)
        self.n = n or self.n
        size = math.ceil(self.n / self.unit) if self.n != None else None
        Tape.Register.__init__(self, self.reg_type, Program.prog.curr_tape,
                               size=size)
        if value is not None:
            self.load_other(value)
    def copy(self):
        return type(self).new(n=instructions_base.get_global_vector_size())
    def set_length(self, n):
        if n > self.n:
            raise Exception('too long: %d/%d' % (n, self.n))
        self.n = n
    def set_size(self, size):
        pass
    def load_int(self, value):
        n_limbs = math.ceil(self.n / self.unit)
        for i in range(n_limbs):
            self.conv_regint(min(self.unit, self.n - i * self.unit),
                             self[i], regint(value % 2 ** self.unit))
            value >>= self.unit
    def load_other(self, other):
        if isinstance(other, cint):
            assert(self.n == other.size)
            self.conv_regint_by_bit(self.n, self, other.to_regint(1, sync=False))
        elif isinstance(other, int):
            self.set_length(self.n or util.int_len(other))
            self.load_int(other)
        elif isinstance(other, regint):
            assert self.unit == 64
            n_units = int(math.ceil(self.n / self.unit))
            n_convs = min(other.size, n_units)
            for i in range(n_convs):
                x = self[i]
                y = other[i]
                self.conv_regint(min(self.unit, self.n - i * self.unit), x, y)
            for i in range(n_convs, n_units):
                inst.ldbits(self[i], min(self.unit, self.n - i * self.unit), 0)
        elif (isinstance(self, type(other)) or isinstance(other, type(self))) \
             and self.n == other.n:
            try:
                self.mov(self, other)
            except AssertionError:
                for i in range(math.ceil(self.n / self.unit)):
                    self.mov(self[i], other[i])
        elif isinstance(other, sintbit) and isinstance(self, sbits):
            assert len(other) == 1
            r = sint.get_dabit()
            self.mov(self, r[1] ^ other.bit_xor(r[0]).reveal())
        elif isinstance(other, sint) and isinstance(self, sbits):
            self.mov(self, sbitvec(other, self.n).elements()[0])
        else:
            try:
                bits = other.bit_decompose()
                bits = bits[:self.n] + [self.bit_type(0)] * (self.n - len(bits))
                other = self.bit_compose(bits)
                assert(isinstance(other, type(self)))
                assert(other.n == self.n)
                self.load_other(other)
            except:
                raise CompilerError('cannot convert %s/%s from %s to %s' % \
                                    (str(other), repr(other), type(other), type(self)))
    def long_one(self):
        return 2**self.n - 1 if self.n != None else None
    def is_long_one(self, other):
        return util.is_all_ones(other, self.n) or \
            (other is None and self.n == None)
    def res_type(self, other):
        if self.n == None and other.n == None:
            n = None
        else:
            n = max(self.n, other.n)
        return self.get_type(n)
    @read_mem_value
    def __and__(self, other):
        if util.is_zero(other):
            return 0
        elif self.is_long_one(other):
            return self
        elif isinstance(other, _vec):
            return other & other.from_vec([self])
        else:
            return self._and(other)
    @read_mem_value
    def __xor__(self, other):
        if util.is_zero(other):
            return self
        elif self.is_long_one(other):
            return ~self
        else:
            return self._xor(other)
    __rand__ = __and__
    __rxor__ = __xor__
    def __repr__(self):
        if self.n != None:
            suffix = '%d' % self.n
            if type(self).n != None and type(self).n != self.n:
                suffix += '/%d' % type(self).n
        else:
            suffix = 'undef'
        return '%s(%s)' % (super(bits, self).__repr__(), suffix)
    __str__ = __repr__
    def _new_by_number(self, i, size=1):
        assert(size == 1)
        n = min(self.unit, self.n - (i - self.i) * self.unit)
        res = self.get_type(n)()
        res.i = i
        res.program = self.program
        return res
    def if_else(self, x, y):
        """
        Bit-wise oblivious selection::

            sb32 = sbits.get_type(32)
            print_ln('%s', sb32(3).if_else(sb32(5), sb32(2)).reveal())

        This will output 1 because it selects the two least
        significant bits from 5 and the rest of the bits from 2.

        """
        return result_conv(x, y)(self & (x ^ y) ^ y)
    def zero_if_not(self, condition):
        if util.is_constant(condition):
            return self * condition
        else:
            return self * cbit.conv(condition)
    def expand(self, length):
        if self.n in (length, None):
            return self
        elif self.n == 1:
            return self.get_type(length).bit_compose([self] * length)
        else:
            raise CompilerError('cannot expand from %s to %s' % (self.n, length))
    @classmethod
    def new_vector(cls, size):
        return cls.get_type(size)()
    @classmethod
    def concat(cls, parts):
        return cls.bit_compose(
            sum([part.bit_decompose() for part in parts], []))
    def copy_from_part(self, source, base, size):
        self.mov(self,
                 self.bit_compose(source.bit_decompose()[base:base + size]))
    def vector_size(self):
        return self.n
    def size_for_mem(self):
        return 1

class cbits(bits):
    """ Clear bits register. Helper type with limited functionality. """
    max_length = 64
    reg_type = 'cb'
    is_clear = True
    load_inst = (inst.ldmcbi, inst.ldmcb)
    store_inst = (inst.stmcbi, inst.stmcb)
    bitdec = inst.bitdecc
    conv_regint = staticmethod(lambda n, x, y: inst.convcint(x, y))
    conv_cint_vec = inst.convcintvec
    mov = staticmethod(lambda x, y: inst.addcbi(x, y, 0))
    @classmethod
    def bit_compose(cls, bits):
        return sum(bit << i for i, bit in enumerate(bits))
    @classmethod
    def conv_regint_by_bit(cls, n, res, other):
        assert n == res.n
        assert n == other.size
        cls.conv_cint_vec(cint(other, size=other.size), res)
    @classmethod
    def conv(cls, other):
        if isinstance(other, cbits) and cls.n != None and \
           cls.n // cls.unit == other.n // cls.unit:
            if isinstance(other, cls):
                return other
            else:
                res = cls()
                for i in range(math.ceil(cls.n / cls.unit)):
                    cls.mov(res[i], other[i])
                return res
        else:
            return super(cbits, cls).conv(other)
    types = {}
    def store_in_dynamic_mem(self, address):
        inst.stmsdci(self, cbits.conv(address))
    def clear_op(self, other, c_inst, ci_inst, op):
        if isinstance(other, cbits):
            res = cbits.get_type(max(self.n, other.n))()
            c_inst(res, self, other)
            return res
        elif isinstance(other, sbits):
            return NotImplemented
        else:
            if util.is_constant(other):
                if other >= 2**31 or other < -2**31:
                    return op(self, cbits.new(other))
                res = cbits.get_type(max(self.n, len(bin(other)) - 2))()
                ci_inst(res, self, other)
                return res
            else:
                return op(self, cbits(other))
    __add__ = lambda self, other: \
              self.clear_op(other, inst.addcb, inst.addcbi, operator.add)
    def __sub__(self, other):
        try:
            return self + -other
        except:
            return type(self)(regint(self) - regint(other))
    def __rsub__(self, other):
        return type(self)(other - regint(self))
    def __neg__(self):
        return type(self)(-regint(self))
    def _xor(self, other):
        if isinstance(other, (sbits, sbitvec)):
            return NotImplemented
        elif isinstance(other, cbits):
            res = self.res_type(other)()
            assert res.size == self.size
            assert res.size == other.size
            inst.xorcb(res.n, res, self, other)
            return res
        else:
            return self.clear_op(other, None, inst.xorcbi, operator.xor)
    def _and(self, other):
        try:
            return cbits.get_type(self.n)(regint(self) & regint(other))
        except CompilerError:
            return NotImplemented
    __radd__ = __add__
    def __mul__(self, other):
        if isinstance(other, cbits):
            return cbits.get_type(self.n)(regint(self) * regint(other))
        else:
            try:
                res = cbits.get_type(min(self.max_length,
                                         self.n+util.int_len(other)))()
                inst.mulcbi(res, self, other)
                return res
            except TypeError:
                return NotImplemented
    def __rshift__(self, other):
        res = cbits.new(n=self.n-other)
        inst.shrcbi(res, self, other)
        return res
    def __lshift__(self, other):
        res = cbits.get_type(self.n+other)()
        inst.shlcbi(res, self, other)
        return res
    def __invert__(self):
        res = type(self)()
        inst.notcb(self.n, res, self)
        return res
    __lt__ = lambda self, other: regint(self) < other
    __le__ = lambda self, other: regint(self) <= other
    __gt__ = lambda self, other: regint(self) > other
    __ge__ = lambda self, other: regint(self) >= other
    __eq__ = lambda self, other: regint(self) == other
    __ne__ = lambda self, other: regint(self) != other
    def print_reg(self, desc=''):
        inst.print_regb(self, desc)
    def print_reg_plain(self):
        inst.print_reg_signed(self.n, self)
    output = print_reg_plain
    def print_if(self, string):
        inst.cond_print_strb(self, string)
    def output_if(self, cond):
        if Program.prog.options.binary:
            @library.if_(cond)
            def _():
                self.print_reg_plain()
        else:
            cint(self).output_if(cond)
    def reveal(self):
        return self
    def to_regint(self, dest=None):
        if dest is None:
            dest = regint()
        if self.n > 64:
            raise CompilerError('too many bits')
        inst.convcbit(dest, self)
        return dest
    def to_regint_by_bit(self):
        if self.n != None:
            res = regint(size=self.n)
        else:
            res = regint()
        inst.convcbitvec(self.n, res, self)
        return res

class sbits(bits, Tape._no_secret_truth):
    """
    Secret bits register. This type supports basic bit-wise operations::

        sb32 = sbits.get_type(32)
        a = sb32(3)
        b = sb32(5)
        print_ln('XOR: %s', (a ^ b).reveal())
        print_ln('AND: %s', (a & b).reveal())
        print_ln('NOT: %s', (~a).reveal())

    This will output the following::

        XOR: 6
        AND: 1
        NOT: -4

    Instances can be also be initialized from :py:obj:`~Compiler.types.regint`
    and :py:obj:`~Compiler.types.sint`.
    """
    max_length = 64
    reg_type = 'sb'
    is_clear = False
    clear_type = cbits
    load_inst = (inst.ldmsbi, inst.ldmsb)
    store_inst = (inst.stmsbi, inst.stmsb)
    bitdec = inst.bitdecs
    bitcom = inst.bitcoms
    conv_regint = inst.convsint
    @classmethod
    def conv_regint_by_bit(cls, n, res, other):
        tmp = cbits.get_type(n)()
        tmp.conv_regint_by_bit(n, tmp, other)
        res.load_other(tmp)
    mov = staticmethod(lambda x, y: inst.movsb(x.n, x, y))
    types = {}
    def __init__(self, *args, **kwargs):
        bits.__init__(self, *args, **kwargs)
    @staticmethod
    def new(value=None, n=None):
        if n == 1:
            return sbit(value)
        else:
            return sbits.get_type(n)(value)
    @staticmethod
    def _new(value):
        return value
    @staticmethod
    def get_random_bit():
        res = sbit()
        inst.bitb(res)
        return res
    @staticmethod
    def _check_input_player(player):
        if not util.is_constant(player):
            raise CompilerError('player must be known at compile time '
                                'for binary circuit inputs')
    @classmethod
    def get_input_from(cls, player, n_bits=None):
        """ Secret input from :py:obj:`player`.

        :param: player (int)
        """
        cls._check_input_player(player)
        if n_bits is None:
            n_bits = cls.n
        res = cls()
        inst.inputb(player, n_bits, 0, res)
        return res
    # compatibility to sint
    get_raw_input_from = get_input_from
    @classmethod
    def load_dynamic_mem(cls, address):
        res = cls()
        if isinstance(address, int):
            inst.ldmsd(res, address, cls.n)
        else:
            inst.ldmsdi(res, address, cls.n)
        return res
    def store_in_dynamic_mem(self, address):
        if isinstance(address, int):
            inst.stmsd(self, address)
        else:
            inst.stmsdi(self, cbits.conv(address))
    def load_int(self, value):
        if (abs(value) > (1 << self.n)):
            raise Exception('public value %d longer than %d bits' \
                            % (value, self.n))
        if self.n <= 32:
            inst.ldbits(self, self.n, value)
        else:
            bits.load_int(self, value)
    def load_other(self, other):
        if isinstance(other, cbits) and self.n == other.n:
            inst.convcbit2s(self.n, self, other)
        else:
            super(sbits, self).load_other(other)
    @read_mem_value
    def __add__(self, other):
        if isinstance(other, int) or other is None:
            return self.xor_int(other)
        else:
            if not isinstance(other, sbits):
                other = self.conv(other)
            if self.n is None or other.n is None:
                assert self.n == other.n
                n = None
            else:
                n = min(self.n, other.n)
            res = self.new(n=n)
            inst.xors(n, res, self, other)
            if self.n != None and max(self.n, other.n) > n:
                if self.n > n:
                    longer = self
                else:
                    longer = other
                bits = res.bit_decompose() + longer.bit_decompose()[n:]
                res = self.bit_compose(bits)
            return res
    __radd__ = __add__
    __sub__ = __add__
    __rsub__ = __add__
    _xor = __add__
    @read_mem_value
    def __mul__(self, other):
        if isinstance(other, int):
            return self.mul_int(other)
        elif isinstance(other, cint):
            try:
                other = cbits.get_type(self.unit)(regint(other))
            except CompilerError:
                return NotImplemented
            if self.n == 1:
                return self.bit_compose([self] * self.unit) & other
        try:
            if (self.n, other.n) == (1, 1):
                return self & other
            if min(self.n, other.n) != 1:
                raise NotImplementedError('high order multiplication')
            n = max(self.n, other.n)
            res = self.new(n=max(self.n, other.n))
            order = (self, other) if self.n != 1 else (other, self)
            inst.andrs(n, res, *order)
            return res
        except AttributeError:
            return NotImplemented
    __rmul__ = __mul__
    def _and(self, other):
        res = self.new(n=self.n)
        if not isinstance(other, sbits) and Program.prog.use_mulm:
            other = cbits.get_type(self.n).conv(other)
            inst.andm(self.n, res, self, other)
            return res
        other = self.conv(other)
        assert(self.n == other.n)
        inst.ands(self.n, res, self, other)
        return res
    def xor_int(self, other):
        if other == 0:
            return self
        elif other == self.long_one():
            return ~self
        self_bits = self.bit_decompose()
        other_bits = util.bit_decompose(other, max(self.n, util.int_len(other)))
        extra_bits = [self.new(b, n=1) for b in other_bits[self.n:]]
        return self.bit_compose([~x if y else x \
                                 for x,y in zip(self_bits, other_bits)] \
                                + extra_bits)
    def mul_int(self, other):
        assert(util.is_constant(other))
        if other == 0:
            return 0
        elif other == 1:
            return self
        elif self.n == 1:
            bits = util.bit_decompose(other, util.int_len(other))
            zero = sbit(0)
            mul_bits = [self if b else zero for b in bits]
            return self.bit_compose(mul_bits)
        else:
            print(self.n, other)
            return NotImplemented
    def __lshift__(self, i):
        return self.bit_compose([sbit(0)] * i + self.bit_decompose()[:self.max_length-i])
    def __invert__(self):
        res = type(self)(n=self.n)
        inst.nots(self.n, res, self)
        return res
    def __neg__(self):
        return self
    def reveal(self, check=False):
        assert not check
        if self.n == None or \
           self.n > max(self.max_length, self.clear_type.max_length):
            assert(self.unit == self.clear_type.unit)
        res = self.clear_type.get_type(self.n)()
        inst.reveal(self.n, res, self)
        return res
    def equal(self, other, n=None):
        bits = (~(self + other)).bit_decompose()
        return reduce(operator.mul, bits)
    __eq__ = equal
    __ne__ = lambda self, other: (self == other).bit_not()
    def right_shift(self, m, k, security=None, signed=True):
        return self.TruncPr(k, m)
    def TruncPr(self, k, m, kappa=None):
        if k > self.n:
            raise Exception('TruncPr overflow: %d > %d' % (k, self.n))
        bits = self.bit_decompose()
        res = self.get_type(k - m).bit_compose(bits[m:k])
        return res
    @classmethod
    def two_power(cls, n):
        if n > cls.n:
            raise Exception('two_power overflow: %d > %d' % (n, cls.n))
        res = cls()
        if n == cls.n:
            res.load_int(-1 << (n - 1))
        else:
            res.load_int(1 << n)
        return res
    def popcnt(self):
        """ Population count / Hamming weight.

        :return: :py:obj:`sbits` of required length """
        return sbitvec([self]).popcnt().elements()[0]
    @classmethod
    def trans(cls, rows):
        rows = list(rows)
        if len(rows) == 1 and rows[0].n <= rows[0].unit:
            return rows[0].bit_decompose()
        for row in rows:
            try:
                n_columns = row.n
                break
            except:
                pass
        for i in range(len(rows)):
            if util.is_zero(rows[i]):
                rows[i] = cls.get_type(n_columns)(0)
        for row in rows:
            assert(row.n == n_columns)
        if n_columns == 1 and len(rows) <= cls.unit:
            return [cls.bit_compose(rows)]
        else:
            res = [cls.new(n=len(rows)) for i in range(n_columns)]
            inst.trans(len(res), *(res + rows))
            return res
    @staticmethod
    def bit_adder(*args, **kwargs):
        """ Binary adder in binary circuits.

        :param a: summand (list of 0/1 in compatible type)
        :param b: summand (list of 0/1 in compatible type)
        :param carry_in: input carry (default 0)
        :param get_carry: add final carry to output
        :returns: list of 0/1 in relevant type
        """
        return sbitint.bit_adder(*args, **kwargs)
    @staticmethod
    def ripple_carry_adder(*args, **kwargs):
        return sbitint.ripple_carry_adder(*args, **kwargs)
    def output(self):
        inst.print_reg_plainsb(self)

class sbitvec(Tape._no_secret_truth, _vec, _bit, _binary):
    """ Vector of registers of secret bits, effectively a matrix of secret bits.
    This facilitates parallel arithmetic operations in binary circuits.
    Container types are not supported, use :py:obj:`sbitvec.get_type` for that.

    You can access the rows by member :py:obj:`v` and the columns by calling
    :py:obj:`elements`.

    There are four ways to create an instance:

    1. By transposition::

        sb32 = sbits.get_type(32)
        x = sbitvec([sb32(5), sb32(3), sb32(0)])
        print_ln('%s', [x.v[0].reveal(), x.v[1].reveal(), x.v[2].reveal()])
        print_ln('%s', [x.elements()[0].reveal(), x.elements()[1].reveal()])

       This should output::

        [3, 2, 1]
        [5, 3]

    2. Without transposition::

        sb32 = sbits.get_type(32)
        x = sbitvec.from_vec([sb32(5), sb32(3)])
        print_ln('%s', [x.v[0].reveal(), x.v[1].reveal()])

       This should output::

        [5, 3]

    3. From :py:obj:`~Compiler.types.sint`::

        y = sint(5)
        x = sbitvec(y, 3, 3)
        print_ln('%s', [x.v[0].reveal(), x.v[1].reveal(), x.v[2].reveal()])

       This should output::

        [1, 0, 1]

    4. Private input::

        x = sbitvec.get_type(32).get_input_from(player)

    """
    bit_extend = staticmethod(lambda v, n: v[:n] + [0] * (n - len(v)))
    is_clear = False
    @classmethod
    def get_type(cls, n):
        """ Create type for fixed-length vector of registers of secret bits.

        As with :py:obj:`sbitvec`, you can access the rows by member
        :py:obj:`v` and the columns by calling :py:obj:`elements`.
        """
        class sbitvecn(cls, _structure):
            n_bits = n
            @staticmethod
            def get_type(n):
                return cls.get_type(n)
            @classmethod
            def malloc(cls, size, creator_tape=None):
                return sbit.malloc(
                    size * cls.mem_size(), creator_tape=creator_tape)
            @staticmethod
            def n_elements():
                return 1
            @staticmethod
            def mem_size():
                return sbits.get_type(n).mem_size()
            @classmethod
            def get_input_from(cls, player, size=1, f=0):
                """ Secret input from :py:obj:`player`. The input is decomposed
                into bits.

                :param: player (int)
                """
                sbits._check_input_player(player)
                instructions_base.check_vector_size(size)
                if size == 1:
                    res = cls.from_vec(sbit() for i in range(n))
                    inst.inputbvec(n + 3, f, player, *res.v)
                    return res
                else:
                    elements = []
                    for i in range(size):
                        v = sbits.get_type(n)()
                        inst.inputb(player, n, f, v)
                        elements.append(v)
                    return cls(elements)
            get_raw_input_from = get_input_from
            @classmethod
            def from_vec(cls, vector, signed=True):
                res = cls()
                if isinstance(vector, sbitvec):
                    vector = vector.v
                v = list(vector)
                if signed:
                    v = _complement_two_extend(v, n)
                else:
                    v = v + [type(v[0])(0)] * (n - len(v))
                res.v = v[:n]
                return res
            def __init__(self, other=None, size=None):
                instructions_base.check_vector_size(size)
                if other is not None:
                    if util.is_constant(other):
                        if util.int_len(other) > n:
                            raise CompilerError('constant outside domain')
                        t = sbits.get_type(size or 1)
                        self.v = [t(((other >> i) & 1) * ((1 << t.n) - 1))
                                  for i in range(n)]
                    elif isinstance(other, _vec):
                        if isinstance(other, sbitfixvec):
                            v = other.v.v[other.f:]
                        else:
                            v = other.v
                        self.v = [type(x)(x) for x in self.bit_extend(v, n)]
                    elif isinstance(other, (list, tuple)):
                        self.v = self.bit_extend(sbitvec(other).v, n)
                    else:
                        self.v = sbits.get_type(n)(other).bit_decompose()
                    assert len(self.v) == n
                    assert size is None or size == self.v[0].n
            @classmethod
            def load_mem(cls, address, size=None):
                if isinstance(address, int) or len(address) == 1:
                    size = size or instructions_base.get_global_vector_size()
                    address = [address + i * cls.mem_size()
                               for i in range(size or 1)]
                else:
                    assert size == None
                return cls(
                    [sbits.get_type(n).load_mem(x) for x in address])
            def store_in_mem(self, address):
                size = 1
                for x in self.v:
                    if not util.is_constant(x):
                        size = max(size, x.n)
                if isinstance(address, int) or len(address) == 1:
                    address = [address + i * self.mem_size()
                               for i in range(size)]
                else:
                    assert size == len(address)
                for x, dest in zip(self.elements(), address):
                    x.store_in_mem(dest)
            @classmethod
            def two_power(cls, nn, size=1):
                return cls.from_vec(
                    [0] * nn + [sbits.get_type(size)().long_one()] + [0] * (n - nn - 1))
            def coerce(self, other):
                if util.is_constant(other):
                    return self.from_vec(util.bit_decompose(other, n))
                else:
                    return super(sbitvecn, self).coerce(other)
            @classmethod
            def bit_compose(cls, bits):
                bits = list(bits)
                if len(bits) < n:
                    bits += [0] * (n - len(bits))
                assert len(bits) == n
                return cls.from_vec(bits)
            def zero_if_not(self, condition):
                return self.from_vec(x.zero_if_not(condition) for x in self.v)
            def __str__(self):
                return 'sbitvec(%d)' % n
            @classmethod
            def get_random_int(cls, n_bits):
                assert instructions_base.get_global_vector_size() == 1
                return cls.from_vec(
                    [sbit.get_random_bit() for i in range(n_bits)] + \
                    [0] * (n - n_bits))
            @staticmethod
            def get_random_bit():
                assert instructions_base.get_global_vector_size() == 1
                return sbit.get_random_bit()
        sbitvecn.basic_type = sbitvecn
        sbitvecn.reg_type = 'sb'
        return sbitvecn
    @classmethod
    def from_vec(cls, vector):
        if isinstance(vector, sbitvec):
            vector = vector.v
        res = cls()
        res.v = list(vector)
        return res
    compose = from_vec
    @classmethod
    def combine(cls, vectors):
        res = cls()
        res.v = sum((vec.v for vec in vectors), [])
        return res
    @classmethod
    def from_matrix(cls, matrix):
        # any number of rows, limited number of columns
        return cls.combine(cls(row) for row in matrix)
    @classmethod
    def from_hex(cls, string, reverse=True):
        """ Create from hexadecimal string (little-endian). """
        assert len(string) % 2 == 0
        v = []
        trans = reversed if reverse else list
        for i in range(0, len(string), 2):
            v += [sbit(int(x))
                  for x in trans(bin(int(string[i:i + 2], 16))[2:].zfill(8))]
        return cls.from_vec(v)
    def __init__(self, elements=None, length=None, input_length=None):
        if length:
            assert isinstance(elements, sint)
            prog = Program.prog
            backup = prog.use_edabit()
            if not prog.have_a2b():
                # force the use of edaBits
                prog.use_edabit(True)
            self.v = prog.non_linear.bit_dec(
                elements, max(length, input_length or prog.bit_length),
                length, maybe_mixed=True)
            assert isinstance(self.v[0], sbits)
            prog.use_edabit(backup)
        elif isinstance(elements, sbitvec):
            self.v = elements.v
        elif isinstance(elements, (list, tuple)) and \
             isinstance(elements[0], sbitvec):
            self.v = sbitvec(sum((x.elements() for x in elements), [])).v
        elif elements is not None and not (util.is_constant(elements) and \
             elements == 0):
            self.v = sbits.trans(elements)
    def __str__(self):
        return 'sbitvec(%s/%s)' % (len(self.v), self.size)
    __repr__ = __str__
    def popcnt(self):
        """ Population count / Hamming weight.

        :return: :py:obj:`sbitintvec` of required length """
        res = sbitint.wallace_tree([[b] for b in self.v])
        while util.is_zero(res[-1]):
            del res[-1]
        return sbitintvec.get_type(len(res)).from_vec(res)
    def elements(self, start=None, stop=None):
        if stop is None:
            start, stop = stop, start
        return sbits.trans(self.v[start:stop])
    def coerce(self, other):
        if isinstance(other, cint):
            size = other.size
            return (other.get_vector(base, min(64, size - base)) \
                    for base in range(0, size, 64))
        if not isinstance(other, type(self)):
            return type(self)(other)
        return other
    def __xor__(self, other):
        other = self.coerce(other)
        return self.from_vec(x ^ y for x, y in zip(*self.expand(other)))
    def __and__(self, other):
        return self.from_vec(x & y for x, y in zip(*self.expand(other)))
    __add__ = __radd__ = __sub__ = __rsub__ =__rxor__ = __xor__
    __rand__ = __and__
    def __invert__(self):
        return self.from_vec(~x for x in self.v)
    def if_else(self, x, y):
        return util.if_else(self.v[0], x, y)
    def __iter__(self):
        return iter(self.elements())
    @classmethod
    def conv(cls, other):
        if isinstance(other, cls):
            return cls.from_vec(other.v)
        else:
            return cls(other)
    hard_conv = conv
    @property
    def size(self):
        if not self.v or util.is_constant(self.v[0]):
            return 1
        else:
            return self.v[0].n
    @property
    def n_bits(self):
        return len(self.v)
    def store_in_mem(self, address):
        for i, x in enumerate(self.elements()):
            x.store_in_mem(address + i)
    def bit_decompose(self, n_bits=None, security=None, maybe_mixed=None):
        return self.v[:n_bits]
    bit_compose = from_vec
    def reveal(self):
        return util.untuplify([x.reveal() for x in self.elements()])
    def long_one(self):
        return [x.long_one() for x in self.v]
    def half_adder(self, other):
        other = self.coerce(other)
        res = zip(*(x.half_adder(y) for x, y in zip(self.v, other)))
        return (self.from_vec(x) for x in res)
    def __mul__(self, other):
        if isinstance(other, int):
            return self.from_vec(x * other for x in self.v)
        if isinstance(other, sbitvec):
            if len(other.v) == 1:
                other = other.v[0]
            elif len(self.v) == 1:
                self, other = other, self.v[0]
            else:
                raise CompilerError('no operand of length 1: %d/%d',
                                    (len(self.v), len(other.v)))
        if not isinstance(other, sbits):
            return NotImplemented
        ops = []
        for x in self.v:
            if not util.is_zero(x):
                assert x.n == other.n
                ops.append(x)
        if ops:
            prods = [sbits.get_type(other.n)() for i in ops]
            inst.andrsvec(3 + 2 * len(ops), other.n, *prods, other, *ops)
        res = []
        i = 0
        for x in self.v:
            if util.is_zero(x):
                res.append(0)
            else:
                res.append(prods[i])
                i += 1
        return sbitvec.from_vec(res)
    __rmul__ = __mul__
    def bit_and(self, other):
        return self & other
    def bit_xor(self, other):
        return self ^ other
    def right_shift(self, m, k, security=None, signed=True):
        return self.from_vec(self.v[m:])
    def tree_reduce(self, function):
        elements = self.elements()
        while len(elements) > 1:
            size = len(elements)
            half = size // 2
            left = elements[:half]
            right = elements[half:2*half]
            odd = elements[2*half:]
            sides = [self.from_vec(sbitvec(x).v) for x in (left, right)]
            red = function(*sides)
            elements = red.elements()
            elements += odd
        return self.from_vec(sbitvec(elements).v)
    @classmethod
    def comp_result(cls, x):
        return cls.get_type(1).from_vec([x])
    @staticmethod
    def reverse_type(other):
        return isinstance(other, sbitfixvec)
    equal = __eq__ = _bitint.__eq__
    eqz = staticmethod(_bitint.eqz)
    def expand(self, other, expand=True, copy=False):
        assert not isinstance(other, sbitfixvec)
        m = 1
        for x in itertools.chain(self.v, other.v if isinstance(other, sbitvec) else []):
            try:
                m = max(m, x.n)
            except:
                pass
        res = []
        if not util.is_constant(other):
            other = self.coerce(other)
        for y in self, other:
            if isinstance(y, int):
                res.append([x * sbits.get_type(m)().long_one()
                            for x in util.bit_decompose(y, len(self.v))])
            else:
                if copy:
                    v = [type(x)(x) if isinstance(x, bits) else x for x in y.v]
                else:
                    v = y.v
                res.append([x.expand(m) if (expand and isinstance(x, bits))
                            else x for x in v])
        return res
    def demux(self):
        if len(self) == 1:
            return sbitvec.from_vec([self.v[0].bit_not(), self.v[0]])
        a = sbitvec.from_vec(self.v[:len(self) // 2]).demux()
        b = sbitvec.from_vec(self.v[len(self) // 2:]).demux()
        prod = [a * bb for bb in b.v]
        return sbitvec.from_vec(reduce(operator.add, (x.v for x in prod)))
    def reverse_bytes(self):
        if len(self.v) % 8 != 0:
            raise CompilerError('bit length not divisible by eight')
        return self.from_vec(sum(reversed(
            [self.v[i:i + 8] for i in range(0, len(self.v), 8)]), []))
    def reveal_print_hex(self):
        """ Reveal and print in hexademical (one line per element). """
        if len(self.v) % 64 != 0:
            raise CompilerError('only works for lengths divisible by 64')
        for x in self.reverse_bytes().elements():
            x.reveal().print_reg()
    def update(self, other):
        other = self.conv(other)
        assert len(self.v) == len(other.v)
        for x, y in zip(self.v, other.v):
            if x is not y:
                x.update(y)

class bit(object):
    n = 1
    
def result_conv(x, y):
    try:
        def f(res):
            try:
                return t.conv(res)
            except:
                return res
        if util.is_constant(x):
            if util.is_constant(y):
                return lambda x: x
            else:
                t = type(y)
                return f
        if util.is_constant(y):
            t = type(x)
            return f
        if type(x) is type(y):
            t = type(x)
            return f
    except AttributeError:
        pass
    return lambda x: x

class sbit(bit, sbits):
    """ Single secret bit. """
    @classmethod
    def get_type(cls, length):
        return sbits.get_type(length)
    def if_else(self, x, y):
        """ Non-vectorized oblivious selection::

            sb32 = sbits.get_type(32)
            print_ln('%s', sbit(1).if_else(sb32(5), sb32(2)).reveal())

        This will output 5.
        """
        assert self.n == 1
        diff = x ^ y
        if isinstance(diff, cbits):
            return result_conv(x, y)(self & (diff) ^ y)
        else:
            return result_conv(x, y)(self * (diff) ^ y)

class cbit(bit, cbits):
    pass

sbits.bit_type = sbit
cbits.bit_type = cbit
sbit.clear_type = cbit
sbits.default_type = sbits

class bitsBlock(oram.Block):
    def __init__(self, value, start, lengths, entries_per_block):
        self.value_type = type(value)
        oram.Block.__init__(self, value, lengths)
        length = sum(self.lengths)
        used_bits = entries_per_block * length
        self.value_bits = self.value.bit_decompose(used_bits)
        start_length = util.log2(entries_per_block)
        self.start_bits = util.bit_decompose(start, start_length)
        self.start_demux = oram.demux_list(self.start_bits)
        self.entries = [sbits.bit_compose(self.value_bits[i*length:][:length]) \
                        for i in range(entries_per_block)]
        self.mul_entries = list(map(operator.mul, self.start_demux, self.entries))
        self.bits = sum(self.mul_entries).bit_decompose()
        self.mul_value = sbits.compose(self.mul_entries, sum(self.lengths))
        self.anti_value = self.mul_value + self.value
    def set_slice(self, value):
        value = sbits.compose(util.tuplify(value), sum(self.lengths))
        for i,b in enumerate(self.start_bits):
            value = b.if_else(value << (2**i * sum(self.lengths)), value)
        self.value = value + self.anti_value
        return self

oram.block_types[sbits] = bitsBlock

class dyn_sbits(sbits):
    pass

class DynamicArray(Array):
    def __init__(self, *args):
        Array.__init__(self, *args)
    def _malloc(self):
        return Program.prog.malloc(self.length, 'sd', self.value_type)
    def _load(self, address):
        return self.value_type.load_dynamic_mem(cbits.conv(address))
    def _store(self, value, address):
        if isinstance(value, MemValue):
            value = value.read()
        if isinstance(value, sbits):
            self.value_type.conv(value).store_in_dynamic_mem(address)
        else:
            cbits.conv(value).store_in_dynamic_mem(address)

sbits.dynamic_array = Array
cbits.dynamic_array = Array

def _complement_two_extend(bits, k):
    if len(bits) == 1:
        return bits + [0] * (k - len(bits))
    else:
        return bits[:k] + [bits[-1]] * (k - len(bits))

class _sbitintbase:
    def extend(self, n):
        bits = self.bit_decompose()
        bits += [bits[-1]] * (n - len(bits))
        return self.get_type(n).bit_compose(bits)
    def cast(self, n):
        bits = self.bit_decompose()[:n]
        bits += [bits[-1]] * (n - len(bits))
        return self.get_type(n).bit_compose(bits)
    def round(self, k, m, kappa=None, nearest=None, signed=None):
        bits = self.bit_decompose()
        if signed:
            bits += [bits[-1]] * (k - len(bits))
        res_bits = self.bit_adder(bits[m:k], [bits[m-1]])
        return self.get_type(k - m).compose(res_bits)
    def int_div(self, other, bit_length=None):
        k = bit_length or max(self.n, other.n)
        return (library.IntDiv(self.cast(k), other.cast(k), k) >> k).cast(k)
    def Norm(self, k, f, kappa=None, simplex_flag=False):
        absolute_val = abs(self)
        #next 2 lines actually compute the SufOR for little indian encoding
        bits = absolute_val.bit_decompose(k)[::-1]
        suffixes = floatingpoint.PreOR(bits)[::-1]
        z = [0] * k
        for i in range(k - 1):
            z[i] = suffixes[i] - suffixes[i+1]
        z[k - 1] = suffixes[k-1]
        z.reverse()
        t2k = self.get_type(2 * k)
        acc = t2k.bit_compose(z)
        sign = self.bit_decompose()[-1]
        signed_acc = util.if_else(sign, -acc, acc)
        absolute_val_2k = t2k.bit_compose(absolute_val.bit_decompose())
        part_reciprocal = absolute_val_2k * acc
        return part_reciprocal, signed_acc
    def pow2(self, k):
        l = int(math.ceil(math.log(k, 2)))
        bits = [self.equal(i, l) for i in range(k)]
        return self.get_type(k).bit_compose(bits)

class sbitint(_bitint, _number, sbits, _sbitintbase):
    """ Secret signed integer in one binary register. Use :py:obj:`get_type()`
    to specify the bit length::

        si32 = sbitint.get_type(32)
        print_ln('add: %s', (si32(5) + si32(3)).reveal())
        print_ln('sub: %s', (si32(5) - si32(3)).reveal())
        print_ln('mul: %s', (si32(5) * si32(3)).reveal())
        print_ln('lt: %s', (si32(5) < si32(3)).reveal())

    This should output::

        add: 8
        sub: 2
        mul: 15
        lt: 0

    This class is retained for compatibility, but development now
    focuses on :py:class:`sbitintvec`.

    """
    n_bits = None
    bin_type = None
    types = {}
    vector_mul = True
    @classmethod
    def get_type(cls, n, other=None):
        """ Returns a signed integer type with fixed length.

        :param n: length """
        if isinstance(other, sbitvec):
            return sbitvec
        if n in cls.types:
            return cls.types[n]
        sbits_type = sbits.get_type(n)
        class _(sbitint, sbits_type):
            # n_bits is used by _bitint
            n_bits = n
            bin_type = sbits_type
        _.__name__ = 'sbitint' + str(n)
        cls.types[n] = _
        return _
    @classmethod
    def combo_type(cls, other):
        if isinstance(other, sbitintvec):
            return sbitintvec
        else:
            return cls
    @classmethod
    def new(cls, value=None, n=None):
        return cls.get_type(n)(value)
    def set_length(*args):
        pass
    @classmethod
    def bit_compose(cls, bits):
        # truncate and extend bits
        bits = list(bits)[:cls.n]
        bits += [0] * (cls.n - len(bits))
        return super(sbitint, cls).bit_compose(bits)
    def force_bit_decompose(self, n_bits=None):
        return sbits.bit_decompose(self, n_bits)
    def TruncMul(self, other, k, m, kappa=None, nearest=False):
        if nearest:
            raise CompilerError('round to nearest not implemented')
        self_bits = self.bit_decompose()
        other_bits = other.bit_decompose()
        if len(self_bits) + len(other_bits) > k:
            raise Exception('invalid parameters for TruncMul: '
                            'self:%d, other:%d, k:%d' %
                            (len(self_bits), len(other_bits), k))
        t = self.get_type(k)
        a = t.bit_compose(self_bits + [self_bits[-1]] * (k - len(self_bits)))
        t = other.get_type(k)
        b = t.bit_compose(other_bits + [other_bits[-1]] * (k - len(other_bits)))
        product = a * b
        res_bits = product.bit_decompose()[m:k]
        res_bits += [res_bits[-1]] * (self.n - len(res_bits))
        t = self.combo_type(other).get_type(k - m)
        return t.bit_compose(res_bits)
    def __mul__(self, other):
        if isinstance(other, sbitintvec):
            return other * self
        else:
            return super(sbitint, self).__mul__(other)
    @classmethod
    def get_bit_matrix(cls, self_bits, other):
        n = len(self_bits)
        assert n == other.n
        res = []
        for i, bit in enumerate(self_bits):
            if util.is_zero(bit):
                res.append([0] * (n - i))
            else:
                if cls.vector_mul:
                    x = sbits.get_type(n - i)()
                    inst.andrs(n - i, x, other, bit)
                    res.append(x.bit_decompose(n - i))
                else:
                    res.append([(x & bit) for x in other.bit_decompose(n - i)])
        return res
    @classmethod
    def popcnt_bits(cls, bits):
        res = sbitintvec.popcnt_bits(bits).elements()[0]
        res = cls.conv(res)
        return res
    def pow2(self, k):
        """ Computer integer power of two.

        :param k: bit length of input """
        return _sbitintbase.pow2(self, k)

class sbitintvec(sbitvec, _bitint, _number, _sbitintbase):
    """
    Values and vectors of signed integers for parallel binary computation::

        si32 = sbitintvec.get_type(32)
        print_ln('add: %s', (si32(5) + si32(3)).reveal())
        print_ln('sub: %s', (si32(5) - si32(3)).reveal())
        print_ln('mul: %s', (si32(5) * si32(3)).reveal())
        print_ln('lt: %s', (si32(5) < si32(3)).reveal())

    This should output::

        add: 8
        sub: 2
        mul: 15
        lt: 0

    The following example uses vectors of size two::

        sb32 = sbits.get_type(32)
        siv32 = sbitintvec.get_type(32)
        a = siv32([sb32(3), sb32(5)])
        b = siv32([sb32(4), sb32(6)])
        c = (a + b).elements()
        print_ln('add: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a * b).elements()
        print_ln('mul: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a - b).elements()
        print_ln('sub: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a < b).elements()
        print_ln('lt: %s, %s', c[0].reveal(), c[1].reveal())

    This should output::

        add: 7, 11
        mul: 12, 30
        sub: -1, 11
        lt: 1, 1

    """
    bit_extend = staticmethod(_complement_two_extend)
    functions = {}
    @classmethod
    def popcnt_bits(cls, bits):
        return sbitvec.from_vec(bits).popcnt()
    def elements(self):
        return [sbitint.get_type(len(self.v))(x)
                for x in sbitvec.elements(self)]
    def __add__(self, other):
        if util.is_zero(other):
            return self
        try:
            a, b = self.expand(other)
        except:
            return NotImplemented
        if len(a) == 1:
            res = _bitint.bit_adder(a, b, get_carry=True)
            return self.get_type(32).from_vec(res, signed=False)
        return self.maybe_function(self.binary_add, a, b)
    __radd__ = __add__
    __sub__ = _bitint.__sub__
    def __rsub__(self, other):
        try:
            a, b = self.expand(other)
        except:
            return NotImplemented
        return self.from_vec(b) - self.from_vec(a)
    def __mul__(self, other):
        if isinstance(other, sbits):
            return self.from_vec(other * x for x in self.v)
        elif len(self.v) == 1:
            return other * self.v[0]
        elif isinstance(other, sbitfixvec):
            return NotImplemented
        try:
            my_bits, other_bits = self.expand(other, False, copy=True)
        except:
            return NotImplemented
        return self.maybe_function(self.binary_mul, my_bits, other_bits)
    @classmethod
    def maybe_function(cls, call, my_bits, other_bits, result_length=None):
        m = float('inf')
        uniform = True
        for x in itertools.chain(my_bits, other_bits):
            try:
                uniform &= type(x) == type(my_bits[0]) and x.n == my_bits[0].n
                m = min(m, x.n)
            except:
                pass
        if uniform and Program.prog.options.cisc:
            bl = len(my_bits)
            ol = result_length or bl
            key = call.__name__, ol, bl, len(other_bits)
            if key not in cls.functions:
                def instruction(*args):
                    res = call(args[ol:ol + bl], args[ol + bl:], args[0].n)
                    for x, y in zip(sbitvec.from_vec(res).v, args):
                        x.mov(y, x)
                instruction.__name__ = '%s%sx%s' % (call.__name__, bl, len(other_bits))
                cls.functions[key] = instructions_base.cisc(instruction, ol)
            res = [sbits.get_type(m)() for i in range(ol)]
            cls.functions[key](*(res + my_bits + other_bits))
            if result_length:
                return res
            else:
                return cls.from_vec(res)
        else:
            return call(my_bits, other_bits, m)
    @classmethod
    def binary_add(cls, a, b, m):
        return cls.from_vec(sbitint.bit_adder(a, b))
    @classmethod
    def binary_mul(cls, my_bits, other_bits, m):
        matrix = []
        for i, b in enumerate(other_bits):
            if m == 1:
                matrix.append([x * b for x in my_bits[:len(my_bits)-i]])
            else:
                matrix.append((
                    sbitvec.from_vec(my_bits[:len(my_bits)-i]) * b).v)
        v = sbitint.wallace_tree_from_matrix(matrix)
        return cls.from_vec(v[:len(my_bits)])
    __rmul__ = __mul__
    reduce_after_mul = lambda x: x
    def TruncMul(self, other, k, m, kappa=None, nearest=False):
        if nearest:
            raise CompilerError('round to nearest not implemented')
        if isinstance(other, int):
            b = other
        else:
            if not isinstance(other, sbitintvec):
                other = sbitintvec(other)
            b = self.get_type(k).from_vec(_complement_two_extend(other.v, k))
        a = self.get_type(k).from_vec(_complement_two_extend(self.v, k))
        tmp = a * b
        assert len(tmp.v) == k
        return self.get_type(k - m).from_vec(tmp.v[m:])
    def pow2(self, k):
        """ Computer integer power of two.

        :param k: bit length of input """
        return _sbitintbase.pow2(self, k)

sbits.vec = sbitvec
sbitint.vec = sbitintvec

class cbitfix(object):
    malloc = staticmethod(lambda *args: cbits.malloc(*args))
    n_elements = staticmethod(lambda: 1)
    conv = staticmethod(lambda x: x)
    load_mem = classmethod(lambda cls, *args: cls._new(
        cbits.get_type(cls.k).load_mem(*args), adjust=False))
    store_in_mem = lambda self, *args: self.v.store_in_mem(*args)
    mem_size = staticmethod(lambda *args: 1)
    size = 1
    @classmethod
    def _new(cls, value, adjust=True):
        if isinstance(value, list):
            return [cls._new(x) for x in value]
        res = cls()
        if cls.k < value.unit and adjust:
            bits = value.bit_decompose(cls.k)
            sign = bits[-1]
            value += (sign << (cls.k)) * -1
        res.v = value
        return res
    def output(self):
        v = self.v
        inst.print_float_plainb(v, cbits.get_type(32)(-self.f), cbits(0),
                                cbits(0), cbits(0))
    def __iter__(self):
        return iter([self])
    def error(*args, **kwargs):
        raise CompilerError(
            'Support for revealed fixed-point values in binary circuits '
            'is currently limited to simple outputs. '
            'Please file a feature request if you need this for an application.')
    __add__ = __mul__ = __sub__ = error

class sbitfix(_fix, _binary):
    """ Secret signed fixed-point number in one binary register.
    Use :py:obj:`set_precision()` to change the precision.

    This class is retained for compatibility, but development now
    focuses on :py:class:`sbitfixvec`.

    Example::

        print_ln('add: %s', (sbitfix(0.5) + sbitfix(0.3)).reveal())
        print_ln('mul: %s', (sbitfix(0.5) * sbitfix(0.3)).reveal())
        print_ln('sub: %s', (sbitfix(0.5) - sbitfix(0.3)).reveal())
        print_ln('lt: %s', (sbitfix(0.5) < sbitfix(0.3)).reveal())

    will output roughly::

        add: 0.800003
        mul: 0.149994
        sub: 0.199997
        lt: 0

    Note that the default precision (16 bits after the dot, 31 bits in
    total) only allows numbers up to :math:`2^{31-16-1} \\approx
    16000`. You can increase this using :py:func:`set_precision`.

    """
    float_type = type(None)
    clear_type = cbitfix
    @classmethod
    def set_precision(cls, f, k=None):
        super(sbitfix, cls).set_precision(f, k)
        cls.int_type = sbitint.get_type(cls.k)
    @classmethod
    def load_mem(cls, address, size=None):
        if size not in (None, 1):
            v = [cls.int_type.load_mem(address + i) for i in range(size)]
            return sbitfixvec._new(sbitintvec(v))
        else:
            return super(sbitfix, cls).load_mem(address)
    @classmethod
    def get_input_from(cls, player):
        """ Secret input from :py:obj:`player`.

        :param: player (int)
        """
        sbits._check_input_player(player)
        v = cls.int_type()
        inst.inputb(player, cls.k, cls.f, v)
        return cls._new(v)
    def __xor__(self, other):
        return type(self)._new(self.v ^ other.v)
    def __mul__(self, other):
        if isinstance(other, sbit):
            return type(self)._new(self.int_type(other * self.v))
        elif isinstance(other, sbitfixvec):
            return other * self
        else:
            return super(sbitfix, self).__mul__(other)
    __rxor__ = __xor__
    __rmul__ = __mul__
    @staticmethod
    def multipliable(other, k, f, size):
        class cls(_fix):
            int_type = sbitint.get_type(k)
            clear_type = cbitfix
        cls.set_precision(f, k)
        return cls._new(cls.int_type(other), k, f)

class sbitfixvec(_fix, _vec, _binary):
    """
    Values and vectors of fixed-point numbers for parallel binary computation::

        print_ln('add: %s', (sbitfixvec(0.5) + sbitfixvec(0.3)).reveal())
        print_ln('mul: %s', (sbitfixvec(0.5) * sbitfixvec(0.3)).reveal())
        print_ln('sub: %s', (sbitfixvec(0.5) - sbitfixvec(0.3)).reveal())
        print_ln('lt: %s', (sbitfixvec(0.5) < sbitfixvec(0.3)).reveal())

    will output roughly::

        add: 0.800003
        mul: 0.149994
        sub: 0.199997
        lt: 0

    Note that the default precision (16 bits after the dot, 31 bits in
    total) only allows numbers up to :math:`2^{31-16-1} \\approx
    16000`. You can increase this using :py:func:`set_precision`.

    Refer to the following example for the vector functionality::

        a = sbitfixvec([sbitfixvec(0.3), sbitfixvec(0.5)])
        b = sbitfixvec([sbitfixvec(0.4), sbitfixvec(0.6)])
        c = (a + b).elements()
        print_ln('add: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a * b).elements()
        print_ln('mul: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a - b).elements()
        print_ln('sub: %s, %s', c[0].reveal(), c[1].reveal())
        c = (a < b).elements()
        print_ln('lt: %s, %s', c[0].reveal(), c[1].reveal())

    This should output roughly::

        add: 0.699997, 1.10001
        mul: 0.119995, 0.300003
        sub: -0.0999908, -0.100021
        lt: 1, 1

    """
    float_type = type(None)
    clear_type = cbitfix
    rep_type = staticmethod(lambda x: x)
    @property
    def bit_type(self):
        return type(self.v.v[0])
    @classmethod
    def set_precision(cls, f, k=None):
        super(sbitfixvec, cls).set_precision(f=f, k=k)
        cls.int_type = sbitintvec.get_type(cls.k)
    @classmethod
    def get_input_from(cls, player, size=1):
        """ Secret input from :py:obj:`player`.

        :param: player (int)
        """
        return cls._new(cls.int_type.get_input_from(player, size=size,
                                                    f=cls.f))
    def __init__(self, value=None, k=None, *args, **kwargs):
        if isinstance(value, (list, tuple)):
            super(sbitfixvec, self).__init__(None, k=k, *args, **kwargs)
            self.int_type = sbitintvec.get_type(self.k)
            self.v = self.int_type.from_vec(sbitvec([x.v for x in value]).v)
        else:
            self.k = k or self.k
            self.int_type = sbitintvec.get_type(self.k)
            if isinstance(value, sbitvec):
                value = self.int_type(value)
            super(sbitfixvec, self).__init__(value, *args, **kwargs)
    def elements(self):
        return [sbitfixvec._new(x, f=self.f, k=self.k)
                for x in self.v.elements()]
    def mul(self, other):
        if isinstance(other, sbits):
            return self._new(self.v * other)
        else:
            return super(sbitfixvec, self).mul(other)
    def __xor__(self, other):
        if util.is_zero(other):
            return self
        return self._new(self.v ^ self.coerce(other).v)
    def __and__(self, other):
        return self._new(self.v & other.v)
    __rxor__ = __xor__
    @staticmethod
    def multipliable(other, k, f, size):
        class cls(_fix):
            int_type = sbitint.get_type(k)
            clear_type = cbitfix
        cls.set_precision(f, k)
        return cls._new(cls.int_type(other), k, f)

sbitfix.set_precision(16, 31)
sbitfixvec.set_precision(16, 31)

sbitfix.vec = sbitfixvec

class cbitfloat:
    def __init__(self, v, p, z, s, nan=0):
        self.v, self.p, self.z, self.s, self.nan = v, p, z, s, cbit.conv(nan)

    def output(self):
        inst.print_float_plainb(self.v, self.p, self.z, self.s, self.nan)
