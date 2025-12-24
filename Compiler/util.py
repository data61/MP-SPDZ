import math
import operator
from functools import reduce
from Compiler.exceptions import *

def format_trace(trace, prefix='  '):
    if trace is None:
        return '<omitted>'
    else:
        return ''.join('\n%sFile "%s", line %s, in %s\n%s  %s' %
                       (prefix,i[0],i[1],i[2],prefix,i[3][0].strip()) \
                           for i in reversed(trace))

def tuplify(x):
    if isinstance(x, (list, tuple)):
        return tuple(x)
    else:
        return (x,)

def untuplify(x):
    if len(x) == 1:
        return x[0]
    else:
        return x

def greater_than(a, b, bits):
    if isinstance(a, int) and isinstance(b, int):
        return a > b
    else:
        return a.greater_than(b, bits)

def pow2_value(a, bit_length=None):
    if is_constant_float(a):
        return 2**a
    else:
        return a.pow2(bit_length)

def mod2m(a, b, bits, signed):
    if isinstance(a, int):
        return a % 2**b
    else:
        return a.mod2m(b, bits, signed=signed)

def trunc_zeros(a, n_zeros, bit_length=None):
    if isinstance(a, int):
        return a >> n_zeros
    else:
        return a.trunc_zeros(n_zeros, bit_length)

def right_shift(a, b, bits):
    if isinstance(a, int):
        return a >> b
    else:
        return a.right_shift(b, bits)

def bit_decompose(a, bits=None):
    if isinstance(a, int):
        if bits is None:
            bits = int_len(a)
        return [int((a >> i) & 1) for i in range(bits)]
    else:
        return a.bit_decompose(bits)

def bit_compose(bits):
    bits = list(bits)
    try:
        if bits:
            return bits[0].bit_compose(bits)
        else:
            return 0
    except AttributeError:
        return sum(b << i for i,b in enumerate(bits))

def series(a):
    sum = 0
    for i in a:
        yield sum
        sum += i
    yield sum

def if_else(cond, a, b):
    try:
        if a is b:
            return a
        if isinstance(cond, (bool, int)):
            if cond:
                return a
            else:
                return b
        if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
            return [if_else(cond, x, y) for x, y in zip(a, b)]
        else:
            return cond.if_else(a, b)
    except:
        raise CompilerError(
            'incompatible types for ternary/if-else operator: %s' % '/'.join(
                type(x).__name__ for x in (cond, a, b)))

def cond_swap(cond, a, b):
    if isinstance(cond, (bool, int)):
        if cond:
            return a, b
        else:
            return b, a
    return cond.cond_swap(a, b)

def log2(x):
    #print 'Compute log2 of', x
    if is_constant_float(x):
        return int(math.ceil(math.log(x, 2)))
    else:
        return x.log2()

def round_to_int(x):
    if is_constant_float(x):
        return int(round(x))
    else:
        return x.round_to_int()

def tree_reduce(function, sequence):
    try:
        return sequence.tree_reduce(function)
    except AttributeError:
        pass

    sequence = list(sequence)
    assert len(sequence) > 0
    n = len(sequence)
    if n == 1:
        return sequence[0]
    else:
        reduced = [function(sequence[2*i], sequence[2*i+1]) for i in range(n//2)]
        return tree_reduce(function, reduced + sequence[n//2*2:])

def or_op(a, b):
    return a + b - bit_and(a, b)

OR = or_op

def bit_xor(a, b):
    if is_constant(a):
        if is_constant(b):
            return a ^ b
        else:
            return b.bit_xor(a)
    else:
        return a.bit_xor(b)

def bit_and(a, b):
    if is_constant(a):
        if is_constant(b):
            return a & b
        else:
            return b.bit_and(a)
    else:
        return a.bit_and(b)

def bit_not(a, n):
    if is_constant(a):
        return ~a & (2 ** n - 1)
    else:
        return a.bit_not()

def pow2(bits):
    powers = [b.if_else(2**2**i, 1) for i,b in enumerate(bits)]
    return tree_reduce(operator.mul, powers)

def irepeat(l, n):
    return reduce(operator.add, ([i] * n for i in l))

def int_len(x):
    return len(bin(x)) - 2

def reveal(x):
    if isinstance(x, str):
        return x
    try:
        return x.reveal()
    except AttributeError:
        pass
    try:
        return [reveal(y) for y in x]
    except TypeError:
        pass
    return x

def is_constant(x):
    return isinstance(x, (int, bool))

def is_constant_float(x):
    return isinstance(x, float) or is_constant(x)

def is_zero(x):
    return is_constant(x) and x == 0

def is_one(x):
    return is_constant(x) and x == 1

def is_all_ones(x, n):
    if is_constant(x):
        return x == 2**n - 1
    else:
        return False

def max(x, y=None, n_threads=None):
    if y is None:
        return tree_reduce(max, x)
    else:
        return if_else(x > y, x, y)

def min(x, y=None):
    if y is None:
        return tree_reduce(min, x)
    else:
        return if_else(x < y, x, y)

def long_one(x):
    try:
        return x.long_one()
    except:
        try:
            for y in x:
                try:
                    return y.long_one()
                except:
                    pass
        except:
            pass
    return 1

def expand(x, size):
    try:
        return x.expand_to_vector(size)
    except AttributeError:
        return x

def mem_size(x):
    try:
        return x.mem_size()
    except AttributeError:
        return 1

def find_in_dict(d, v):
    return list(d.keys())[list(d.values()).index(v)]

class set_by_id(object):
    def __init__(self, init=[]):
        self.content = {}
        for x in init:
            self.add(x)

    def __contains__(self, value):
        return id(value) in self.content

    def __iter__(self):
        return iter(self.content.values())

    def __bool__(self):
        return bool(self.content)

    def __len__(self):
        return len(self.content)

    def add(self, value):
        self.content[id(value)] = value

    def pop(self):
        return self.content.popitem()[1]

    def remove(self, value):
        del self.content[id(value)]

    def __ior__(self, values):
        for value in values:
            self.add(value)
        return self

class dict_by_id(object):
    def __init__(self):
        self.content = {}

    def __contains__(self, key):
        return id(key) in self.content

    def __getitem__(self, key):
        return self.content[id(key)][1]

    def __setitem__(self, key, value):
        self.content[id(key)] = (key, value)

    def keys(self):
        return (x[0] for x in self.content.values())

    def __iter__(self):
        return self.keys()

    def pop(self, key):
        return self.content.pop(id(key), None)

class defaultdict_by_id(dict_by_id):
    def __init__(self, default):
        dict_by_id.__init__(self)
        self.default = default

    def __getitem__(self, key):
        if key not in self:
            self[key] = self.default()
        return dict_by_id.__getitem__(self, key)
