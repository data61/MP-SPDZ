import math
from math import log, floor, ceil
from Compiler.instructions import *
from . import types
from . import comparison
from . import program
from . import util
from . import instructions_base

##
## Helper functions for floating point arithmetic
##


def two_power(n):
    if isinstance(n, int) and n < 31:
        return 2**n
    else:
        max = types.cint(1) << 31
        res = 2**(n%31)
        for i in range(n // 31):
            res *= max
        return res

def shift_two(n, pos):
    return n >> pos


def maskRing(a, k):
    shift = int(program.Program.prog.options.ring) - k
    if program.Program.prog.use_edabit():
        r_prime, r = types.sint.get_edabit(k)
    elif program.Program.prog.use_dabit:
        rr, r = zip(*(types.sint.get_dabit() for i in range(k)))
        r_prime = types.sint.bit_compose(rr)
    else:
        r = [types.sint.get_random_bit() for i in range(k)]
        r_prime = types.sint.bit_compose(r)
    c = ((a + r_prime) << shift).reveal(False) >> shift
    return c, r

def maskField(a, k):
    r_dprime = types.sint()
    r_prime = types.sint()
    c = types.cint()
    r = [types.sint() for i in range(k)]
    comparison.PRandM(r_dprime, r_prime, r, k, k)
    # always signed due to usage in equality testing
    a += two_power(k)
    asm_open(True, c, a + two_power(k) * r_dprime + r_prime)
    return c, r

@instructions_base.ret_cisc
def EQZ(a, k):
    prog = program.Program.prog
    if prog.use_split():
        prog.reading('equality', 'ABY3')
        from Compiler.GC.types import sbitvec
        v = sbitvec(a, k).v
        bit = util.tree_reduce(operator.and_, (~b for b in v))
        return types.sintbit.conv(bit)
    prog.reading('equality', 'CdH10', 'Protocol 3.7')
    return prog.non_linear.eqz(a, k)

def bits(a,m):
    """ Get the bits of an int """
    if isinstance(a, int):
        res = [None]*m
        for i in range(m):
            res[i] = a & 1
            a >>= 1
    else:
        res = []
        from Compiler.types import regint, cint
        while m > 0:
            aa = regint()
            convmodp(aa, a, 0, bitlength=0)
            res += [cint(x) for x in aa.bit_decompose(min(64, m))]
            m -= 64
            if m > 0:
                aa = cint()
                shrci(aa, a, 64)
                a = aa
    return res

def carry(b, a, compute_p=True):
    """ Carry propagation:
        (p,g) = (p_2, g_2)o(p_1, g_1) -> (p_1 & p_2, g_2 | (p_2 & g_1))
    """
    if compute_p:
        t1 = util.bit_and(a[0], b[0])
    else:
        t1 = None
    t2 = a[1] + util.bit_and(a[0], b[1])
    return (t1, t2)

def or_op(a, b, void=None):
    return util.or_op(a, b)

def mul_op(a, b, void=None):
    return a * b

def PreORC(a, m=None, raw=False):
    k = len(a)
    if k == 1:
        return [a[0]]
    prog = program.Program.prog
    kappa = prog.security
    m = m or k
    if isinstance(a[0], types.sgf2n):
        max_k = program.Program.prog.galois_length - 1
    else:
        # assume prime length is power of two
        prime_length = 2 ** int(ceil(log(prog.bit_length + kappa, 2)))
        max_k = prime_length - kappa - 2
    assert(max_k > 0)
    if k <= max_k:
        p = [None] * m
        if m == k:
            p[0] = a[0]
        if isinstance(a[0], types.sgf2n):
            b = comparison.PreMulC([3 - a[i] for i in range(k)])
            for i in range(m):
                tmp = b[k-1-i]
                if not raw:
                    tmp = tmp.bit_decompose()[0]
                p[m-1-i] = 1 - tmp
        else:
            t = [types.sint() for i in range(m)]
            b = comparison.PreMulC([a[i] + 1 for i in range(k)])
            for i in range(m):
                comparison.Mod2(t[i], b[k-1-i], k, False)
                p[m-1-i] = 1 - t[i]
        return p
    else:
        # not constant-round anymore
        s = [PreORC(a[i:i+max_k], raw=raw) for i in range(0,k,max_k)]
        t = PreORC([si[-1] for si in s[:-1]], raw=raw)
        return sum(([or_op(x, y) for x in si]
                    for si,y in zip(s[1:],t)), s[0])[-m:]

def PreOpL(op, items):
    """
    Uses algorithm from SecureSCM WP9 deliverable.
    
    op must be a binary function that outputs a new register
    """
    k = len(items)
    logk = int(ceil(log(k,2)))
    kmax = 2**logk
    output = list(items)
    for i in range(logk):
        for j in range(kmax//(2**(i+1))):
            y = two_power(i) + j*two_power(i+1) - 1
            for z in range(1, 2**i+1):
                if y+z < k:
                    output[y+z] = op(output[y], output[y+z], j != 0)
    return output

def PreOpL2(op, items):
    """
    Uses algorithm from SecureSCM WP9 deliverable.

    op must be a binary function that outputs a new register
    """
    k = len(items)
    half = k // 2
    output = list(items)
    if k == 0:
        return []
    u = [op(items[2 * i], items[2 * i + 1]) for i in range(half)]
    v = PreOpL2(op, u)
    for i in range(half):
        output[2 * i + 1] = v[i]
    for i in range(1,  (k + 1) // 2):
        output[2 * i] = op(v[i - 1], items[2 * i])
    return output

def PreOpL2_vec(op, *items):
    """ Vectorized version of :py:func:`PreOpL2` """
    k = len(items[0])
    for x in items:
        assert len(x) == k
    if k == 1:
        return items
    half = k // 2
    other_half = (k + 1) // 2 - 1
    u = op([x.get_vector(base=0, size=half, skip=2) for x in items],
           [x.get_vector(base=1, size=half, skip=2) for x in items])
    assert len(u) == len(items)
    assert len(u[0]) == half
    v = PreOpL2_vec(op, *u)
    if other_half:
        w = op([x.get_vector(base=0, size=other_half) for x in v],
               [x.get_vector(base=2, size=other_half, skip=2) for x in items])
    if half == other_half:
        res = [type(x).zip(x, y) for x, y in zip(v, w)]
        for i in range(len(res)):
            res[i] = type(res[i]).concat((items[i].get_vector(base=0, size=1),
                                          res[i]))
    else:
        if other_half:
            for i in range(len(w)):
                w[i] = type(w[i]).concat((items[i].get_vector(base=0, size=1),
                                          w[i]))
        else:
            w = [x.get_vector(base=0, size=1) for x in items]
        res = [type(x).zip(x, y) for x, y in zip(w, v)]
    assert len(res) == len(items)
    for x in res:
        assert len(x) == k
    return res

def PreOpN(op, items):
    """ Naive PreOp algorithm """
    k = len(items)
    output = [None]*k
    output[0] = items[0]
    for i in range(1, k):
        output[i] = op(output[i-1], items[i])
    return output

def PreOR(a=None, raw=False):
    if comparison.const_rounds and a and isinstance(a[0], types._secret):
        return PreORC(a, raw=raw)
    else:
        return PreOpL(or_op, a)

def KOpL(op, a):
    k = len(a)
    if k == 1:
        return a[0]
    else:
        t1 = KOpL(op, a[:k//2])
        t2 = KOpL(op, a[k//2:])
        return op(t1, t2)

def KORL(a):
    """ log rounds k-ary OR """
    k = len(a)
    if k == 1:
        return a[0]
    else:
        t1 = KORL(a[:k//2])
        t2 = KORL(a[k//2:])
        return t1 + t2 - t1.bit_and(t2)

def KORC(a):
    return PreORC(a, 1)[0]

def KOR(a):
    if comparison.const_rounds:
        return KORC(a)
    else:
        return KORL(a)

def KMul(a):
    if comparison.const_rounds:
        return comparison.KMulC(a)
    else:
        return KOpL(mul_op, a)


def Inv(a):
    """ Invert a non-zero value """
    t = [types.sint() for i in range(3)]
    c = [types.cint() for i in range(2)]
    one = types.cint()
    ldi(one, 1)
    inverse(t[0], t[1])
    s = t[0]*a
    asm_open(True, c[0], s)
    # avoid division by zero for benchmarking
    divc(c[1], one, c[0])
    #divc(c[1], c[0], one)
    return c[1]*t[0]

def BitAdd(a, b, bits_to_compute=None):
    """ Add the bits a[k-1], ..., a[0] and b[k-1], ..., b[0], return k+1
        bits s[0], ... , s[k] """
    k = len(a)
    if not bits_to_compute:
        bits_to_compute = list(range(k))
    d = [None] * k
    for i in range(1,k):
        t = a[i]*b[i]
        d[i] = (a[i] + b[i] - 2*t, t)
    d[0] = (None, a[0]*b[0])
    pg = PreOpL(carry, d)
    c = [pair[1] for pair in pg]
    
    s = [None] * (k+1)
    if 0 in bits_to_compute:
        s[0] = a[0] + b[0] - 2*c[0]
        bits_to_compute.remove(0)
    for i in bits_to_compute:
        s[i] = a[i] + b[i] + c[i-1] - 2*c[i]
    s[k] = c[k-1]
    return s

def BitDec(a, k, m, bits_to_compute=None):
    return program.Program.prog.non_linear.bit_dec(a, k, m)

def BitDecRingRaw(a, k, m):
    prog = program.Program.prog
    comparison.require_ring_size(m, 'bit decomposition')
    n_shift = int(program.Program.prog.options.ring) - m
    if program.Program.prog.use_split():
        prog.reading('bit decomposition', 'ABY3')
        x = a.split_to_two_summands(m)
        bits = types._bitint.bit_adder(x[0], x[1])
        assert len(bits) >= m
        return bits[:m]
    else:
        if program.Program.prog.use_edabit():
            r, r_bits = types.sint.get_edabit(m, strict=False, size=a.size)
        elif program.Program.prog.use_dabit:
            r, r_bits = zip(*(types.sint.get_dabit(size=a.size)
                              for i in range(m)))
            r = types.sint.bit_compose(r)
        else:
            r_bits = [types.sint.get_random_bit() for i in range(m)]
            r = types.sint.bit_compose(r_bits)
        shifted = ((a - r) << n_shift).reveal(False)
        masked = shifted >> n_shift
        bits = r_bits[0].bit_adder(r_bits, masked.bit_decompose(m),
                                   get_carry=False)
        assert len(bits) == m
        return bits

@instructions_base.bit_cisc
def BitDecRing(a, k, m):
    bits = BitDecRingRaw(a, k, m)
    # reversing to reduce number of rounds
    return [types.sintbit.conv(bit) for bit in reversed(bits)][::-1]

def BitDecFieldRaw(a, k, m, bits_to_compute=None):
    comparison.program.reading('bit decomposition', 'CdH10-fixed',
                               'Protocol 3.7')
    instructions_base.set_global_vector_size(a.size)
    r_dprime = types.sint()
    r_prime = types.sint()
    c = types.cint()
    r = [types.sint() for i in range(m)]
    comparison.PRandM(r_dprime, r_prime, r, k, m)
    kappa = program.Program.prog.security
    pow2 = two_power(k + kappa)
    asm_open(True, c, pow2 + two_power(k) + a - two_power(m)*r_dprime - r_prime)
    res = r[0].bit_adder(r, list(r[0].bit_decompose_clear(c,m)))
    instructions_base.reset_global_vector_size()
    return res

@instructions_base.bit_cisc
def BitDecField(a, k, m, bits_to_compute=None):
    res = BitDecFieldRaw(a, k, m, bits_to_compute)
    return [types.sintbit.conv(bit) for bit in res]


@instructions_base.ret_cisc
def Pow2(a, l):
    comparison.program.curr_tape.require_bit_length(l - 1)
    m = int(ceil(log(l, 2)))
    t = BitDec(a, m, m)
    return Pow2_from_bits(t)

def Pow2_from_bits(bits):
    comparison.program.reading('power of two', 'ABZS13', 'Section 3')
    m = len(bits)
    t = list(bits)
    pow2k = [None for i in range(m)]
    for i in range(m):
        pow2k[i] = two_power(2**i)
        t[i] = t[i]*pow2k[i] + 1 - t[i]
    return KMul(t)

def B2U(a, l):
    pow2a = Pow2(a, l)
    return B2U_from_Pow2(pow2a, l), pow2a

def B2U_from_Pow2(pow2a, l):
    kappa = program.Program.prog.security
    r = [types.sint() for i in range(l)]
    t = types.sint()
    c = types.cint()
    if program.Program.prog.use_dabit:
        r, r_bits = zip(*(types.sint.get_dabit() for i in range(l)))
    else: 
        for i in range(l):
            bit(r[i])
        r_bits = r
    if program.Program.prog.options.ring:
        n_shift = int(program.Program.prog.options.ring) - l
        assert n_shift > 0
        c = ((pow2a + types.sint.bit_compose(r)) << n_shift).reveal(False) >> n_shift
    else:
        comparison.PRandInt(t, kappa)
        asm_open(True, c, pow2a + two_power(l) * t +
                 sum(two_power(i) * r[i] for i in range(l)))
        comparison.program.curr_tape.require_bit_length(l + kappa)
    c = list(r_bits[0].bit_decompose_clear(c, l))
    x = [r_bits[i].bit_xor(c[i]) for i in range(l)]
    #print ' '.join(str(b.value) for b in x)
    y = PreOR(x)
    #print ' '.join(str(b.value) for b in y)
    return [types.sint.conv(1 - y[i]) for i in range(l)]

def Trunc(a, l, m, compute_modulo=False, signed=False):
    """ Oblivious truncation by secret m """
    prog = program.Program.prog
    if util.is_constant(m) and not compute_modulo:
        # cheaper
        res = type(a)(size=a.size)
        comparison.Trunc(res, a, l, m, signed=signed)
        return res
    if l == 1:
        if compute_modulo:
            return a * m, 1 + m
        else:
            return a * (1 - m)
    if program.Program.prog.options.ring and not compute_modulo:
        return TruncInRing(a, l, Pow2(m, l))
    else:
        kappa = program.Program.prog.security
    prog.reading('secret truncation', 'ABZS13', 'Section 3')
    r = [types.sint() for i in range(l)]
    r_dprime = types.sint(0)
    r_prime = types.sint(0)
    rk = types.sint()
    c = types.cint()
    ci = [types.cint() for i in range(l)]
    d = types.sint()
    x, pow2m = B2U(m, l)
    for i in range(l):
        bit(r[i])
        t1 = two_power(i) * r[i]
        t2 = t1*x[i]
        r_prime += t2
        r_dprime += t1 - t2
    if program.Program.prog.options.ring:
        n_shift = int(program.Program.prog.options.ring) - l
        c = ((a + r_dprime + r_prime) << n_shift).reveal(False) >> n_shift
    else:
        comparison.PRandInt(rk, kappa)
        r_dprime += two_power(l) * rk
        asm_open(True, c, a + r_dprime + r_prime)
    for i in range(1,l):
        ci[i] = c % two_power(i)
    c_dprime = sum(ci[i]*(x[i-1] - x[i]) for i in range(1,l))
    d = program.Program.prog.non_linear.ltz(c_dprime - r_prime, l)
    if compute_modulo:
        b = c_dprime - r_prime + pow2m * d
        return b, pow2m
    else:
        to_shift = a - c_dprime + r_prime
        if program.Program.prog.options.ring:
            shifted = TruncInRing(to_shift, l, pow2m)
        else:
            pow2inv = Inv(pow2m)
            shifted = to_shift * pow2inv
        b = shifted - d
    return b

@instructions_base.ret_cisc
def TruncInRing(to_shift, l, pow2m):
    comparison.program.reading('secret truncation', 'DEK20', 'Section 3.2.3')
    n_shift = int(program.Program.prog.options.ring) - l
    bits = util.bit_decompose(to_shift, l)
    rev = types.sint.bit_compose(reversed(bits))
    rev <<= n_shift
    rev *= pow2m
    r_bits = [types.sint.get_random_bit() for i in range(l)]
    r = types.sint.bit_compose(r_bits)
    shifted = (rev - (r << n_shift)).reveal(False)
    masked = shifted >> n_shift
    bits = types.intbitint.bit_adder(r_bits, masked.bit_decompose(l))
    return types.sint.bit_compose(reversed(bits))

def SplitInRing(a, l, m):
    if l == 1:
        return m.if_else(a, 0), m.if_else(0, a), 1
    pow2m = Pow2(m, l)
    upper = TruncInRing(a, l, pow2m)
    lower = a - upper * pow2m
    return lower, upper, pow2m

def TruncRoundNearestAdjustOverflow(a, length, target_length):
    t = comparison.TruncRoundNearest(a, length, length - target_length)
    overflow = t.greater_equal(two_power(target_length), target_length + 1)
    s = (1 - overflow) * t + overflow * t.trunc_zeros(1, length, False)
    return s, overflow

def Int2FL(a, gamma, l):
    lam = gamma - 1
    s = a.less_than(0, gamma)
    z = a.equal(0, gamma)
    a = s.if_else(-a, a)
    a_bits = a.bit_decompose(lam)
    a_bits.reverse()
    b = PreOR(a_bits)
    t = a * (1 + a.bit_compose(1 - b_i for b_i in b))
    p = a.popcnt_bits(b) - lam
    if gamma - 1 > l:
        if types.sfloat.round_nearest:
            v, overflow = TruncRoundNearestAdjustOverflow(t, gamma - 1, l)
            p = p + overflow
        else:
            v = t.right_shift(gamma - l - 1, gamma - 1, signed=False)
    else:
        v = 2**(l-gamma+1) * t
    p = (p + gamma - 1 - l) * z.bit_not()
    return v, p, z, s

def FLRound(x, mode):
    """ Rounding with floating point output.
    *mode*: 0 -> floor, 1 -> ceil, -1 > trunc """
    v1, p1, z1, s1, l, k = x.v, x.p, x.z, x.s, x.vlen, x.plen
    a = types.sint()
    comparison.LTZ(a, p1, k)
    b = p1.less_than(-l + 1, k)
    v2, inv_2pow_p1 = Trunc(v1, l, -a * (1 - b) * x.p, compute_modulo=True)
    c = EQZ(v2, l)
    if mode == -1:
        away_from_zero = 0
        mode = x.s
    else:
        away_from_zero = mode + s1 - 2 * mode * s1
    v = v1 - v2 + (1 - c) * inv_2pow_p1 * away_from_zero
    d = v.equal(two_power(l), l + 1)
    v = d * two_power(l-1) + (1 - d) * v
    v = a * ((1 - b) * v + b * away_from_zero * two_power(l-1)) + (1 - a) * v1
    s = (1 - b * mode) * s1
    z = or_op(EQZ(v, l), z1)
    v = v * (1 - z)
    p = ((p1 + d * a) * (1 - b) + b * away_from_zero * (1 - l)) * (1 - z)
    return v, p, z, s

@instructions_base.ret_cisc
def TruncPr(a, k, m, signed=True):
    """ Probabilistic truncation [a/2^m + u]
        where Pr[u = 1] = (a % 2^m) / 2^m
    """
    nl = program.Program.prog.non_linear
    return nl.trunc_pr(a, k, m, signed)

def TruncPrRing(a, k, m, signed=True):
    if m == 0:
        return a
    prog = program.Program.prog
    prog.trunc_pr_warning()
    n_ring = int(program.Program.prog.options.ring)
    comparison.require_ring_size(k, 'truncation')
    if k == n_ring:
        program.Program.prog.curr_tape.require_bit_length(1)
        if program.Program.prog.use_edabit():
            a += types.sint.get_edabit(m, True)[0]
        else:
            for i in range(m):
                a += types.sint.get_random_bit() << i
        return comparison.TruncLeakyInRing(a, k, m, signed=signed)
    else:
        from .types import sint
        prog = program.Program.prog
        if signed:
            a += (1 << (k - 1))
        if False:
            res = sint()
            trunc_pr(res, a, k, m)
        else:
            prog.reading('probabilistic truncation', 'CdH10-fixed',
                         'Protocol 3.1')
            # extra bit to mask overflow
            prog.curr_tape.require_bit_length(1)
            if prog.use_edabit() or prog.use_split() > 2:
                lower = sint.get_random_int(m)
                upper = sint.get_random_int(k - m)
                msb = sint.get_random_bit()
                r = (msb << k) + (upper << m) + lower
            else:
                r_bits = [sint.get_random_bit() for i in range(k + 1)]
                r = sint.bit_compose(r_bits)
                upper = sint.bit_compose(r_bits[m:k])
                msb = r_bits[-1]
            n_shift = n_ring - (k + 1)
            tmp = a + r
            masked = (tmp << n_shift).reveal(False)
            shifted = (masked << 1 >> (n_shift + m + 1))
            overflow = msb.bit_xor(masked >> (n_ring - 1))
            res = shifted - upper + \
                  (overflow << (k - m))
        if signed:
            res -= (1 << (k - m - 1))
        return res

def TruncPrField(a, k, m):
    if m == 0:
        return a

    program.Program.prog.trunc_pr_warning()
    prog = program.Program.prog
    prog.reading('probabilistic truncation', 'CdH10-fixed', 'Protocol 3.1')
    b = two_power(k-1) + a
    r_prime, r_dprime = types.sint(), types.sint()
    comparison.PRandM(r_dprime, r_prime, [types.sint() for i in range(m)],
                      k, m, use_dabit=False)
    two_to_m = two_power(m)
    r = two_to_m * r_dprime + r_prime
    c = (b + r).reveal(True)
    c_prime = c % two_to_m
    a_prime = c_prime - r_prime
    d = (a - a_prime).field_div(two_to_m)
    return d

@instructions_base.ret_cisc
def SDiv(a, b, l, round_nearest=False):
    theta = int(ceil(log(l / 3.5) / log(2)))
    alpha = two_power(2*l)
    w = types.cint(int(2.9142 * 2 ** l)) - 2 * b
    x = alpha - b * w
    y = a * w
    y = y.round(2 * l + 1, l, nearest=round_nearest, signed=False)
    x2 = types.sint()
    comparison.Mod2m(x2, x, 2 * l + 1, l, signed=True)
    x1 = comparison.TruncZeros(x - x2, 2 * l + 1, l, True)
    for i in range(theta-1):
        y = y * (x1 + two_power(l)) + (y * x2).round(2 * l, l,
                                                     nearest=round_nearest,
                                                     signed=False)
        y = y.round(2 * l + 1, l, nearest=round_nearest, signed=False)
        x = x1 * x2 + (x2**2).round(2 * l + 1, l + 1, nearest=round_nearest,
                                    signed=False)
        x = x1 * x1 + x.round(2 * l + 1, l - 1, nearest=round_nearest,
                              signed=False)
        x2 = types.sint()
        comparison.Mod2m(x2, x, 2 * l, l, signed=False)
        x1 = comparison.TruncZeros(x - x2, 2 * l + 1, l, True)
    y = y * (x1 + two_power(l)) + (y * x2).round(2 * l, l, nearest=round_nearest,
                                                 signed=False)
    y = y.round(2 * l + 1, l + 1, nearest=round_nearest, signed=False)
    return y

def SDiv_mono(a, b, l):
    theta = int(ceil(log(l / 3.5) / log(2)))
    alpha = two_power(2*l)
    w = types.cint(int(2.9142 * two_power(l))) - 2 * b
    x = alpha - b * w
    y = a * w
    y = TruncPr(y, 2 * l + 1, l + 1)
    for i in range(theta-1):
        y = y * (alpha + x)
        # keep y with l bits
        y = TruncPr(y, 3 * l, 2 * l)
        x = x**2
        # keep x with 2l bits
        x = TruncPr(x, 4 * l, 2 * l)
    y = y * (alpha + x)
    y = TruncPr(y, 3 * l, 2 * l)
    return y

# LT bit comparison on shared bit values
#  Assumes b has the larger size
#   - From the paper
#        Unconditionally Secure Constant-Rounds Multi-party Computation
#        for Equality, Comparison, Bits and Exponentiation
def BITLT(a, b, bit_length):
    from .types import sint, regint, longint, cint
    e = [None]*bit_length
    g = [None]*bit_length
    h = [None]*bit_length
    for i in range(bit_length):
        # Compute the XOR (reverse order of e for PreOpL)
        e[bit_length-i-1] = util.bit_xor(a[i], b[i])
    f = PreOpL(or_op, e)
    g[bit_length-1] = f[0]
    for i in range(bit_length-1):
        # reverse order of f due to PreOpL
        g[i] = f[bit_length-i-1]-f[bit_length-i-2]
    ans = 0
    for i in range(bit_length):
        h[i] = g[i].bit_and(b[i])
        ans = ans + h[i]
    return ans

# Exact BitDec with no need for a statistical gap
#   - From the paper
#        Multiparty Computation for Interval, Equality, and Comparison without 
#        Bit-Decomposition Protocol
def BitDecFull(a, n_bits=None, maybe_mixed=False):
    from .library import get_program, do_while, if_, break_point
    from .types import sint, regint, longint, cint
    get_program().reading('full bit decomposition', 'NO07', 'Figure 2')
    p = get_program().prime
    assert p
    bit_length = p.bit_length()
    n_bits = n_bits or bit_length
    assert n_bits <= bit_length
    if get_program().rabbit_gap():
        # inspired by Rabbit (https://eprint.iacr.org/2021/119)
        # no need for exact randomness generation
        # if modulo a power of two is close enough
        logp = int(round(math.log(p, 2)))
        if get_program().use_edabit():
            b, bbits = sint.get_edabit(logp, True, size=a.size)
            if logp != bit_length:
                from .GC.types import sbits
                bbits += [0]
        else:
            bbits = [sint.get_random_bit(size=a.size) for i in range(logp)]
            b = sint.bit_compose(bbits)
            if logp != bit_length:
                bbits += [sint(0, size=a.size)]
    else:
        if maybe_mixed:
            from .GC.types import sbitvec, sbit, sbits
            bs = [sint() for j in range(a.size)]
            tbits = [sbitvec.from_vec(sbit() for i in range(bit_length))
                     for j in range(a.size)]
        else:
            bbits = [sint(size=a.size) for i in range(bit_length)]
            tbits = [[sint(size=1) for i in range(bit_length)]
                     for j in range(a.size)]
        pbits = util.bit_decompose(p)
        # Loop until we get some random integers less than p
        done = [regint(0) for i in range(a.size)]
        from Compiler import library
        closeness = max(1, -math.log(2 ** bit_length / p - 1, 2))
        assert closeness > 0
        @library.for_range(int(
            max(40, math.ceil(get_program().security) / closeness)))
        def get_bits_loop(_):
            for j in range(a.size):
                @if_(done[j] == 0)
                def _():
                    if maybe_mixed:
                        r = sint.get_edabit(bit_length, True)
                        bs[j].link(r[0])
                        tbits[j].link(sbitvec.from_vec(r[1]))
                        tbits[j] = tbits[j].v
                    else:
                        for i in range(bit_length):
                            tbits[j][i].link(sint.get_random_bit())
                    c = regint(BITLT(tbits[j], pbits, bit_length).reveal(False))
                    done[j].link(c)
            library.runtime_error_if((sum(done) < 0) + (sum(done) > a.size))
            return (sum(done) != a.size)
        library.runtime_error_if(sum(done) != a.size, 'bad luck in bit decomposition')
        if maybe_mixed:
            b = sint(bs)
            bbits = [sbits.get_type(a.size).bit_compose(
                tbits[j][i] for j in range(a.size)) for i in range(bit_length)]
        else:
            for j in range(a.size):
                for i in range(bit_length):
                    movs(bbits[i][j], tbits[j][i])
            b = sint.bit_compose(bbits)
    c = (a-b).reveal(False)
    cmodp = c
    t = bbits[0].bit_decompose_clear(p - c, bit_length)
    c = longint(c, bit_length)
    czero = (c==0)
    q = bbits[0].long_one() - comparison.BitLTL_raw(bbits, t)
    fbar = [bbits[0].clear_type.conv(cint(x))
            for x in ((1<<bit_length)+c-p).bit_decompose(n_bits)]
    fbard = bbits[0].bit_decompose_clear(cmodp, n_bits)
    g = [q.if_else(fbar[i], fbard[i]) for i in range(n_bits)]
    h = bbits[0].bit_adder(bbits, g)
    abits = [bbits[0].clear_type(cint(czero)).if_else(bbits[i], h[i])
             for i in range(n_bits)]
    if maybe_mixed:
        return abits
    else:
        return [sint.conv(bit) for bit in abits]

