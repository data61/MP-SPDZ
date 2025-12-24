"""
Functions for secure comparison of GF(p) types.
Most protocols come from [1], with a few subroutines described in [2].

Function naming of comparison routines is as in [1,2], with k always
representing the integer bit length, and kappa the statistical security
parameter.

Most of these routines were implemented before the cint/sint classes, so use
the old-fashioned Register class and assembly instructions instead of operator
overloading.

The PreMulC function has a few variants, depending on whether
preprocessing is only triples/bits, or inverse tuples or "special"
comparison-specific preprocessing is also available.

[1] https://www1.cs.fau.de/filepool/publications/octavian_securescm/smcint-scn10.pdf
[2] https://www1.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf
"""

# Use constant rounds protocols instead of log rounds
const_rounds = False
# Set use_inv to use preprocessed inverse tuples for more efficient
# online phase comparisons.
use_inv = True
# If do_precomp is not set, use_inv uses standard inverse tuples, otherwise if
# both are set, use a list of "special" tuples of the form
# (r[i], r[i]^-1, r[i] * r[i-1]^-1)
do_precomp = True

from . import instructions_base
from . import util

def set_variant(options):
    """ Set flags based on the command-line option provided """
    global const_rounds, do_precomp, use_inv
    variant = options.comparison
    if variant == 'log':
        const_rounds = False
    elif variant == 'plain':
        const_rounds = True
        use_inv = False
    elif variant == 'inv':
        const_rounds = True
        use_inv = True
        do_precomp = True
    elif variant == 'sinv':
        const_rounds = True
        use_inv = True
        do_precomp = False
    elif variant is not None:
        raise CompilerError('Unknown comparison variant: %s' % variant)
    if const_rounds and instructions_base.program.options.binary:
        raise CompilerError(
            'Comparison variant choice incompatible with binary circuits')

def ld2i(c, n):
    """ Load immediate 2^n into clear GF(p) register c """
    t1 = program.curr_block.new_reg('c')
    ldi(t1, 2 ** (n % 30))
    for i in range(n // 30):
        t2 = program.curr_block.new_reg('c')
        mulci(t2, t1, 2 ** 30)
        t1 = t2
    movc(c, t1)

def maybe_mulm(res, x, y):
    # overwrite instruction for function-dependent preprocessing protocols
    from Compiler import types
    program.curr_block.replace_last_reg(res, x * y)

def require_ring_size(k, op, suffix='', slack=0):
    if not program.options.ring:
        return
    diff = slack * (not program.allow_tight_parameters)
    k += diff
    if int(program.options.ring) < k:
        msg = 'ring size too small for %s, compile ' \
            'with \'-R %d\' or more' % (op, k)
        if k > 64 and k < 128:
            msg += ' (maybe \'-R 128\' as it is supported by default)'
        if int(program.options.ring) >= k - diff:
            msg += ", alternatively set " \
                "'program.allow_tight_parameters=True' in the program"
        raise CompilerError(msg + suffix)
    program.curr_tape.require_bit_length(k)

@instructions_base.cisc
def LTZ(s, a, k):
    """
    s = (a ?< 0)

    k: bit length of a
    """
    program.curr_block.replace_last_reg(s, program.non_linear.ltz(a, k))

def LtzRing(a, k):
    from .types import sint
    return sint.conv(LtzRingRaw(a, k))

def LtzRingRaw(a, k):
    from .types import sint, _bitint
    from .GC.types import sbitvec
    if program.use_split():
        program.reading('comparison', 'Keller25', 'Section 6')
        summands = a.split_to_two_summands(k)
        carry = CarryOutRawLE(*reversed(list(x[:-1] for x in summands)))
        msb = carry ^ summands[0][-1] ^ summands[1][-1]
        return msb
    else:
        program.reading('comparison', 'DEK20-pre', 'Paragraph III.D.8')
        from . import floatingpoint
        require_ring_size(k, 'comparison')
        m = k - 1
        shift = int(program.options.ring) - k
        r_prime, r_bin = MaskingBitsInRing(k)
        tmp = a - r_prime
        c_prime = (tmp << shift).reveal(False) >> shift
        a = r_bin[0].bit_decompose_clear(c_prime, m)
        b = r_bin[:m]
        u = CarryOutRaw(a[::-1], b[::-1])
        return r_bin[m].bit_xor(c_prime >> m).bit_xor(u)

def LessThanZero(a, k):
    from . import types
    res = types.sint()
    LTZ(res, a, k)
    return res

@instructions_base.cisc
def Trunc(d, a, k, m, signed):
    """
    d = a >> m

    k: bit length of a
    m: compile-time integer
    signed: True/False, describes a
    """
    if m == 0:
        movs(d, a)
        return
    else:
        movs(d, program.non_linear.trunc(a, k, m, signed=signed))

def TruncRing(d, a, k, m, signed):
    program.curr_tape.require_bit_length(1)
    if program.use_split() in (2, 3):
        program.reading('truncation', 'ABY3')
        if signed:
            a += (1 << (k - 1))
        from Compiler.types import sint
        from .GC.types import sbitint
        length = int(program.options.ring)
        summands = a.split_to_n_summands(length, program.use_split())
        x = sbitint.wallace_tree_without_finish(summands, True)
        if program.use_split() == 2:
            carries = sbitint.get_carries(*x)
            low = carries[m]
            high = sint.conv(carries[length])
        else:
            if m == 1:
                low = x[0][1]
                high = sint.conv(CarryOutLE(x[1][:-1], x[0][:-1])) + \
                       sint.conv(x[0][-1])
            else:
                mid_carry = CarryOutRawLE(x[1][:m], x[0][:m])
                low = sint.conv(mid_carry) + sint.conv(x[0][m])
                tmp = util.tree_reduce(carry, (sbitint.half_adder(xx, yy)
                                               for xx, yy in zip(x[1][m:-1],
                                                                 x[0][m:-1])))
                top_carry = sint.conv(carry([None, mid_carry], tmp, False)[1])
                high = top_carry + sint.conv(x[0][-1])
        shifted = sint()
        shrsi(shifted, a, m)
        res = shifted + sint.conv(low) - (high << (length - m))
        if signed:
            res -= (1 << (k - m - 1))
    else:
        a_prime = Mod2mRing(None, a, k, m, signed)
        a -= a_prime
        res = TruncLeakyInRing(a, k, m, signed)
    if d is not None:
        movs(d, res)
    return res

def TruncZeros(a, k, m, signed):
    if program.options.ring:
        return TruncLeakyInRing(a, k, m, signed)
    else:
        from . import types
        tmp = types.cint()
        inv2m(tmp, m)
        return a * tmp

def TruncLeakyInRing(a, k, m, signed):
    """
    Returns a >> m.
    Requires a < 2^k and leaks a % 2^m (needs to be constant or random).
    """
    if k == m:
        return 0
    assert k > m
    program.reading('truncation', 'DEK20-pre', 'Paragraph III.D.4')
    require_ring_size(k, 'leaky truncation')
    from .types import sint, intbitint, cint, cgf2n
    n_bits = k - m
    n_shift = int(program.options.ring) - n_bits
    if n_bits > 1:
        r, r_bits = MaskingBitsInRing(n_bits, True)
    else:
        r_bits = [sint.get_random_bit() for i in range(n_bits)]
        r = sint.bit_compose(r_bits)
    if signed:
        a += (1 << (k - 1))
    shifted = ((a << (n_shift - m)) + (r << n_shift)).reveal(False)
    masked = shifted >> n_shift
    u = sint()
    BitLTL(u, masked, r_bits[:n_bits])
    res = (u << n_bits) + masked - r
    if signed:
        res -= (1 << (n_bits - 1))
    return res

def TruncRoundNearest(a, k, m, signed=False):
    """
    Returns a / 2^m, rounded to the nearest integer.

    k: bit length of a
    m: compile-time integer
    """
    if m == 0:
        return a
    return program.non_linear.trunc_round_nearest(a, k, m, signed)

@instructions_base.cisc
def Mod2m(a_prime, a, k, m, signed):
    """
    a_prime = a % 2^m

    k: bit length of a
    m: compile-time integer
    signed: True/False, describes a
    """
    movs(a_prime, program.non_linear.mod2m(a, k, m, signed))

def Mod2mRing(a_prime, a, k, m, signed):
    program.reading('modulo', 'DEK20-pre', 'Paragraph III.D.3')
    require_ring_size(k, 'modulo power of two')
    from Compiler.types import sint, intbitint, cint
    shift = int(program.options.ring) - m
    r_prime, r_bin = MaskingBitsInRing(m, True)
    tmp = a + r_prime
    c_prime = (tmp << shift).reveal(False) >> shift
    u = sint()
    BitLTL(u, c_prime, r_bin[:m])
    res = (u << m) + c_prime - r_prime
    if a_prime is not None:
        movs(a_prime, res)
    return res

def Mod2mField(a_prime, a, k, m, signed):
    program.reading('modulo', 'CdH10', 'Protocol 3.2')
    from .types import sint
    r_dprime = program.curr_block.new_reg('s')
    r_prime = program.curr_block.new_reg('s')
    r = [sint() for i in range(m)]
    c = program.curr_block.new_reg('c')
    c_prime = program.curr_block.new_reg('c')
    v = program.curr_block.new_reg('s')
    u = program.curr_block.new_reg('s')
    t = [program.curr_block.new_reg('s') for i in range(6)]
    c2m = program.curr_block.new_reg('c')
    c2k1 = program.curr_block.new_reg('c')
    PRandM(r_dprime, r_prime, r, k, m)
    ld2i(c2m, m)
    mulm(t[0], r_dprime, c2m)
    if signed:
        ld2i(c2k1, k - 1)
        addm(t[1], a, c2k1)
    else:
        t[1] = a
    adds(t[2], t[0], t[1])
    adds(t[3], t[2], r_prime)
    asm_open(True, c, t[3])
    modc(c_prime, c, c2m)
    if const_rounds:
        BitLTC1(u, c_prime, r)
    else:
        BitLTL(u, c_prime, r)
    mulm(t[4], u, c2m)
    submr(t[5], c_prime, r_prime)
    adds(a_prime, t[5], t[4])
    return r_dprime, r_prime, c, c_prime, u, t, c2k1

def MaskingBitsInRing(m, strict=False):
    program.curr_tape.require_bit_length(1)
    from Compiler.types import sint
    if program.use_edabit():
        return sint.get_edabit(m, strict)
    elif program.use_dabit:
        r, r_bin = zip(*(sint.get_dabit() for i in range(m)))
    else:
        r = [sint.get_random_bit() for i in range(m)]
        r_bin = r
    return sint.bit_compose(r), r_bin

def PRandM(r_dprime, r_prime, b, k, m, use_dabit=True):
    """
    r_dprime = random secret integer in range [0, 2^(k + kappa - m) - 1]
    r_prime = random secret integer in range [0, 2^m - 1]
    b = array containing bits of r_prime
    """
    assert k >= m
    kappa = program.security
    program.curr_tape.require_bit_length(k + kappa, reason='statistical masking as in https://www.researchgate.net/publication/225092133_Improved_Primitives_for_Secure_Multiparty_Integer_Computation')
    from .types import sint
    if program.use_edabit() and not const_rounds:
        movs(r_dprime, sint.get_edabit(k + kappa - m, True)[0])
        tmp, b[:] = sint.get_edabit(m, True)
        movs(r_prime, tmp)
        return
    t = [[program.curr_block.new_reg('s') for j in range(2)] for i in range(m)]
    t[0][1] = b[-1]
    PRandInt(r_dprime, k + kappa - m)
    # r_dprime is always multiplied by 2^m
    if use_dabit and program.use_dabit and m > 1 and not const_rounds:
        r, b[:] = zip(*(sint.get_dabit() for i in range(m)))
        r = sint.bit_compose(r)
        movs(r_prime, r)
        return
    bit(b[-1])
    for i in range(1,m):
        adds(t[i][0], t[i-1][1], t[i-1][1])
        bit(b[-i-1])
        adds(t[i][1], t[i][0], b[-i-1])
    movs(r_prime, t[m-1][1])

def PRandInt(r, k):
    """
    r = random secret integer in range [0, 2^k - 1]
    """
    t = [[program.curr_block.new_reg('s') for i in range(k)] for j in range(3)]
    t[2][k-1] = r
    bit(t[2][0])
    for i in range(1,k):
        adds(t[0][i], t[2][i-1], t[2][i-1])
        bit(t[1][i])
        adds(t[2][i], t[0][i], t[1][i])

def BitLTC1(u, a, b):
    """
    u = a <? b

    a: array of clear bits
    b: array of secret bits (same length as a)
    """
    program.reading('constant-round bit-wise public-private comparison',
                    'CdH10', 'Protocol 4.5')
    k = len(b)
    p = [program.curr_block.new_reg('s') for i in range(k)]
    from . import floatingpoint
    a_bits = floatingpoint.bits(a, k)
    if instructions_base.get_global_vector_size() == 1:
        a_ = a_bits
        a_bits = program.curr_block.new_reg('c', size=k)
        b_vec = program.curr_block.new_reg('s', size=k)
        for i in range(k):
            movc(a_bits[i], a_[i])
            movs(b_vec[i], b[i])
        d = program.curr_block.new_reg('s', size=k)
        s = program.curr_block.new_reg('s', size=k)
        t = [program.curr_block.new_reg('s', size=k) for j in range(5)]
        c = [program.curr_block.new_reg('c', size=k) for j in range(4)]
    else:
        d = [program.curr_block.new_reg('s') for i in range(k)]
        s = [program.curr_block.new_reg('s') for i in range(k)]
        t = [[program.curr_block.new_reg('s') for i in range(k)] for j in range(5)]
        c = [[program.curr_block.new_reg('c') for i in range(k)] for j in range(4)]
    if instructions_base.get_global_vector_size() == 1:
        vmulci(k, c[2], a_bits, 2)
        vmulm(k, t[0], b_vec, c[2])
        vaddm(k, t[1], b_vec, a_bits)
        vsubs(k, d, t[1], t[0])
        vaddsi(k, t[2], d, 1)
        t[2].create_vector_elements()
        pre_input = t[2].vector[:]
    else:
        for i in range(k):
            mulci(c[2][i], a_bits[i], 2)
            mulm(t[0][i], b[i], c[2][i])
            addm(t[1][i], b[i], a_bits[i])
            subs(d[i], t[1][i], t[0][i])
            addsi(t[2][i], d[i], 1)
            pre_input = t[2][:]
    pre_input.reverse()
    if use_inv:
        if instructions_base.get_global_vector_size() == 1:
            PreMulC_with_inverses(p, pre_input)
        else:
            if do_precomp:
                PreMulC_with_inverses(p, pre_input)
            else:
                raise NotImplementedError('Vectors not compatible with -c sinv')
    else:
        PreMulC_without_inverses(p, pre_input)
    p.reverse()
    for i in range(k-1):
        subs(s[i], p[i], p[i+1])
    subsi(s[k-1], p[k-1], 1)
    subcfi(c[3][0], a_bits[0], 1)
    mulm(t[4][0], s[0], c[3][0])
    from .types import sint
    t[3] = [sint() for i in range(k)]
    for i in range(1,k):
        subcfi(c[3][i], a_bits[i], 1)
        mulm(t[3][i], s[i], c[3][i])
        adds(t[4][i], t[4][i-1], t[3][i])
    Mod2(u, t[4][k-1], k, False)
    return p, a_bits, d, s, t, c, b, pre_input

def carry(b, a, compute_p=True):
    """ Carry propagation:
        return (p,g) = (p_2, g_2)o(p_1, g_1) -> (p_1 & p_2, g_2 | (p_2 & g_1))
    """
    if a is None:
        return b
    if b is None:
        return a
    t = [None] * 3
    if compute_p:
        t[0] = a[0].bit_and(b[0])
    t[2] = a[0].bit_and(b[1]) + a[1]
    return t[0], t[2]

# from WP9 report
# length of a is even
def CarryOutAux(a):
    k = len(a)
    if k > 1 and k % 2 == 1:
        a.append(None)
        k += 1
    u = [None]*(k//2)
    a = a[::-1]
    if k > 1:
        for i in range(k//2):
            u[i] = carry(a[2*i+1], a[2*i], i != k//2-1)
        return CarryOutAux(u[:k//2][::-1])
    else:
        return a[0][1]

# carry out with carry-in bit c
def CarryOut(res, a, b, c=0):
    """
    res = last carry bit in addition of a and b

    a: array of clear bits
    b: array of secret bits (same length as a)
    c: initial carry-in bit
    """
    from .types import sint
    movs(res, sint.conv(CarryOutRaw(a, b, c)))

def CarryOutRaw(a, b, c=0):
    assert len(a) == len(b)
    k = len(a)
    from . import types
    if program.linear_rounds():
        carry = 0
        for (ai, bi) in zip(a, b):
            carry = bi.carry_out(ai, carry)
        return carry
    d = [program.curr_block.new_reg('s') for i in range(k)]
    s = [program.curr_block.new_reg('s') for i in range(3)]
    for i in range(k):
        d[i] = list(b[i].half_adder(a[i]))
    s[0] = d[-1][0].bit_and(c)
    s[1] = d[-1][1] + s[0]
    d[-1][1] = s[1]
    return CarryOutAux(d[::-1])

def CarryOutRawLE(a, b, c=0):
    """ Little-endian version """
    return CarryOutRaw(a[::-1], b[::-1], c)

def CarryOutLE(a, b, c=0):
    """ Little-endian version """
    from . import types
    res = types.sint()
    CarryOut(res, a[::-1], b[::-1], c)
    return res

def BitLTL(res, a, b):
    """
    res = a <? b (logarithmic rounds version)

    a: clear integer register
    b: array of secret bits (same length as a)
    """
    program.reading('logarithmic-round bit-wise public-private comparison',
                    'CdH10', 'Protocol 4.1')
    k = len(b)
    a_bits = b[0].bit_decompose_clear(a, k)
    from .types import sint
    movs(res, sint.conv(BitLTL_raw(a_bits, b)))

def BitLTL_raw(a_bits, b):
    s = [x.bit_not() for x in b]
    return CarryOutRaw(a_bits[::-1], s[::-1], b[0].long_one()).bit_not()

def PreMulC_with_inverses_and_vectors(p, a):
    """
    p[i] = prod_{j=0}^{i-1} a[i]

    Variant for vector registers using preprocessed inverses.
    """
    from Compiler.types import _types
    sint = _types[a[0].reg_type]
    cint = sint.clear_type
    k = len(p)
    a_vec = sint(size=k)
    r = sint(size=k)
    w = sint(size=k)
    w_tmp = sint(size=k)
    z = sint(size=k)
    m = cint(size=k)
    t = [sint(size=k) for i in range(1)]
    c = [cint() for i in range(k)]
    # warning: computer scientists count from 0
    if do_precomp:
        vinverse(k, r, z)
    else:
        vprep(k, 'PreMulC', r, z, w_tmp)
    for i in range(1,k):
        if do_precomp:
            muls(w[i], r[i], z[i-1])
        else:
            movs(w[i], w_tmp[i])
        movs(a_vec[i], a[i])
    movs(w[0], r[0])
    movs(a_vec[0], a[0])
    vmuls(k, t[0], w, a_vec)
    vasm_open(k, True, m, t[0])
    PreMulC_end(p, a, c, m, z)

def PreMulC_with_inverses(p, a):
    """
    Variant using preprocessed inverses or special inverses.
    The latter are triples of the form (a_i, a_i^{-1}, a_i * a_{i-1}^{-1}).
    See also make_PreMulC() in Fake-Offline.cpp.
    """
    from Compiler.types import _types
    sint = _types[a[0].reg_type]
    cint = sint.clear_type
    k = len(a)
    r = [[sint() for i in range(k)] for j in range(3)]
    w = [[sint() for i in range(k)] for j in range(2)]
    z = [sint() for i in range(k)]
    m = [cint() for i in range(k)]
    t = [[sint() for i in range(k)] for i in range(1)]
    c = [cint() for i in range(k)]
    # warning: computer scientists count from 0
    for i in range(k):
        if do_precomp:
            inverse(r[0][i], z[i])
        else:
            prep('PreMulC', r[0][i], z[i], w[1][i])
    if do_precomp:
        for i in range(1,k):
            muls(w[1][i], r[0][i], z[i-1])
    w[1][0] = r[0][0]
    for i in range(k):
        muls(t[0][i], w[1][i], a[i])
    for i in range(k):
        asm_open(True, m[i], t[0][i])
    PreMulC_end(p, a, c, m, z)

def PreMulC_without_inverses(p, a):
    """
    Plain variant with no extra preprocessing.
    """
    from Compiler.types import _types
    sint = _types[a[0].reg_type]
    cint = sint.clear_type
    k = len(a)
    r = [sint() for i in range(k)]
    s = [sint() for i in range(k)]
    u = [cint() for i in range(k)]
    v = [sint() for i in range(k)]
    w = [sint() for i in range(k)]
    z = [sint() for i in range(k)]
    m = [cint() for i in range(k)]
    t = [[sint() for i in range(k)] for i in range(2)]
    #tt = [[sint() for i in range(k)] for i in range(4)]
    u_inv = [cint() for i in range(k)]
    c = [cint() for i in range(k)]
    # warning: computer scientists count from 0
    for i in range(k):
        triple(s[i], r[i], t[0][i])
        #adds(tt[0][i], t[0][i], a[i])
        #subs(tt[1][i], tt[0][i], a[i])
        #startopen(tt[1][i])
        asm_open(True, u[i], t[0][i])
    for i in range(k-1):
        muls(v[i], r[i+1], s[i])
    w[0] = r[0]
    one = cint()
    ldi(one, 1)
    for i in range(k):
        divc(u_inv[i], one, u[i])
        # avoid division by zero, just for benchmarking
        #divc(u_inv[i], u[i], one)
    for i in range(1,k):
        maybe_mulm(w[i], v[i-1], u_inv[i-1])
    for i in range(1,k):
        maybe_mulm(z[i], s[i], u_inv[i])
    for i in range(k):
        muls(t[1][i], w[i], a[i])
        asm_open(True, m[i], t[1][i])
    PreMulC_end(p, a, c, m, z)

def PreMulC_end(p, a, c, m, z):
    """
    Helper function for all PreMulC variants. Local operation.
    """
    k = len(a)
    c[0] = m[0]
    for j in range(1,k):
        mulc(c[j], c[j-1], m[j])
        if isinstance(p, list):
            maybe_mulm(p[j], z[j], c[j])
    if isinstance(p, list):
        p[0] = a[0]
    else:
        maybe_mulm(p, z[-1], c[-1])

def PreMulC(a):
    p = [type(a[0])() for i in range(len(a))]
    instructions_base.set_global_instruction_type(a[0].instruction_type)
    if use_inv:
        PreMulC_with_inverses(p, a)
    else:
        PreMulC_without_inverses(p, a)
    instructions_base.reset_global_instruction_type()
    return p

def KMulC(a):
    """
    Return just the product of all items in a
    """
    from .types import sint, cint
    p = sint()
    if use_inv:
        PreMulC_with_inverses(p, a)
    else:
        PreMulC_without_inverses(p, a)
    return p

def Mod2(a_0, a, k, signed):
    """
    a_0 = a % 2

    k: bit length of a
    """
    if k <= 1:
        movs(a_0, a)
        return
    program.reading('modulo', 'CdH10', 'Protocol 3.4')
    r_dprime = program.curr_block.new_reg('s')
    r_prime = program.curr_block.new_reg('s')
    r_0 = program.curr_block.new_reg('s')
    c = program.curr_block.new_reg('c')
    c_0 = program.curr_block.new_reg('c')
    tc = program.curr_block.new_reg('c')
    t = [program.curr_block.new_reg('s') for i in range(6)]
    c2k1 = program.curr_block.new_reg('c')
    PRandM(r_dprime, r_prime, [r_0], k, 1)
    r_0 = r_prime
    mulsi(t[0], r_dprime, 2)
    if signed:
        ld2i(c2k1, k - 1)
        addm(t[1], a, c2k1)
    else:
        t[1] = a
    adds(t[2], t[0], t[1])
    adds(t[3], t[2], r_prime)
    asm_open(True, c, t[3])
    from . import floatingpoint
    c_0 = floatingpoint.bits(c, 1)[0]
    mulci(tc, c_0, 2)
    mulm(t[4], r_0, tc)
    addm(t[5], r_0, c_0)
    subs(a_0, t[5], t[4])


# hack for circular dependency
from .instructions import *
