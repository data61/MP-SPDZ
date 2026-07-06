import itertools
from Compiler import types, library, instructions
from Compiler import comparison, util

def dest_comp(B):
    Bt = B.transpose()
    St_flat = Bt.get_vector().prefix_sum()
    Tt_flat = Bt.get_vector() * St_flat.get_vector()
    Tt = types.Matrix(*Bt.sizes, B.value_type)
    Tt.assign_vector(Tt_flat)
    Bt.delete()
    return (sum(Tt) - 1, Tt.delete())[0]

def gen_bit_perm(k, n_threads=None, time=False):
    # Protocol 4.1 in https://eprint.iacr.org/2022/1595
    if n_threads is None:
        k = k.get_vector()
        f = [None, k]
        f[0] = 1 - f[1]
        s = [ff.prefix_sum() for ff in f]
        s[1] += s[0].get_vector(len(k) - 1)
        t = k.get_vector() * (s[1] - s[0])
        return s[0] + t - 1
    else:
        sint = types.sint
        multithread = library.multithread
        timer = library.MultiTimer(time)
        f = [sint.Array(len(k)), types.Array.create_from(k)]
        timer.next()
        @multithread(n_threads, len(k))
        def _(base, size):
            f[0].assign_vector(1 - f[1].get_vector(base=base, size=size),
                               base=base)
        timer.next()
        s = [types.Array.create_from(ff[:].prefix_sum()) for ff in f]
        timer.next()
        res = sint.Array(len(k))
        @multithread(n_threads, len(k))
        def _(base, size):
            s[1].assign_vector(s[1].get_vector(base=base, size=size) + \
                               s[0].get_vector(base=len(k) - 1), base=base)
        timer.next()
        @multithread(n_threads, len(k))
        def _(base, size):
            gv = lambda x: x.get_vector(base=base, size=size)
            res.assign_vector(
                gv(s[0]) + gv(f[1]) * (gv(s[1]) - gv(s[0])) - 1, base=base)
        timer.end()
        for x in sum((f, s), []):
            x.delete()
        return (res[:], res.delete())[0]

def reveal_sort(k, D, reverse=False, n_threads=None, time=False):
    r""" Sort in place according to "perfect" key. The name hints at the fact
    that a random order of the keys is revealed.

    :param k: vector or Array of sint containing exactly :math:`0,\dots,n-1`
      in any order
    :param D: Array or MultiArray to sort
    :param reverse: whether :py:obj:`key` is a permutation in forward or
      backward order

    """
    library.get_program().reading('sorting', 'HICT14')
    comparison.require_ring_size(util.log2(len(k)) + 1, 'sorting')
    assert len(k) == len(D)
    timer = library.MultiTimer(time)
    library.break_point('reveal_sort')
    shuffle = types.sint.get_secure_shuffle(len(k))
    timer.next()
    k_prime = types.Array.create_from(k.get_vector().secure_permute(shuffle))
    timer.next()
    idx = types.regint.Array(len(k))
    @library.multithread(n_threads, len(k),
                         max_size=library.get_program().memory_budget)
    def _(base, size):
        tmp = k_prime.get_vector(base=base, size=size).reveal()
        idx.assign_vector(tmp, base=base)
    timer.next()
    if reverse:
        D.permute(idx, n_threads=n_threads)
        timer.next()
        library.break_point('reveal_sort2')
        D.secure_permute(shuffle, reverse=True, n_threads=n_threads)
    else:
        D.secure_permute(shuffle, n_threads=n_threads)
        timer.next()
        library.break_point('reveal_sort3')
        D.permute(idx, reverse=True, n_threads=n_threads)
    timer.end()
    library.break_point('reveal_sort4')
    k_prime.delete()
    idx.delete()
    instructions.delshuffle(shuffle)

class EmulatorBitDecomposer:
    def __init__(self, x, n, signed):
        self.x = x.get_vector()
        self.n = n or self.x.default_bit_length()
        self.signed = signed
        self.cache = types.sint.Array(len(x))
        self.last = types.MemValue(0)
        self.cache_bit(0)

    def __len__(self):
        return self.n

    def __getitem__(self, i):
        @library.if_(i != self.last)
        def _():
            self.cache_bit(i)
            self.last.write(i)
        return self.cache

    def cache_bit(self, i):
        res = types.sint(size=self.x.size)
        class Bite(instructions.cisc, instructions.base.Instruction):
            arg_format = ['str','int','int','sw','s','ci']
            has_var_args = staticmethod(lambda: True)
        inst = Bite('bite', 5, res.size, res, self.x.pre_mul(),
                    types.regint.conv(i))
        self.cache[:] = res
        if self.signed:
            @library.if_((self.n != 1) * (i == self.n - 1))
            def _():
                self.cache[:] = self.cache[:].bit_not()

    def __iter__(self):
        return iter(())

def radix_sort(k, D, n_bits=None, signed=True, n_threads=None, **kwargs):
    """ Sort in place according to key.

    :param k: keys (vector or Array of sint or sfix)
    :param D: Array or MultiArray to sort
    :param n_bits: number of bits in keys (int)
    :param signed: whether keys are signed (bool)

    """
    assert len(k) == len(D)
    if types.program.options.keep_cisc is not None:
        return radix_sort_from_matrix(
            EmulatorBitDecomposer(k, n_bits, signed=signed), D,
            n_threads=n_threads, **kwargs)
    k = types.Array.create_from(k)
    bs = types.sint.Matrix(n_bits or k[0].default_bit_length(), len(k))
    @library.multithread(n_threads, len(k),
                         max_size=library.get_program().budget)
    def _(base, size):
        tmp = k.get_vector(base=base, size=size).bit_decompose(n_bits)
        for i, x in enumerate(tmp):
            bs[i].assign(x, base=base)
    if signed and len(bs) > 1:
        bs[-1][:] = bs[-1][:].bit_not()
    radix_sort_from_matrix(bs, D, n_threads=n_threads, **kwargs)

def radix_sort_from_matrix(bs, D, time=False, n_threads=None):
    n = len(D)
    for b in bs:
        assert(len(b) == n)
    h = types.Array.create_from(types.sint(types.regint.inc(n)))
    @library.for_range(len(bs))
    def _(i):
        timer = library.MultiTimer(time)
        b = bs[i]
        timer.next()
        c = gen_bit_perm(bs[i], n_threads=n_threads, time=10 * timer.timer_id)
        timer.next()
        reveal_sort(c, h, reverse=False, n_threads=n_threads,
                    time=10 * timer.timer_id)
        timer.next()
        @library.if_e(i < len(bs) - 1, split_factor=(len(bs) - 1) / len(bs))
        def _():
            reveal_sort(h, bs[i + 1], reverse=True, n_threads=n_threads,
                        time=10 * timer.timer_id)
        @library.else_
        def _():
            reveal_sort(h, D, reverse=True, n_threads=n_threads,
                        time=10 * timer.timer_id)
        timer.end()
    h.delete()
