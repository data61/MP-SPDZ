import itertools
import math
from Compiler import types, library, instructions
from Compiler import comparison, util
from Compiler import tools
from Compiler import oram
from Compiler.GC import types as GC_types

def dest_comp(B):
    Bt = B.transpose()
    St_flat = Bt.get_vector().prefix_sum()
    Tt_flat = Bt.get_vector() * St_flat.get_vector()
    Tt = types.Matrix(*Bt.sizes, B.value_type)
    Tt.assign_vector(Tt_flat)
    Bt.delete()
    return (sum(Tt) - 1, Tt.delete())[0]

def gen_bit_perm(k, n_threads=None, time=False, get_array=False):
    # Protocol 4.1 in https://eprint.iacr.org/2022/1595
    if n_threads is None:
        k = k.get_vector()
        f = [None, k]
        timer = library.MultiTimer(time)
        f[0] = 1 - f[1]
        timer.next()
        s = [ff.prefix_sum() for ff in f]
        timer.next()
        s[1] += s[0].get_vector(len(k) - 1)
        timer.next()
        t = k.get_vector().if_else(s[1], s[0])
        timer.next()
        res = t - 1
        timer.end()
        if get_array:
            return types.Array.create_from(res)
        else:
            return res
    else:
        multithread = library.multithread
        timer = library.MultiTimer(time)
        k = k.get_vector()
        f = [k.bit_type.Array(len(k)), types.Array.create_from(k)]
        timer.next()
        max_size = library.get_program().memory_budget // n_threads
        @multithread(n_threads, len(k), max_size=max_size)
        def _(base, size):
            f[0].assign_vector(1 - f[1].get_vector(base=base, size=size),
                               base=base)
        timer.next()
        s = [types.Array.create_from(ff[:].prefix_sum()) for ff in f]
        timer.next()
        res = k.get_type(util.log2(len(k))).Array(len(k))
        @multithread(n_threads, len(k), max_size=max_size)
        def _(base, size):
            s[1].assign_vector(s[1].get_vector(base=base, size=size) + \
                               s[0].get_vector(base=len(k) - 1), base=base)
        timer.next()
        @multithread(n_threads, len(k), max_size=max_size)
        def _(base, size):
            gv = lambda x: x.get_vector(base=base, size=size)
            res.assign_vector(gv(f[1]).if_else(gv(s[1]), gv(s[0])) - 1, base=base)
        timer.end()
        for x in sum((f, s), []):
            x.delete()
        if get_array:
            return res
        else:
            return (res[:], res.delete())[0]

def gen_multi_bit_perm(x, l, time=None, maybe_mixed=True, n_threads=None):
    """ GenMultiBitSort by `Asharov et
    al. <https://eprint.iacr.org/2022/1595>`_

    :param x: entries of at most :py:obj:`l` bits (vector or array)
    :param l: number of bits to consider (int)
    :param maybe_mixed: whether to use mixed circuits if inputs are
      binary rather than arithmetic
    :param n_threads: number of threads (default is to run in the same
      thread)

    """
    if n_threads and len(x) / n_threads < 2 ** 12:
        n_threads = None
    x = x.get_vector()
    maybe_mixed = maybe_mixed and isinstance(x, GC_types.sbitvec)
    timer = library.MultiTimer(time)
    f = oram.decompose_demux(x, l, n_threads=n_threads)
    timer.next()
    if maybe_mixed:
        f_for_sum = types.sintbit.Matrix(len(f), len(x))
        f_for_sum.from_binary(f, n_threads=n_threads)
        timer.next()
    else:
        f_for_sum = f
    s = []
    for i in range(len(f)):
        s.append(f_for_sum[0].value_type.int_type.get_type(1)(
            f_for_sum[i][:]).prefix_sum())
        if i:
            s[-1] += s[-2].get_vector(base=len(x) - 1)
    timer.next()
    s = types.Matrix.create_from(s)
    timer.next()
    if maybe_mixed:
        for i in range(len(f)):
            @library.multithread(n_threads, len(x))
            def _(base, size):
                s[i].assign_vector(
                    s[i].get_vector(
                        base=base, size=size) * f_for_sum[i].get_vector(
                            base=base, size=size), base=base)
        timer.next()
        res = sum(s)
    else:
        res = types.sint.Array(len(x))
        @library.multithread(n_threads, len(x))
        def _(base, size):
            all_ops = [], []
            for i in range(len(f)):
                for j, operand in enumerate((s, f_for_sum)):
                    all_ops[j].append(
                        operand[i].get_vector(base=base, size=size))
            res.assign_vector(
                types.sint.dot_product(*all_ops), base=base)
    f_for_sum.delete()
    s.delete()
    res -= 1
    timer.next()
    if maybe_mixed and isinstance(x, GC_types.sbitvec):
        bit_length = util.log2(len(x))
        res = types.Array.create_from(res).to_binary_with_right_length(
            bit_length, n_threads=n_threads)[:]
    timer.end()
    return res

def reveal_sort(k, D, reverse=False, n_threads=None, time=False,
                return_shuffle=False, shuffle=None, debug=False):
    r""" Sort in place according to "perfect" key. The name hints at the fact
    that a random order of the keys is revealed.

    :param k: vector or Array of sint containing exactly :math:`0,\dots,n-1`
      in any order
    :param D: Array or MultiArray to sort
    :param reverse: whether :py:obj:`key` is a permutation in forward or
      backward order
    :param n_threads: number of threads (default is to run in the same
      thread)
    :param time: use timers for granular benchmarking
    :param return_shuffle: whether to return the secure shuffle
    :param shuffle: previously generated secure shuffle (default
      generate new one)
    :param debug: debugging output (insecure)

    """
    library.get_program().reading('sorting', ('Keller26', 'HICT14'))
    if maybe_fake_sort(k, D, reverse=reverse):
        return
    assert len(k) == len(D)
    comparison.require_ring_size(util.log2(len(k)) + 1, 'sorting')
    timer = library.MultiTimer(time)
    mixed = isinstance(k.get_vector(), GC_types._binary) ^ \
        issubclass(D.value_type, GC_types._binary)
    if mixed:
        D_input = D
        D = D.same_shape(GC_types.sbitvec.get_type(
            D.value_type().default_bit_length()))
        @library.multithread(n_threads, D.total_size())
        def _(base, size):
            tmp = D.value_type.from_right_length(
                D_input.get_vector(base=base, size=size))
            D.assign_vector(tmp, base=base)
        timer.next()
    library.break_point('reveal_sort')
    if shuffle is None:
        shuffle = D.value_type.int_type.get_secure_shuffle(len(k))
    timer.next()
    k_prime = types.Array.create_from(k.get_vector().secure_permute(shuffle))
    timer.next()
    idx = types.regint.Array(len(k))
    @library.multithread(n_threads, len(k),
                         max_size=library.get_program().memory_budget)
    def _(base, size):
        tmp = k_prime.get_vector(base=base, size=size).reveal()
        # unsigned conversion to regint
        R = library.get_program().options.ring
        if R and int(R) < 64:
            tmp = tmp.to_regint(0)
        idx.assign_vector(tmp, base=base)
    timer.next()
    if debug:
        library.print_ln('k=%s idx=%s D=%s', k.reveal(), idx, D.reveal())
    if reverse:
        D.permute(idx, n_threads=n_threads)
        timer.next()
        if debug:
            library.print_ln('permuted D %s', D.reveal())
        library.break_point('reveal_sort2')
        D.secure_permute(shuffle, reverse=True, n_threads=n_threads)
    else:
        D.secure_permute(shuffle, n_threads=n_threads)
        timer.next()
        if debug:
            library.print_ln('shuffled D %s', D.reveal())
        library.break_point('reveal_sort3')
        D.permute(idx, reverse=True, n_threads=n_threads)
    if mixed:
        timer.next()
        D_input.from_binary(D, signed=True, n_threads=n_threads)
    timer.end()
    library.break_point('reveal_sort4')
    k_prime.delete()
    if return_shuffle:
        return idx, shuffle
    else:
        idx.delete()
        D.value_type.int_type.delete_shuffle(shuffle)

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

def maybe_fake_sort(k, D, reverse=False):
    if 'sort' in (types.program.options.keep_cisc or []):
        class Sort(instructions.cisc, instructions.base.Instruction):
            arg_format = ['str','int','int','s','int','ci','int']
            has_var_args = staticmethod(lambda: True)
        try:
            k = k.key
        except:
            pass
        Sort('sort', 6, len(k), k.get_vector().pre_mul(), D.total_size(),
             types.regint.conv(D.address), reverse)
        library.break_point()
        return True

def radix_sort(k, D=None, n_bits=None, signed=True, n_threads=None, l=2,
               **kwargs):
    """ Sort in place according to key.

    :param k: keys (vector or Array of sint or sfix)
    :param D: Array or MultiArray to sort
    :param n_bits: number of bits in keys (int)
    :param signed: whether keys are signed (bool)
    :param n_threads: number of threads (default is to run in the same
      thread)
    :param l: number of bits to process at once

    """
    if D is not None:
        assert len(k) == len(D)
    keep_cisc = types.program.options.keep_cisc
    if maybe_fake_sort(k, D):
        return
    if keep_cisc is not None:
        return radix_sort_from_matrix(
            EmulatorBitDecomposer(k, n_bits, signed=signed), D,
            n_threads=n_threads, **kwargs)
    k = types.Array.create_from(k)
    n_bits = n_bits or k[0].default_bit_length()
    l = min(l, n_bits)
    n_bits = l * int(math.ceil(n_bits / l))
    bs = k.value_type.bit_type.Matrix(n_bits, len(k))
    @library.multithread(n_threads, len(k),
                         max_size=library.get_program().budget)
    def _(base, size):
        tmp = k.get_vector(base=base, size=size).bit_decompose(n_bits)
        for i, x in enumerate(tmp):
            bs[i].assign(x, base=base)
    if signed and len(bs) > 1:
        sign_bit = min(n_bits, k[0].default_bit_length()) - 1
        bs[-1][:] = bs[sign_bit][:].bit_not()
    res = radix_sort_from_matrix(bs, D, n_threads=n_threads, l=l, **kwargs)
    bs.delete()
    k.delete()
    return res

def radix_sort_from_matrix(bs, D=None, time=False, n_threads=None, l=1,
                           only_perm=False, maybe_mixed=True, debug=False,
                           n_shuffle_threads=None, seq_shuffle_gen=False,
                           **kwargs):
    n = len(bs[0])
    for b in bs:
        assert(len(b) == n)
    h = types.Array.create_from(
        bs[0].value_type.get_type(util.log2(n))(types.regint.inc(n)))
    assert len(h) == n
    assert len(bs) % l == 0
    n_loops = len(bs) // l
    shuffles = types.regint.Array(n_loops + (not only_perm))
    timer = library.MultiTimer(time)
    shuffle_type = bs[0].value_type.int_type
    n_shuffle_threads = n_shuffle_threads or n_threads
    @library.multithread(n_shuffle_threads, len(shuffles))
    def _(base, size):
        if seq_shuffle_gen or n_threads != n_shuffle_threads:
            for i in range(size):
                shuffles[base + i] = shuffle_type.get_secure_shuffle(n, True)
        else:
            shuffles.assign_vector(
                shuffle_type.get_secure_shuffle(n, True, size=size), base=base)
    timer.end()
    time = timer.timer_id
    @library.for_range(n_loops)
    def _(i):
        nonlocal time
        timer = library.MultiTimer(time)
        timer.next()
        if l == 1:
            b = bs[i]
        else:
            bits = [bs[l * i + j][:] for j in range(l)]
            b = bits[0].get_type(l).bit_compose(bits)
            b = types.Array.create_from(b)
        perm = types.regint.Array(n)
        shuffle = shuffles[i]
        @library.if_(i > 0, split_factor=(n_loops - 1) / n_loops)
        def _():
            tmp = reveal_sort(h, b, reverse=False, n_threads=n_threads,
                              time=10 * timer.timer_id, return_shuffle=True,
                              shuffle=shuffle)
            perm.assign(tmp[0])
            shuffle.update(tmp[1])
            tmp[0].delete()
        timer.next()
        if l == 1 and not maybe_mixed:
            c = gen_bit_perm(b, n_threads=n_threads, time=10 * timer.timer_id)
        else:
            c = gen_multi_bit_perm(b[:], l, time=10 * timer.timer_id,
                                   maybe_mixed=maybe_mixed, n_threads=n_threads,
                                   **kwargs)
        if debug:
            library.print_ln('c=%s b=%s', list(c.reveal()), b.reveal())
        timer.next()
        h.assign(c)
        if isinstance(c, types.Array):
            c.delete()
        @library.if_(i > 0, split_factor=(n_loops - 1) / n_loops)
        def _():
            h.permute(perm, reverse=False)
            h.secure_permute(shuffle, reverse=True)
        shuffle_type.delete_shuffle(shuffle)
        timer.end()
        time = timer.timer_id
    if only_perm:
        return h
    else:
        assert D
        timer = library.MultiTimer(time)
        timer.next()
        reveal_sort(h, D, reverse=False, n_threads=n_threads,
                    shuffle=shuffles[n_loops], time=timer.timer_id * 10)
        timer.end()
        h.delete()

def quicksort(k, n_bits, debug=False, verbose=False, time=False,
              n_threads=None, return_permutation=False):
    """ Quicksort by `Araki et
    al. <https://doi.org/10.1145/3460120.3484560>`_.

    :param k: array to be sorted
    :param n_bits: bit size of entries
    :param debug: debugging
    :param verbose: output round numbers
    :param time: granular timings
    :param n_threads: number of threads (default is to run in the same
      thread)
    :param return_permutation: whether to return the permutation
      instead of applying it
    :returns: if requested, tuple of oblivious shuffle and cleartext
      permutation

    """
    library.get_program().reading('Quicksort', 'Keller26')
    assert n_bits
    from Compiler.types import Array, regint, MemValue, sint
    from Compiler.library import while_do, for_range, if_e, if_, else_, \
        print_ln, MultiTimer, multithread
    t = MultiTimer(time)
    tmp = Array.create_from(k)
    shuffle = tmp.secure_shuffle(n_threads=n_threads,
                                 get_shuffle=return_permutation)
    loglen = util.log2(len(tmp))
    @multithread(n_threads, len(tmp))
    def _(base, size):
        x = tmp.get_vector(base=base, size=size) << loglen
        x += regint.inc(size, base)
        tmp.assign_vector(x, base=base)
    g = regint.Array(len(tmp))
    g.assign_all(0, n_threads=n_threads)
    g[0] = 1
    n_rounds = MemValue(0)
    t.next()
    if return_permutation:
        res_perm = Array.create_from(regint.inc(len(k)))
    # generous upper limit for usage prediction
    @for_range(int(3 * math.log(len(tmp), 2)), disable_index_checks=True)
    def _(i):
        if verbose:
            print_ln('round %s', i)
        n_rounds.write(i + 1)
        timer = MultiTimer(10 * t.timer_id)
        addresses = regint(size=len(tmp))
        instructions.groupsumint(addresses, g[:], regint.inc(len(tmp)) * g[:])
        pivots = Array.create_from(tmp.get(addresses))
        timer.next()
        if debug:
            pre_perm = tmp[:]
        c = regint.Array(len(tmp))
        @multithread(n_threads, len(tmp))
        def _(base, size):
            c.assign_vector(pivots.get_vector(base=base, size=size).less_than(
                tmp.get_vector(base=base, size=size),
                bit_length=n_bits + loglen,
                maybe_mixed=True).reveal_to_regint_by_bit(), base=base)
        if not debug:
            pivots.delete()
        g_in = g[:]
        timer.next()
        g_out, perm = [regint(size=len(tmp)) for i in range(2)]
        instructions.qs_perm(perm, g_out, g_in, c[:])
        if not debug:
            c.delete()
        g[:] = g_out
        perm = Array.create_from(perm)
        tmp.permute(perm, n_threads=n_threads)
        if return_permutation:
            res_perm.permute(perm, n_threads=n_threads)
        if not debug:
            perm.delete()
        if debug:
            print_ln('pre_perm=%s', pre_perm.reveal())
            print_ln('g_in=%s', g_in.reveal())
            print_ln('pivots=%s', pivots.reveal())
            print_ln('c=%s', c)
            print_ln('perm=%s', perm)
            print_ln('g_out=%s', g.reveal())
            print_ln('tmp=%s', tmp.reveal())
        timer.end()
        return g.sum() < len(tmp)
    t.next()
    if not return_permutation:
        @multithread(n_threads, len(tmp))
        def _(base, size):
            k.assign_vector(
                tmp.get_vector(base=base, size=size) >> loglen, base=base)
    t.end()
    if verbose:
        print_ln('done after %s rounds', n_rounds)
    if return_permutation:
        return shuffle, res_perm
