""" This module contains code for the sparse matrix multiplication by
`Keller <https://eprint.iacr.org/2026/2457>`_ as well as the graph cycle
detection built on top.

"""

from Compiler.types import *
from Compiler.library import *
from Compiler import util, sorting
from Compiler import decision_tree
from Compiler import floatingpoint

def GroupOr(g, x, max_group_size, n_threads=None):
    """ Group-wise OR.

    :param g: group indicators (vector or array)
    :param x: inputs (vector or array)
    :param max_group_size: maximum size of a group
    :param n_threads: number of threads (default is to run in the same thread)

    """
    s = decision_tree.GroupSum(g, x, n_threads=n_threads)
    return s.greater_than(0, bit_length=util.log2(max_group_size))

class SparseMatrix:
    """ Sparse matrix in row-wise and/or column-wise
    representation. Both are three-dimensional tensors. The first
    index represents rows or columns, and the second the sparse
    entries thereof. The third dimension are tuples consisting of
    index (column for row-wise and vice versa), content, and non-zero
    indicator. The constructs constructs an empty matrix, and
    :py:func:`from_graph` constructs an adjacency matrix for a graph.

    """
    @classmethod
    def from_graph(cls, graph, randomize=False, dry=False):
        """ Construct sparse matrix from graph.

        :param graph: graph with NetworkX interface
        :param randomize: use random indices for empty entries
        :param dry: don't process data, only use sizes

        """
        rows, cols = ([[] for j in range(len(graph))] for i in range(2))
        nodes = list(sorted(graph))
        if randomize:
            random.shuffle(nodes)
        rev = dict(reversed(x) for x in enumerate(nodes))
        for i, node in enumerate(nodes):
            for x in graph[node]:
                j = rev[x]
                rows[i].append([j, 1, 1])
                cols[j].append([i, 1, 1])
        ms = [None] * 2
        for i, l in enumerate((rows, cols)):
            m = max(len(x) for x in l)
            ms[i] = m
            if not dry:
                for x in l:
                    assert len(x) <= m
                    while len(x) < m:
                        x += [[random.randrange(len(nodes))
                               if randomize else 0, 0, 0]]
        res = cls()
        if dry:
            res.rows = sint.Tensor((len(rows), ms[0], 3))
            res.cols = sint.Tensor((len(cols), ms[1], 3))
        else:
            res.rows = sint.input_tensor_via(0, rows)
            res.cols = sint.input_tensor_via(0, cols)
        return res

    def __init__(self, n_rows=None, n_cols=None, max_non_zero=None):
        if max_non_zero:
            if n_rows:
                self.rows = sint.Tensor((n_rows, max_non_zero, 3))
                self.rows.assign_all(0)
            if n_cols:
                self.cols = sint.Tensor((n_cols, max_non_zero, 3))
                self.cols.assign_all(0)

    def __mul__(self, other):
        return self.placeholder_removal(self.mul_without_removal(other))

    def mul_without_removal(self, other, avg_output_limit=None,
                            balance_rows=False, time=False, debug=False,
                            fail=False, n_threads=None, follow=None,
                            n_heavy_threads=None, **kwargs):
        """ Multiplication by `Damie et
        al. <https://doi.org/10.1145/3800506.3803493>`_

        :param other: multiplicand sparse matrix
        :param avg_output_limit: limit for average non-zero entries
          per row in product
        :param balance_rows: make sure every row appears once in output
        :param time: granular timings
        :param debug: output debugging information (insecure)
        :param fail: check correctness of sub-algorithms (insecure)
        :param n_threads: number of threads (default is to run in same
          thread)
        :param follow: list of indices to follow for debugging
        :param n_heavy_threads: number of threads for first part
          (default: same as :py:obj:`n_threads`)
        :returns: :py:class:`CellSparseMatrix` object

        """
        program.reading('sparse matrix multiplication', ('Keller26', 'DHPR26'))
        n_heavy_threads = n_heavy_threads or n_threads
        m = len(self.cols)
        assert m == len(other.rows)
        max_window = self.cols.sizes[1] * other.rows.sizes[1]
        if balance_rows:
            avg_output_limit = avg_output_limit or (max_window + 1)
            max_window += 1
        res_length = m * max_window
        if time:
            start_timer(1)
        timer = library.MultiTimer(time * 10)
        def step(Z, k, l):
            i = 0
            x = self.cols[k]
            y = other.rows[k]
            xa, ya = (xx.to_array() for xx in (x, y))
            ix = regint.inc(len(x) * len(y), repeat=len(y)) * x.get_part_size()
            Z.set_column(0, xa.get(ix), base=l)
            iy = regint.inc(len(x) * len(y), wrap=len(y)) * y.get_part_size()
            Z.set_column(1, ya.get(iy), base=l)
            for j in range(2):
                Z.set_column(2 + j, xa.get(ix + 1 + j) * ya.get(iy + 1 + j),
                             base=l)
            return len(x) * len(y)
        if avg_output_limit and avg_output_limit < max_window:
            new_Z = sint.Matrix(
                avg_output_limit * max(len(self.cols), len(other.rows)), 4)
            new_Z.assign_all(0)
            factor = res_length / new_Z.sizes[0]
            max_size = 10 ** 7 // max_window
            real_threads = n_heavy_threads or 1
            use_sizes = regint.Matrix(
                real_threads, int(math.ceil(m / real_threads / max_size)))
            @multithread(n_heavy_threads, m, max_size=max_size, get_counters=True)
            def _(base, size, thread_counter, loop_counter):
                use_size = int(max_window * size / factor)
                use_sizes[thread_counter][loop_counter] = use_size
            store_bases = use_sizes.same_shape()
            store_bases.assign_all(0)
            @for_range(store_bases.total_size() - 1)
            def _(i):
                store_bases.array[i + 1] = \
                    store_bases.array[i] + use_sizes.array[i]
            print_ln('use sizes %s', use_sizes)
            print_ln('store bases %s', store_bases)
            timer.next()
            @multithread(n_heavy_threads, m, max_size=max_size, get_counters=True)
            def _(base, size, thread_counter, loop_counter):
                time_part = not n_heavy_threads or n_heavy_threads == 1
                if time_part:
                    timer = library.MultiTimer(110 * time)
                    print_ln('processing up to %s/%s', base + size, m)
                part = sint.Matrix(size * max_window, 4)
                part.assign_all(0)
                base = MemValue(base)
                if time_part:
                    timer.next()
                @for_range_opt(size, disable_index_checks=True)
                def _(i):
                    step_size = max_window - balance_rows
                    done = step(part, base + i, i * step_size)
                    assert done == step_size
                if time_part:
                    timer.next()
                if program.use_binary_shuffle:
                    tmp = part.to_binary_with_right_length(64)
                    tmp.secure_shuffle()
                    part.from_binary(tmp)
                else:
                    part.secure_shuffle()
                if time_part:
                    timer.next()
                part.sort(key_indices=3, n_bits=1)
                use_size = int(max_window * size / factor)
                store_base = store_bases[thread_counter][loop_counter]
                runtime_error_if(
                    use_size != use_sizes[thread_counter][loop_counter],
                    'wrong size')
                use_base = part.sizes[0] - use_size
                if time_part:
                    timer.next()
                tmp = part.get_part_vector(base=use_base, size=use_size)
                new_Z.assign_part_vector(tmp, base=store_base)
                if debug:
                    print_ln('sizes %s/%s base %s factor %s',
                             use_size, size, store_base, factor)
                    print_ln('part %s', part.reveal())
                    print_ln('Z %s', new_Z.reveal())
                if follow:
                    @for_range(len(part))
                    def _(i):
                        for x in tuplify(follow):
                            @if_((part[i][0].reveal() == x).bit_or(
                                part[i][1].reveal() == x))
                            def _():
                                print_ln('entry at %s (use base %s) has %s: %s',
                                         i, use_base, x, part[i].reveal())
                part.delete()
                if time_part:
                    timer.end()
            Z = new_Z
            del res_length
        else:
            max_size = 0
            Z = sint.Matrix(res_length, 4)
            Z.assign_all(0)
            l = MemValue(0)
            @for_range(m)
            def _(k):
                l.iadd(step(Z, k, l))
        timer.end()
        if fail:
            n_rows = len(self.rows)
            self.reveal_check_rows(Z, n_rows)
        if balance_rows:
            if time:
                start_timer(12)
            if max_size <= len(Z):
                Z.sort(key_indices=3, n_bits=1, n_threads=n_threads)
            if fail:
                n_spots = len(Z) - Z.get_column(3).sum().reveal()
                runtime_error_if(
                    n_spots < len(self.rows),
                    'not enough spots for balancing: %s < %s',
                    n_spots, len(self.rows))
            @multithread(n_threads, len(Z) // len(self.rows), max_size=int(
                math.ceil(program.budget / len(self.rows))))
            def _(base, size):
                base *= len(self.rows)
                size *= len(self.rows)
                Z.set_column(0, Z.get_column(3, base=base, size=size).if_else(
                    Z.get_column(0, base=base, size=size), regint.inc(
                        size, wrap=len(self.rows))), base=base)
            if time:
                stop_timer(12)
        if fail:
            self.reveal_check_rows(Z, n_rows)
        self.follow(Z, follow)
        if time:
            stop_timer(1)
            start_timer(2)
        if program.use_binary_shuffle:
            Z_ari = Z
            Z = Z_ari.to_binary_with_right_length(
                util.log2(max(len(other.rows), len(other.cols))), signed=False)
        Z.sort(key_indices=1, n_threads=n_threads,
               n_bits=util.log2(len(other.cols)), signed=False, time=time * 20)
        self.follow(Z, follow)
        Z.sort(key_indices=0, n_threads=n_threads,
               n_bits=util.log2(len(other.rows)), signed=False, time=time * 20)
        if program.use_binary_shuffle:
            Z_ari.from_binary(Z)
            Z = Z_ari
        if fail:
            self.reveal_check_rows(Z, n_rows)
        self.follow(Z, follow)
        if time:
            stop_timer(2)
            start_timer(3)
        self.agg_equal_coord(Z, len(self.rows), len(other.cols), debug=debug,
                             n_threads=n_threads, follow=follow, **kwargs)
        if debug:
            print_ln('rows =    %s', Z.get_column(0).reveal())
            print_ln('cols =    %s', Z.get_column(1).reveal())
            print_ln('values =  %s', Z.get_column(2).reveal())
            print_ln('invalid = %s', Z.get_column(3).reveal())
        if fail:
            self.reveal_check_rows(Z, n_rows)
        if time:
            stop_timer(3)
        return CellSparseMatrix(Z, len(self.rows), len(other.cols))

    @staticmethod
    def agg_equal_coord(Z, n_rows, n_cols, n_threads=None, debug=False,
                        follow=None):
        g = sint.Array(len(Z))
        g[0] = 1
        @multithread(n_threads, len(g) - 1, max_size=program.budget)
        def _(base, size):
            g.assign_vector(Z.get_column(0, base=base, size=size).equal(
                Z.get_column(0, base=base + 1, size=size),
                bit_length=util.log2(n_rows)).bit_and(
                    Z.get_column(1, base=base, size=size).equal(
                        Z.get_column(1, base=base + 1, size=size),
                        bit_length=util.log2(n_cols))).bit_not(), base=base + 1)
        last = sint.concat((g.get_vector(base=1), sint(1)))
        Z.set_column(2, last * decision_tree.GroupSum(
            g, Z.get_column(2), n_threads=n_threads))
        valid = GroupOr(g, Z.get_column(3), len(Z) / n_rows,
                        n_threads=n_threads)
        Z.set_column(3, (last * valid).bit_not())
        if follow:
            last = Array.create_from(last)
            valid = Array.create_from(valid)
            @for_range(len(Z))
            def _(i):
                for x in tuplify(follow):
                    @if_((Z[i][0].reveal() == x).bit_or(
                        Z[i][1].reveal() == x))
                    def _():
                        print_ln('entry at %s has %s: %s (g=%s last=%s valid=%s)',
                                 i, x, Z[i].reveal(), g[i].reveal(),
                                 last[i].reveal(), valid[i].reveal())
        g.delete()
        break_point()

    @staticmethod
    def placeholder_removal(Z):
        try:
            Z = Z.content
        except AttributeError:
            pass
        Z.secure_shuffle()
        places = Z.get_column(3)
        n_places = len(Z) - places.sum().reveal()
        places = Array.create_from(places.reveal())
        res = sint.Matrix(len(Z), 3)
        i = MemValue(0)
        @for_range_opt(len(Z))
        def _(k):
            res[i] = places[k].if_else(res[i], Z[k][:3])
            i.iadd(1 - places[k])
        res.sizes = [n_places, 3]
        return res

    @staticmethod
    def reveal_check_rows(Z, n_rows):
        break_point()
        @for_range_opt(len(Z))
        def _(i):
            row = Z[0].reveal()
            print_ln_if((row < 0).bit_or(row > n_rows),
                        'row out of range: %s/%s', row, n_rows)
        break_point()

    @staticmethod
    def follow(entries, follow):
        if follow:
            @for_range(len(entries))
            def _(i):
                for x in tuplify(follow):
                    @if_((entries[i][0].reveal() == x).bit_or(
                        entries[i][1].reveal() == x))
                    def _():
                        print_ln('entry at %s has %s: %s', i, x,
                                 entries[i].reveal())

    def find_cycles(self, max_cycle, debug=False, fail=False,
                    avg_output_limit=None, output=False, follow=None,
                    n_threads=None, time=False, n_heavy_threads=None,
                    reduced=None, **kwargs):
        """ Find cycles in adjacency matrix.

        :param max_cycles: maximum cycle length
        :param debug: print debugging information (insecure)
        :param fail: check sub-algorithms (insecure)
        :param avg_output_limit: maximum number of non-zero entries in
          intermediate matrices
        :param output: output results
        :param follow: indices for debugging outputs
        :param n_threads: number of threads (default is to run in same
          thread)
        :param time: granular timings
        :param n_heavy_threads: number of threads for first step
          (default is same as :py:obj:`n_threads`)
        :param reduced: pre-allocated matrix for intermediate results
          (default: fresh allocation)
        :returns: matrix of results by cycle and entry

        """
        program.reading('graph cycle detection', 'Keller26')
        assert len(self.rows) == len(self.cols)
        res = sint.Matrix(max_cycle - 1, len(self.rows))
        res.assign_all(0)
        if debug:
            print_ln('input %s', self.rows.reveal())
        def follow_output(prod):
            for i in tuplify(follow):
                print_ln('row %s: %s', i, prod.rows[i].reveal())
            @for_range(len(prod.rows))
            def _(i):
                row = prod.rows[i]
                @for_range(len(row))
                def _(j):
                    entry = row[j]
                    col = entry[0].reveal()
                    for k in tuplify(follow):
                        @if_(col == k)
                        def _():
                            print_ln('in row %s col %s/%s: %s, %s', i, col, k,
                                     util.reveal(entry), list(entry),
                                     print_secrets=True)
        def step(i, prod, reduced=None):
            if output and follow is not None:
                print_ln('before mul')
                follow_output(prod)
            pre = (reduced or self).mul_without_removal(
                prod, balance_rows=True, avg_output_limit=avg_output_limit,
                fail=fail, debug=debug, n_threads=n_threads, time=time,
                follow=follow, n_heavy_threads=n_heavy_threads, **kwargs)
            self.follow(pre.content, follow)
            prod = pre.get_tight_row_matrix(
                debug=debug, fail=fail, n_threads=n_threads, time=time,
                max_non_zero=avg_output_limit, **kwargs)
            pre.content.delete()
            if debug:
                print_ln('prod %s %s', i, prod.rows.reveal())
            if output and follow is not None:
                print_ln('after mul')
                follow_output(prod)
            timer = MultiTimer(time * 5)
            ii = MemValue(i)
            @for_range_opt_multithread(n_threads, len(self.rows),
                                       disable_index_checks=True)
            def _(j):
                i = ii.read()
                row = prod.rows[j]
                col2 = row.get_column(2)
                diagonal = (row.get_column(0) == j).bit_and(col2)
                for k in range(len(row)):
                    res[i][j] = diagonal[k].if_else(col2[k], res[i][j])
                col2 = diagonal.if_else(0, col2)
                row.set_column(2, col2)
                row.set_column(0, row.get_column(0) * col2)
                row.set_column(1, col2)
            timer.next()
            if output:
                i = MemValue(i)
                @map_sum_opt(n_threads, len(res[i]), [sint])
                def _(j):
                    return res[i][j] != 0
                print_ln('%s/%s nodes in cycles of length %s',
                         res[i].sum().reveal(), _().reveal(), i + 2)
                if follow is not None:
                    print_ln('after diagonal')
                    follow_output(prod)
            timer.end()
            if debug:
                print_ln('after diagonal %s', prod.rows.reveal())
            return prod
        if avg_output_limit:
            prod = step(0, self)
            @for_range(1, max_cycle - 1)
            def _(i):
                tmp = step(i, prod, reduced=reduced)
                prod.rows.assign(tmp.rows, n_threads=n_threads)
                tmp.rows.delete()
        else:
            prod = self
            for i in range(max_cycle - 1):
                if i == 0:
                    prod = step(i, prod)
                else:
                    prod = step(i, prod, reduced=reduced)
        return res

class CellSparseMatrix:
    """ Cell-wise sparse matrix contain tuples of row index, column
    index, content, and zero indicator. """
    def __init__(self, content, n_rows, n_cols):
        assert len(content.sizes) == 2
        assert content.sizes[1] == 4
        self.content = content
        self.n_rows = n_rows
        self.n_cols = n_cols

    def reveal(self):
        return self.content.reveal()

    def get_tight_row_matrix(self, sort=False, debug=False, fail=False,
                             time=False, n_threads=None, max_non_zero=None):
        """ Convert back to row-wise :py:class:`SparseMatrix`.

        :param sort: sort row entries putting non-empty first
        :param debug: debugging output (insecure)
        :param fail: check sub-algorithms (insecure)
        :param time: granular timings
        :param n_threads: number of threads (default is to run in same
          thread)
        :param max_non_zero: maximum non-zero entries per row in
          result (default: determine from input)

        """
        combo_timer = MultiTimer(4 * time)
        timer = MultiTimer(41 * time)
        if fail:
            SparseMatrix.reveal_check_rows(self.content, self.n_rows)
        content = self.content
        max_nonzero = len(content) // self.n_rows
        assert content.sizes[0] % self.n_rows == 0
        g = sint.Array(len(content))
        g[0] = 1
        @multithread(n_threads, len(g) - 1, max_size=program.budget)
        def _(base, size):
            g.assign_vector(content.get_column(0, base=base, size=size).equal(
                content.get_column(0, base=base + 1, size=size),
                bit_length=util.log2(self.n_rows)).bit_not(), base=base + 1)
        if fail:
            @for_range_opt_multithread(n_threads, len(g) - 1)
            def _(i):
                this_row = content[i][0].reveal()
                next_row = content[i + 1][0].reveal()
                runtime_error_if(
                    (this_row + 1 != next_row).bit_and(this_row != next_row),
                    'bad row increase, this is %s, next is %s', this_row, next_row)
        if time:
            timer.next()
        n_groups = g.sum().reveal()
        runtime_error_if(n_groups != self.n_rows,
                         'bad number of groups: %s/%s', n_groups, self.n_rows)
        counts = decision_tree.GroupSum(
            g, content.get_column(3).bit_not(), n_threads=n_threads)
        if debug:
            print_ln('%s rows, %s entries', self.n_rows, len(content))
            print_ln('g =      %s', g.reveal())
            print_ln('valid =  %s', content.get_column(3).bit_not().reveal())
            print_ln('counts = %s', counts.reveal())
        if time:
            timer.next()
        perm = decision_tree.SortPerm(g[:].bit_not(), n_threads=n_threads)
        g.delete()
        sorted_counts = perm.apply(counts)
        perm.perm.delete()
        if time:
            timer.next()
        factor = len(content) // self.n_rows
        if debug:
            print_ln('sorted_counts = %s', sorted_counts.reveal())
            print_ln('red_counts = %s',
                     sorted_counts.get_vector(size=self.n_rows).reveal())
        if fail:
            max_count = regint(0)
            sc = Array.create_from(sorted_counts.get_vector(size=self.n_rows).reveal())
            @for_range(self.n_rows)
            def _(i):
                max_count.update(util.max(max_count, sc[i]))
            runtime_error_if(max_count > factor,
                             'maximum count too large: %s > %s',
                             max_count, factor)
            n_valid = content.get_column(3).bit_not().sum().reveal()
            n_good = sorted_counts.get_vector(size=self.n_rows).sum().reveal()
            runtime_error_if(n_valid != n_good,
                             'mismatch in valid entry number: %s/%s',
                             n_good, n_valid)
        countdown = sint.Array(len(content))
        indices = sint.Array(len(content))
        @for_range(factor)
        def _(i):
            countdown.assign_vector(sorted_counts.get_vector(
                size=self.n_rows) - i - 1, base=i * self.n_rows)
            indices.assign_vector(regint.inc(self.n_rows), base=i * self.n_rows)
        sorted_counts.delete()
        if debug:
            print_ln('countdown = %s', countdown.reveal())
            print_ln('indices %s', indices.reveal())
        if fail > 1:
            n_countdown = sum(countdown.reveal() >= 0)
            runtime_error_if(n_valid != n_countdown,
                             'mismatch in countdown: %s/%s',
                             n_countdown, n_valid)
        ltz = countdown
        @multithread(n_threads, len(ltz), max_size=program.budget)
        def _(base, size):
            ltz.assign_vector(
                countdown.get_vector(base=base, size=size).less_than(
                    0, bit_length=util.log2(factor) + 1), base=base)
        if time:
            timer.next()
        perm = decision_tree.LocalSortPerm(ltz[:], n_threads=n_threads)
        perm.apply(indices)
        perm.apply(ltz)
        if time:
            timer.next()
        sorted_content = Matrix.create_from(content, n_threads=n_threads) \
            if content is self.content else content
        sorted_content.sort(key_indices=3, n_bits=1, n_threads=n_threads,
                            time=timer)
        if debug:
            print_ln('ltz %s', ltz.reveal())
            print_ln('sorted indices %s', indices.reveal())
            print_ln('sorted %s', sorted_content.reveal())
        if fail:
            n_fixed = len(ltz) - ltz.sum().reveal()
            runtime_error_if(
                n_good != n_fixed,
                'mismatch in valid entry number %s/%s', n_fixed, n_good)
        if time:
            timer.next()
        @multithread(n_threads, len(sorted_content), max_size=program.budget)
        def _(base, size):
            replace = ltz.get_vector(base=base, size=size)
            sorted_content.set_column(
                0, replace.if_else(
                    indices.get_vector(base=base, size=size),
                    sorted_content.get_column(0, base=base, size=size)),
                base=base)
        ltz.delete()
        indices.delete()
        if time:
            timer.next()
        sorted_content.sort(n_bits=util.log2(self.n_rows), signed=False,
                            n_threads=n_threads, time=timer)
        if debug:
            print_ln('res %s', sorted_content.reveal())
            @for_range(self.n_rows)
            def _(i):
                print_ln('res %s %s %s', i, sorted_content[i * factor].reveal(),
                         sorted_content[(i + 1) * factor - 1].reveal())
        if time:
            timer.next()
        max_non_zero = max_non_zero or factor
        assert factor <= max_non_zero
        res = SparseMatrix(self.n_rows, max_non_zero=max_non_zero)
        res.cols = (None,) * self.n_cols
        if max_non_zero != factor:
            res.rows.assign_all(0, n_threads=n_threads)
        @for_range_opt_multithread(n_threads, self.n_rows,
                                   disable_index_checks=True)
        def _(i):
            base = i * factor
            valid = sorted_content.get_column(
                3, base=base, size=factor).bit_not()
            res.rows[i].set_column(2, valid)
            for j in range(2):
                res.rows[i].set_column(j, valid * sorted_content.get_column(
                    j + 1, base=base, size=factor))
            if fail:
                @for_range_opt(factor)
                def _(j):
                    cell = sorted_content[i * factor + j]
                    valid = cell[3].bit_not()
                    row = cell[0].reveal()
                    runtime_error_if(row != i, 'bad row: %s/%s', row, i)
                    valid = valid.reveal()
                    valid_invalid = ((valid * valid.bit_not()) == 0).bit_not()
                    runtime_error_if(valid_invalid, 'invalid bit %s at %s, %s',
                                     valid, i, j)
            if sort:
                res.rows[i].sort(key_indices=2, n_bits=1, key_prep=util.bit_not)
        if sorted_content is not self.content:
            sorted_content.delete()
        if time:
            timer.end()
        combo_timer.end()
        return res

    def output_above(self, threshold):
        shuffled = Matrix.create_from(self.content)
        shuffled.secure_shuffle()
        places = Array.create_from(
            (shuffled.get_column(2) > threshold).bit_and(
                shuffled.get_column(3).bit_not()).reveal())

        @for_range_opt(len(places))
        def _(i):
            @if_(places[i])
            def _():
                print_ln('%s', shuffled[i].reveal())

def cycle_run(G, n_cycles, program, reveal=False, arg_base=None, fail=False,
              dry=False):
    try:
        avg_output_limit = int(program.args[arg_base])
    except:
        avg_output_limit = None

    try:
        n_threads = int(program.args[arg_base + 1])
    except:
        n_threads = None

    try:
        n_heavy_threads = int(program.args[arg_base + 2])
    except:
        n_heavy_threads = None

    M = SparseMatrix.from_graph(G, dry=dry)

    if 'red' in program.args:
        import networkx as nx
        # remove all two-cycles
        for u, v in nx.simple_cycles(G, length_bound=2):
            if u != v:
                G.remove_edge(u, v)
                G.remove_edge(v, u)
        M_red = SparseMatrix.from_graph(G, dry=dry)
    else:
        M_red = None

    print(M.rows.sizes, M.cols.sizes)

    res = M.find_cycles(n_cycles, avg_output_limit=avg_output_limit,
                        time=True, debug=False, fail=fail,
                        n_threads=n_threads, n_heavy_threads=n_heavy_threads,
                        output=reveal, reduced=M_red)

    if reveal:
        secret_res = res
        res = res.reveal()

        @for_range(len(res))
        def _(i):
            part = res[i]
            @for_range(len(part))
            def _(j):
                print_ln_if(part[j], 'size %s at %s', i + 2, j)

        @for_range_opt(len(res))
        def _(i):
            print_ln('%s nodes in length %s', secret_res[i].sum().reveal(),
                     i + 2)
