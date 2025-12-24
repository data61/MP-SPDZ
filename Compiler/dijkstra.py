""" This module implements `Dijkstra's algorithm
<https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm>`_ based on
oblivious RAM. """


from Compiler.oram import *

from Compiler.program import Program

ORAM = OptimalORAM

try:
    prog = program.Program.prog
    prog.set_bit_length(min(64, prog.bit_length))
except AttributeError:
    pass

class HeapEntry(object):
    fields = ['empty', 'prio', 'value']
    def __init__(self, int_type, *args):
        self.int_type = int_type
        if not len(args):
            raise CompilerError()
        if len(args) == 1:
            args = args[0]
        for field,arg in zip(self.fields, args):
            self.__dict__[field] = arg
    def data(self):
        return self.prio, self.value
    def __repr__(self):
        return '(' + ', '.join('%s=%s' % (field,self.__dict__[field]) \
                                   for field in self.fields) + ')'
    def __eq__(self, other):
        return self.__dict__ == other.__dict__
    def __gt__(self, other):
        return (1 - self.empty) * (1 - other.empty) * \
            (self.int_type(self.prio) > self.int_type(other.prio))
    def __iter__(self):
        for field in self.fields:
            yield self.__dict__[field]
    def __add__(self, other):
        return type(self)(self.int_type, (i + j for i,j in zip(self, other)))
    def __sub__(self, other):
        return type(self)(self.int_type, (i - j for i,j in zip(self, other)))
    def __xor__(self, other):
        return type(self)(self.int_type, (i ^ j for i,j in zip(self, other)))
    def __mul__(self, other):
        return type(self)(self.int_type, (other * i for i in self))
    __rxor__ = __xor__
    __rmul__ = __mul__
    def hard_conv_me(self, value_type):
        return type(self)(self.int_type, \
                              *(value_type.hard_conv(x) for x in self))
    def dump(self):
        print_ln('empty %s, prio %s, value %s', *(reveal(x) for x in self))

class HeapORAM(object):
    def __init__(self, size, oram_type, init_rounds, int_type, entry_size=None):
        if entry_size is None:
            entry_size = (32,log2(size))
        self.int_type = int_type
        self.oram = oram_type(size, entry_size=entry_size, \
                                  init_rounds=init_rounds, \
                                  value_type=int_type.basic_type)
    def __getitem__(self, index):
        return self.make_entry(*self.oram.read(index))
    def make_entry(self, value, empty):
        return HeapEntry(self.int_type, (empty,) + value)
    def __setitem__(self, index, value):
        self.oram.access(index, value.data(), True, new_empty=value.empty)
    def access(self, index, value, write):
        tmp = self.oram.access(index, value.data(), write)
        return self.make_entry(*tmp)
    def delete(self, index, for_real):
        self.oram.delete(index, for_real)
    def read_and_maybe_remove(self, index):
        entry, state = self.oram.read_and_maybe_remove(index)
        return self.make_entry(*entry), state
    def add(self, index, entry, state):
        self.oram.add(Entry(MemValue(index), \
                                [MemValue(i) for i in entry.data()], \
                                entry.empty), state=state)
    def __len__(self):
        return len(self.oram)

class HeapQ(object):
    def __init__(self, max_size, oram_type=ORAM, init_rounds=-1, int_type=sint, entry_size=None):
        if entry_size is None:
            entry_size = (32, log2(max_size))
        basic_type = int_type.basic_type
        self.max_size = max_size
        self.levels = log2(max_size)
        self.depth = self.levels - 1
        self.heap = HeapORAM(2**self.levels, oram_type, init_rounds, int_type, entry_size=entry_size)
        self.value_index = oram_type(max_size, entry_size=entry_size[1], \
                                         init_rounds=init_rounds, \
                                         value_type=basic_type)
        self.size = MemValue(int_type(0))
        self.int_type = int_type
        self.basic_type = basic_type
        prog.reading('heap queue', 'KS14', 'Section 5.1')
        print('heap: %d levels, depth %d, size %d, index size %d' % \
            (self.levels, self.depth, self.heap.oram.size, self.value_index.size))
    def update(self, value, prio, for_real=True):
        self._update(self.basic_type.hard_conv(value), \
                         self.basic_type.hard_conv(prio), \
                         self.basic_type.hard_conv(for_real))
    def pop(self, for_real=True):
        return self._pop(self.basic_type.hard_conv(for_real))
    def bubble_up(self, start):
        bits = bit_decompose(start, self.levels)
        bits.reverse()
        bits = [0] + floatingpoint.PreOR(bits, self.levels)
        bits = [bits[i+1] - bits[i] for i in range(self.levels)]
        shift = self.int_type.bit_compose(bits)
        childpos = MemValue(start * shift)
        @for_range(self.levels - 1)
        def f(i):
            parentpos = childpos.right_shift(1, self.levels + 1)
            parent, parent_state = self.heap.read_and_maybe_remove(parentpos)
            child, child_state = self.heap.read_and_maybe_remove(childpos)
            swap = parent > child
            new_parent, new_child = cond_swap(swap, parent, child)
            self.heap.add(childpos, new_child, child_state)
            self.heap.add(parentpos, new_parent, parent_state)
            self.value_index.access(new_parent.value, parentpos, swap)
            self.value_index.access(new_child.value, childpos, swap)
            childpos.write(parentpos)
    @method_block
    def _pop(self, for_real=True):
        Program.prog.curr_tape.\
            start_new_basicblock(name='heapq-pop')
        pop_for_real = for_real * (self.size != 0)
        entry = self.heap[1]
        self.value_index.delete(entry.value, for_real)
        last = self.heap[self.basic_type(self.size)]
        self.heap.access(1, last, pop_for_real)
        self.value_index.access(last.value, 1, for_real * (self.size != 1))
        self.heap.delete(self.basic_type(self.size), for_real)
        self.size -= self.int_type(pop_for_real)
        parentpos = MemValue(self.basic_type(1))
        @for_range(self.levels - 1)
        def f(i):
            childpos = 2 * parentpos
            left_child, l_state = self.heap.read_and_maybe_remove(childpos)
            right_child, r_state = self.heap.read_and_maybe_remove(childpos+1)
            go_right = left_child > right_child
            otherchildpos = childpos + 1 - go_right
            childpos += go_right
            child, other_child = cond_swap(go_right, left_child, right_child)
            child_state, other_state = cond_swap(go_right, l_state, r_state)
            parent, parent_state = self.heap.read_and_maybe_remove(parentpos)
            swap = parent > child
            new_parent, new_child = cond_swap(swap, parent, child)
            self.heap.add(childpos, new_child, child_state)
            self.heap.add(otherchildpos, other_child, other_state)
            self.heap.add(parentpos, new_parent, parent_state)
            self.value_index.access(new_parent.value, parentpos, swap)
            self.value_index.access(new_child.value, childpos, swap)
            parentpos.write(childpos)
        self.check()
        return entry.value
    @method_block
    def _update(self, value, prio, for_real=True):
        Program.prog.curr_tape.\
            start_new_basicblock(name='heapq-update')
        index, not_found = self.value_index.read(value)
        self.size += self.int_type(not_found * for_real)
        index = if_else(not_found, self.basic_type(self.size), index[0])
        self.value_index.access(value, self.basic_type(self.size), \
                                    not_found * for_real)
        self.heap.access(index, HeapEntry(self.int_type, 0, prio, value), for_real)
        self.bubble_up(index)
        self.check()
    def __len__(self):
        return self.size
    def check(self):
        if debug:
            for i in range(len(self.heap)):
                if ((2 * i + 1 < len(self.heap) and \
                         self.heap[i] > self.heap[2*i+1]) or \
                        (2 * i + 2 < len(self.heap) and \
                             self.heap[i] > self.heap[2*i+2])) and \
                             not self.heap[i].empty:
                    raise Exception('heap condition violated at %d' % i)
                if i >= self.size and not self.heap[i].empty:
                    raise Exception('wrong size at %d' % i)
                if i < self.size and self.heap[i].empty:
                    raise Exception('empty entry in heap at %d' % i)
                # if not self.heap[i].empty and \
                #         self.heap[i].value not in self.value_index:
                #     raise Exception('missing index at %d' % i)
            for value,(index,empty) in enumerate(self.value_index):
                if not empty and self.heap[index].value != value:
                    raise Exception('index violated at %d' % index)
        if debug_online:
            @for_range(self.max_size)
            def f(value):
                index, not_found = self.value_index.read(value)
                index, not_found = index[0].reveal(), not_found.reveal()
                @if_(not_found == 0)
                def f():
                    heap_value = self.heap[index].value.reveal()
                    @if_(heap_value != value)
                    def f():
                        print_ln('heap mismatch: %s:%s in index, %s in heap', \
                                     value, index, heap_value)
                        crash()            
    def dump(self, msg=''):
        print_ln(msg)
        print_ln('size: %s', self.size.reveal())
        print_str('heap:')
        if isinstance(self.heap.oram, LinearORAM):
            for entry in self.heap.oram.ram:
                print_str(' %s:%s,%s', entry.empty().reveal(), \
                              entry.x[0].reveal(), entry.x[1].reveal())
        else:
            for i in range(self.max_size+1):
                print_str(' %s:%s', *(x.reveal() for x in self.heap.oram[i]))
        print_ln()
        print_str('value index:')
        if isinstance(self.value_index, LinearORAM):
            for entry in self.value_index.ram:
                print_str(' %s:%s', entry.empty().reveal(), entry.x[0].reveal())
        else:
            for i in range(self.max_size):
                print_str(' %s:%s', i, self.value_index[i].reveal())
        print_ln()
        print_ln()

def dijkstra(source, edges, e_index, oram_type, n_loops=None, int_type=None,
             debug=False):
    """ Securely compute Dijstra's algorithm on a secret graph. See
    :download:`../Programs/Source/dijkstra_example.mpc` for an
    explanation of the required inputs.

    :param source: source node (secret or clear-text integer)
    :param edges: ORAM representation of edges
    :param e_index: ORAM representation of vertices
    :param oram_type: ORAM type to use internally (default:
      :py:func:`~Compiler.oram.OptimalORAM`)
    :param n_loops: when to stop (default: number of edges)
    :param int_type: secret integer type (default: sint)

    """
    prog.reading("Dijkstra's algorithm", "KS14", "Section 5.2")
    vert_loops = n_loops * e_index.size // edges.size \
        if n_loops else -1
    dist = oram_type(e_index.size, entry_size=(32,log2(e_index.size)), \
                         init_rounds=vert_loops, value_type=int_type)
    int_type = dist.value_type
    basic_type = int_type.basic_type
    #visited = ORAM(e_index.size)
    #previous = oram_type(e_index.size)
    Q = HeapQ(e_index.size, oram_type, init_rounds=vert_loops, \
                  int_type=int_type)

    if n_loops is not None:
        # put initialization in different timer
        stop_timer()
        start_timer(1)
    dist[source] = (0,0)
    Q.update(source, 0)
    if n_loops is not None:
        stop_timer(1)
        start_timer()
    last_edge = MemValue(basic_type(1))
    i_edge = MemValue(int_type(0))
    u = MemValue(basic_type(0))
    running = MemValue(basic_type(1))
    @for_range(n_loops or edges.size)
    def f(i):
        print_ln('loop %s', i)
        time()
        running.write(last_edge.bit_not().bit_or(Q.size > 0).bit_and(running))
        u.write(if_else(last_edge, Q.pop(last_edge), u))
        #visited.access(u, True, last_edge)
        i_edge.write(int_type(if_else(last_edge, e_index[u], i_edge)))
        v, weight, le = edges[i_edge]
        last_edge.write(le)
        i_edge.iadd(1)
        alt = int_type(dist[u][0]) + int_type(weight)
        #is_shorter = (alt < dist[v]) * (1 - visited[v])
        dv, not_visited = dist.read(v)
        # relying on default dv negative here
        is_shorter = (alt < int_type(dv[0])) + not_visited
        is_shorter *= running
        dist.access(v, (basic_type(alt), u), is_shorter)
        #previous.access(v, u, is_shorter)
        Q.update(v, basic_type(alt), is_shorter)
        if debug:
            print_ln('u: %s, v: %s, alt: %s, dv: %s, first visit: %s, '
                     'shorter: %s, running: %s, queue size: %s, last edge: %s',
                     u.reveal(), v.reveal(), alt.reveal(), dv[0].reveal(),
                     not_visited.reveal(), is_shorter.reveal(),
                     running.reveal(), Q.size.reveal(), last_edge.reveal())
    return dist

def convert_graph(G):
    """ Convert a `NetworkX directed graph
    <https://networkx.org/documentation/stable/reference/classes/digraph.html>`_
    to the cleartext representation of what :py:func:`dijkstra` expects. """
    G = G.copy()
    for u in G:
        for v in G[u]:
            G[u][v].setdefault('weight', 1)
    edges = [None] * (2 * G.size())
    e_index = [None] * (len(G))
    i = 0
    for v in sorted(G):
        e_index[v] = i
        for u in sorted(G[v]):
            edges[i] = [u, G[v][u]['weight'], 0]
            i += 1
        if not G[v]:
            edges[i] = [v, 0, 0]
            i += 1
        edges[i-1][-1] = 1
    return list(filter(lambda x: x, edges)), e_index

def test_dijkstra(G, source, oram_type=ORAM, n_loops=None,
                  int_type=sint):
    """ Securely compute Dijstra's algorithm on a cleartext graph.

    :param G: directed graph with NetworkX interface
    :param source: source node (secret or clear-text integer)
    :param n_loops: when to stop (default: number of edges)
    :param int_type: secret integer type (default: sint)

    """
    edges_list, e_index_list = convert_graph(G)
    edges = oram_type(len(edges_list), \
                          entry_size=(log2(len(G)), log2(len(G)), 1), \
                          init_rounds=0, value_type=int_type.basic_type)
    e_index = oram_type(len(e_index_list), entry_size=log2(len(edges_list)), \
                            value_type=int_type.basic_type)
    for i in range(n_loops or edges.size):
        cint(i).print_reg('edge')
        time()
        edges[i] = edges_list[i]
    vert_loops = n_loops * e_index.size // edges.size \
        if n_loops else e_index.size
    for i in range(vert_loops):
        cint(i).print_reg('vert')
        time()
        e_index[i] = e_index_list[i]
    return dijkstra(source, edges, e_index, oram_type, n_loops, int_type)

def test_dijkstra_on_cycle(n, oram_type=ORAM, n_loops=None, int_type=sint):
    n_edges = 2 * n
    edges = oram_type(n_edges, entry_size=(log2(n),log2(n),1), init_rounds=0, 
                      value_type=int_type.basic_type)
    e_index = oram_type(n, entry_size=log2(n_edges), init_rounds=0, \
                            value_type=int_type.basic_type)
    @for_range(n_loops or edges.size)
    def f(i):
        cint(i).print_reg('edge')
        time()
        neighbour = ((i >> 1) + 2 * (i % 2) - 1 + n) % n
        edges[i] = (neighbour, 1, i % 2)
    vert_loops = n_loops * e_index.size // edges.size \
        if n_loops else e_index.size
    @for_range(vert_loops)
    def f(i):
        cint(i).print_reg('vert')
        time()
        e_index[i] = 2 * i
    return dijkstra(0, edges, e_index, oram_type, n_loops, int_type)

def test_dijkstra_on_complete(n, oram_type=ORAM, n_loops=None, int_type=sint):
    n_edges = n**2
    edges = oram_type(n_edges, entry_size=(log2(n),log2(n),1), init_rounds=0, 
                      value_type=int_type.basic_type)
    e_index = oram_type(n, entry_size=log2(n_edges), init_rounds=0, \
                            value_type=int_type.basic_type)
    @for_range(n_loops or n)
    def f(i):
        @for_range(n_loops - 1 if n_loops else n - 1)
        def f(j):
            cint(i).print_reg('v1')
            cint(j).print_reg('v2')
            time()
            edges[i*n+j] = (j, 1, 0)
        edges[i*n+n-1] = (n - 1, 1, 1)
    if n_loops is not None:
        stop_timer()
        start_timer(2)
    @for_range(n_loops or n)
    def f(i):
        cint(i).print_reg('vert')
        time()
        e_index[i] = n * i
    if n_loops is not None:
        stop_timer(2)
        start_timer()
    return dijkstra(0, edges, e_index, oram_type, \
                        n_loops**2 if n_loops else n**2, int_type)

class ExtInt(object):
    def __init__(self, x, inf=False):
        self.x = x
        self.inf = inf
    def __add__(self, other):
        if isinstance(other, ExtInt):
            return ExtInt(self.x + other.x, self.inf + other.inf)
        else:
            return ExtInt(self.x + other, self.inf)
    def __sub__(self, other):
        if isinstance(other, ExtInt):
            return ExtInt(self.x - other.x, self.inf - other.inf)
        else:
            return ExtInt(self.x - other, self.inf)    
    def __rsub__(self, other):
        return ExtInt(other - self.x, -self.inf)
    def __mul__(self, other):
        if isinstance(other, ExtInt):
            raise Exception()
            return ExtInt(self.x * other.x, self.inf * other.inf)
        else:
            return ExtInt(self.x * other, self.inf * other)
    __radd__ = __add__
    __rmul__ = __mul__
    def __lt__(self, other):
        if isinstance(other, ExtInt):
            return ((1 - self.inf) * (1 - other.inf) * (self.x < other.x)) + \
                other.inf
        else:
            return (1 - self.inf) * (self.x < other)
    def __gt__(self, other):
        if isinstance(other, ExtInt):
            return ((1 - self.inf) * (1 - other.inf) * (self.x > other.x)) + \
                self.inf
        else:
            return 1 - (1 -self.inf) * (1 - (self.x > other))
    def __repr__(self):
        if self.inf:
            return 'T'
        else:
            return str(self.x)

class Vector(object):
    """ Works like a vector. """
    def __add__(self, other):
        print('add', type(self))
        res = type(self)(len(self))
        @for_range(len(self))
        def f(i):
            res[i] = self[i] + other[i]
        return res
    def __sub__(self, other):
        print('sub', type(other))
        res = type(other)(len(self))
        @for_range(len(self))
        def f(i):
            res[i] = self[i] - other[i]
        return res
    def __mul__(self, other):
        if isinstance(other, Vector):
            res = type(self)(1)
            res[0] = ExtInt(0)
            @for_range(len(self))
            def f(i):
                res[0] += self[i] * other[i]
            return res[0]
        else:
            print('mul', type(self))
            res = type(self)(len(self))
            @for_range_parallel(1024, len(self))
            def f(i):
                res[i] = self[i] * other
            return res
    __rmul__ = __mul__

class VectorList(Vector, list):
    pass

class VectorArray(Vector):
    def __init__(self, length, address=None):
        self.length = length
        if address is None:
            self.arrays = [Array(length, 's') for i in range(2)]
        else:
            self.arrays = [Array(length, 's', addr) \
                               for addr in (address,address+length)]
    def assign(self, values):
        @for_range(len(self))
        def f(i):
            self[i] = values[i]
    def assign_all(self, value):
        self.arrays[0].assign_all(value.x)
        self.arrays[1].assign_all(value.inf)
    def __getitem__(self, index):
        return ExtInt(*[v[index] for v in self.arrays])
    def __setitem__(self, index, value):
        self.arrays[0][index] = value.x
        self.arrays[1][index] = value.inf
    def __len__(self):
        return len(self.arrays[0])

class IntVectorArray(Vector, Array):
    def __init__(self, length):
        Array.__init__(self, length, 's')

class Matrix(object):
    """ Guess what. """
    def __init__(self, rows, columns):
        self.rows = rows
        self.columns = columns
        self.address = Array(2 * rows * columns, 's').address
    def __getitem__(self, index):
        return VectorArray(self.columns, self.address + 2 * self.columns * index)
    def __setitem__(self, index, value):
        self[index].assign(value)
    def __len__(self):
        return self.rows
    def assign_all(self, value):
        @for_range(len(self))
        def f(i):
            self[i].assign_all(value)
        return self

def updatevector(vector, index, value):
    @for_range_parallel(1024, len(vector))
    def f(i):
        vector[i] += index[i] * (value - vector[i])

def binarymin(A):
    if len(A) == 1:
        return [1], A[0]
    else:
        half = len(A) // 2
        A_prime = VectorArray(half)
        B = IntVectorArray(half)
        i = IntVectorArray(len(A))
        @for_range_parallel(128, half)
        def f(j):
            B[j] = A[2*j] < A[2*j+1]
            A_prime[j] = if_else(B[j], A[2*j], A[2*j+1])
        i_prime, min = binarymin(A_prime)
        @for_range_parallel(1024, half)
        def f(j):
            i[2*j] = B[j] * i_prime[j]
            i[2*j+1] = (1 - B[j]) * i_prime[j]
        return i, min

def stupid_dijkstra(M, s, n_loops=None):
    if n_loops is not None:
        stop_timer()
        start_timer(1)
    P = Matrix(len(M), len(M))
    P.assign_all(ExtInt(0))
    d = VectorArray(len(M))
    d.assign_all(ExtInt(0,True))
    q = VectorArray(len(M))
    q.assign_all(ExtInt(0))
    d_prime = VectorArray(len(M))
    updatevector(d, s, 0)
    if n_loops is not None:
        stop_timer(1)
        start_timer()
    @for_range(n_loops or len(M))
    def f(i):
        if n_loops is not None:
            stop_timer()
            start_timer(2)
        d_prime.assign(d + q)
        k, min = binarymin(d_prime)
        updatevector(q, k, ExtInt(0,True))
        if n_loops is not None:
            stop_timer(2)
            start_timer()
        @for_range(n_loops or len(M))
        def f(j):
            a = (d + M[j]) * k
            c = a < d[j]
            P[j] = P[j] + c * (k - P[j])
            d[j] += c * (a - d[j])
    return d, P

def convert_graph_to_matrix(G):
    M = Matrix(len(G), len(G))
    M.assign_all(ExtInt(0,True))
    for u in G:
        for v in G[u]:
            M[u][v] = ExtInt(G[u][v].get('weight', 1))
    return M

def test_stupid_dijkstra(G, source):
    return stupid_dijkstra(convert_graph_to_matrix(G), \
                               demux(bit_decompose(source, log2(len(G)))))

def test_stupid_dijkstra_on_cycle(n, n_loops=None):
    if n_loops is not None:
        stop_timer()
        start_timer(1)
    M = Matrix(n, n)
    M.assign_all(ExtInt(0,True))
    s = IntVectorArray(n)
    s.assign_all(0)
    s[0] = 1
    @for_range(n)
    def f(i):
        M[i][(i+1)%n] = ExtInt(1)
        M[i][(i-1+n)%n] = ExtInt(1)
    if n_loops is not None:
        stop_timer(1)
        start_timer()
    return stupid_dijkstra(M, s, n_loops)
