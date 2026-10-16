import networkx as nx

from Compiler.sparse import *

G = nx.read_adjlist(program.args[1], create_using=nx.DiGraph)

try:
    avg_output_limit = int(program.args[2])
except:
    avg_output_limit = None

try:
    max_nonzero = int(program.args[3])
except:
    max_nonzero = None

M = SparseMatrix.from_graph(G, randomize=True)

print(M.rows.sizes, M.cols.sizes)

cells = M.mul_without_removal(M, avg_output_limit=avg_output_limit,
                              balance_rows=True, time=True, debug=False)
prod = cells.reveal()

mm = avg_output_limit or (M.rows.sizes[1] * M.cols.sizes[1])
max_diff = MemValue(0)
index = MemValue(0)

@for_range(1000)
def _(j):
    i = len(prod) // 2 + j
    @if_(i < len(prod))
    def _():
        print_ln('%s %s', i // mm, prod[i])
        @if_(prod[i][2])
        def _():
            index.write(prod[i][0])

@for_range(len(prod))
def _(i):
    diff = abs(i // mm - prod[i][0])
    @if_(max_diff < diff)
    def _():
        max_diff.write(diff)

prod = cells.get_tight_row_matrix(max_nonzero=max_nonzero, time=True,
                                  fail=False, debug=False)

print_ln('index %s', index)

@for_range_opt(prod.rows.sizes[1])
def _(i):
    print_ln('%s', prod.rows[index][i].reveal())

print_ln('cells above')
cells.output_above(1)

print_ln('max diff %s', max_diff)
