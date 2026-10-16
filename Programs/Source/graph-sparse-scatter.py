import networkx as nx

program.unlimited_compilation()

program.set_bit_length(32)

from Compiler.sparse import *

G = nx.read_adjlist(program.args[1], create_using=nx.DiGraph)
M = SparseMatrix.from_graph(G)

threshold = int(program.args[2])

arg_base = 3

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

fail = debug = follow = False
time = True

prod = M.mul_without_removal(
    M, avg_output_limit=avg_output_limit,
    fail=fail, debug=debug, n_threads=n_threads, time=time,
    follow=follow, n_heavy_threads=n_heavy_threads)

prod.output_above(threshold)
