import networkx as nx

program.set_bit_length(32)

from Compiler.sparse import *

G = nx.DiGraph()

n = int(program.args[1])

m = int(program.args[2])

n_cycles = int(program.args[3])

assert n_cycles + m < n

for i in range(n_cycles):
    G.add_edge(i, (i + 1) % n_cycles)

for i in range(n_cycles, n):
    G.add_edge(i, i - n_cycles)

for i in range(m):
    G.add_edge(n_cycles, n_cycles + 1 + i)

print('graph size', len(G))
print('nodes', list(G))

cycle_run(G, n_cycles, program, reveal=True, arg_base=4)
