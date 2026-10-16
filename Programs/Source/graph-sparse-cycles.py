import networkx as nx

program.unlimited_compilation()

program.set_bit_length(32)

from Compiler.sparse import *

n_cycles = int(program.args[2])

G = nx.read_adjlist(program.args[1], create_using=nx.DiGraph)

cycle_run(G, n_cycles, program, reveal=True, arg_base=3,
          fail='fail' in program.args, dry='dry' in program.args)
