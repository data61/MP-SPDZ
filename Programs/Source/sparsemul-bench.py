from Compiler.sparse import *

n = int(program.args[1])
m = int(program.args[2])
M = SparseMatrix(n, n, m)
M.mul_without_removal(M, avg_output_limit=int(program.args[3]), time=True)
