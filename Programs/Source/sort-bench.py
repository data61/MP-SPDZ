from Compiler import sorting
from Compiler.library import MultiTimer

n = int(program.args[1])

try:
    m = int(program.args[3])
except:
    m = None

try:
    l = int(program.args[4])
except:
    l = 1

try:
    n_threads = int(program.args[5])
except:
    n_threads = None

try:
    n_shuffle_threads = int(program.args[6])
except:
    n_shuffle_threads = None

try:
    n_bits = int(program.args[7])
except:
    n_bits = 32

program.set_bit_length(n_bits)

if m:
    a = sint.Matrix(n, m)
    a[:] = regint.inc(n * m, n - 1, -1, m)
else:
    a = sint.Array(n)
    a.assign_all(100)
    limit = min(n, 10 ** 6)
    a.assign_vector(sint(regint.inc(limit, limit - 1, -1)))

mixed = int(program.args[2])
program.use_binary_shuffle = mixed

a.sort(n_bits=n_bits, time=True, l=l, n_threads=n_threads,
       n_shuffle_threads=n_shuffle_threads)

print_ln('%s', a.get_vector(0, min(100, n)).reveal())
