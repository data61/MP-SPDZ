from Compiler import sorting
from Compiler.library import MultiTimer
from Compiler.types import _bitint

n_bits = 32
program.set_bit_length(n_bits)

n = int(program.args[1])

if program.use_binary_shuffle:
    t = sbitintvec.get_type(n_bits)
else:
    t = sint

a = t.Array(n)
limit = n
a[:] = regint.inc(limit, limit - 1, -1)

try:
    n_threads = int(program.args[3])
except:
    n_threads = None

try:
    seq_shuffle_gen = int(program.args[4])
except:
    seq_shuffle_gen = False

_bitint.linear_rounds = 'linear' in program.args

res = sorting.radix_sort(a, n_bits=n_bits, l=int(program.args[2]),
                         n_threads=n_threads, only_perm=True, time=True,
                         seq_shuffle_gen=seq_shuffle_gen)

print_ln('%s', list(res.get_vector(size=min(100, n)).reveal()))
