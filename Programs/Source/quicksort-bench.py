from sorting import quicksort
import math

program.options_from_args()

n = int(program.args[1])

try:
    n_threads = int(program.args[2])
except:
    n_threads = None

try:
    n_bits = int(program.args[3])
except:
    n_bits = 32

if n_bits > math.log(n, 2):
    a = regint.inc(n, n - 1, -1)
else:
    wrap = 2 ** max(1, n_bits - 2)
    a = regint.inc(n, step=1, repeat=1, wrap=wrap)

a = Array.create_from(sint(a))
print_ln('input %s...', a.get_vector(size=min(100, n)).reveal())

quicksort(a, n_bits=n_bits, verbose=True, time=True, n_threads=n_threads)

print_ln('output %s...', a.get_vector(size=min(100, n)).reveal())

if n_bits > math.log(n, 2):
    crash(a[-1].reveal() != n - 1)
else:
    crash(a[-1].reveal() != wrap - 1)
