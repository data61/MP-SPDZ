import math

n = int(program.args[1])
n_sqrt = int(math.sqrt(n))

sfix.Matrix(n_sqrt, 10) * sfix.Matrix(10, n_sqrt)
(sfix(0, size=n) < 0).store_in_mem(0)

sint.Array(n).secure_shuffle()

sint(personal(0, cint(0, size=n)))
