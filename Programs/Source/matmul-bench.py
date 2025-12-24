n = int(program.args[1])
try:
    m = int(program.args[3])
except:
    m = n
try:
    k = int(program.args[4])
except:
    k = n
A = sint.Matrix(n, m)
B = sint.Matrix(m, k)

@for_range(int(program.args[2]))
def _(i):
    A * B
