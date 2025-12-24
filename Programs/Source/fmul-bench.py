program.options_from_args()
sfix.set_precision_from_args(program)

try:
        n = int(program.args[1])
except:
        n = 10 ** 6

m = int(program.args[2])
a = sfix(0, size=n)

@for_range(m)
def _(i):
    (a * a).store_in_mem(0)
