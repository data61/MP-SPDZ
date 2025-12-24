program.options_from_args()
sfix.set_precision_from_args(program)

n = int(program.args[1])
m = int(program.args[2])
a = sfix(0, size=n)

@for_range(m)
def _(i):
    (a / a).store_in_mem(0)
