x = sint(0, size=int(program.args[1]))

m = int(program.args[2])
@for_range(m)
def _(i):
    (x * x)#.store_in_mem(0)
