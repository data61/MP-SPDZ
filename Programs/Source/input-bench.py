x = personal(0, cint(0, size=int(program.args[1])))

@for_range(int(program.args[2]))
def _(i):
    sint(x).store_in_mem(0)
