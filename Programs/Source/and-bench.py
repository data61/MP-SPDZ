a = sbits.get_type(int(program.args[1]))(0)

@for_range(int(program.args[2]))
def _(i):
    a & a
