#sfix.set_precision(32, 63)
#program.use_trunc_pr = True
#program.use_split(3)
program.options_from_args()
sfix.set_precision_from_args(program)
try:
    n_loops = int(program.args[2])
except:
    n_loops = 1

a = sfix(cint(0, size=int(program.args[1])))

@for_range(n_loops)
def _(i):
    (a < a)#.store_in_mem(0)
