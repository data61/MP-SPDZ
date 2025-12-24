program.options_from_args()
sfix.set_precision_from_args(program)

try:
        n = int(program.args[1])
except:
        n = 10 ** 6

m = int(program.args[2])

x = sint(0, size=n)

@for_range(m)
def _(i):
        x.round(sfix.k + sfix.f, sfix.f, nearest=sfix.round_nearest,
                signed=True)
