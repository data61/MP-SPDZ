n = int(program.args[1])
sbv64 = sbitvec.get_type(64)

@for_range(int(program.args[2]))
def _(i):
    x = sbv64(regint.inc(n)).secure_permute(
        sbv64.get_secure_shuffle(n))
