n_apply = 1
if len(program.args) > 3:
    n_apply = int(program.args[3])

@for_range(int(program.args[2]))
def _(i):
    print_ln('%s', i)
    handle = sint.get_secure_shuffle(int(program.args[1]))

    @for_range(n_apply)
    def _(i):
        sint.Array(int(program.args[1])).secure_permute(handle)

print_ln('bye')
