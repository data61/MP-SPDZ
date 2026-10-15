#!/usr/bin/env python3


#     ===== Compiler usage instructions =====
#
# ./compile.py input_file
#
# will compile Programs/Source/input_file.mpc onto
# Programs/Bytecode/input_file.bc and Programs/Schedules/input_file.sch
#
# (run with --help for more options)
#
# See the compiler documentation at https://mp-spdz.readthedocs.io
# for details on the Compiler package
from Compiler.compilerLib import Compiler


def compilation(compiler):
    prog = compiler.compile_file()

    if prog.public_input_file is not None:
        print(
            "WARNING: %s is required to run the program" % prog.public_input_file.name
        )


def main(compiler):
    compiler.prep_compile()
    if compiler.options.profile:
        import cProfile

        p = cProfile.Profile().runctx("compilation(compiler)", globals(), locals())
        p.dump_stats(compiler.args[0] + ".prof")
        p.sort_stats("cumulative").print_stats(40)
    else:
        compilation(compiler)


if __name__ == "__main__":
    compiler = Compiler()
    main(compiler)
