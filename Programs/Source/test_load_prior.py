from Compiler.compilerLib import Compiler
from Compiler.types import sfix, Matrix
from Compiler.library import print_ln, for_range
from matsat_utils import MatSatUtils

""" compilation instructions
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/test_load_prior.py --n 3 --iteration_no 0
make -j8 shamir-party.x
./shamir-party.x -N 3 -p 0 -pn 5001 test_load_prior
./shamir-party.x -N 3 -p 1 -pn 5001 test_load_prior
./shamir-party.x -N 3 -p 2 -pn 5001 test_load_prior
"""

compiler = Compiler()
compiler.parser.add_option("--n", dest="n", type=int, default=3)
compiler.parser.add_option("--iteration_no", dest="iteration_no", type=int, default=0)


@compiler.register_function("test_load_prior")
def test_load_prior():
    compiler.parse_args()
    n = compiler.options.n or 3
    iteration_no = compiler.options.iteration_no or 0

    print_ln("Loading matrix from file (n=%s, iteration_no=%s)...", n, iteration_no)

    # Load the matrix
    matrix, stop_pos = MatSatUtils.load_prior(n, iteration_no)
    if iteration_no == 0:
        print_ln("Using default prior matrix (iteration_no=0)")
    else:
        print_ln("Loaded matrix from file (stop_pos=%s)", stop_pos)

    # Print the loaded matrix
    print_ln("Matrix contents:")

    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            print_ln("matrix[%s][%s] = %s", i, j, matrix[i][j].reveal())


if __name__ == "__main__":
    compiler.compile_func()
