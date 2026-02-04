from Compiler.compilerLib import Compiler
from Compiler.types import sfix, Matrix
from Compiler.library import print_ln, for_range
from matsat_utils import MatSatUtils

""" compilation instructions
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/test_save_posterior.py --n 3
make -j8 shamir-party.x
./shamir-party.x -N 3 -p 0 -pn 5001 test_save_posterior
./shamir-party.x -N 3 -p 1 -pn 5001 test_save_posterior
./shamir-party.x -N 3 -p 2 -pn 5001 test_save_posterior
"""

compiler = Compiler()
compiler.parser.add_option("--n", dest="n", type=int, default=3)


@compiler.register_function("test_save_posterior")
def test_save_posterior():
    compiler.parse_args()
    n = compiler.options.n or 3

    print_ln("Creating %sx%s test matrix of sfix...", n, n)

    # Create a test matrix with some values
    matrix = Matrix(n, n, sfix)

    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            # Fill with some test values: convert regint to sfix first
            # Calculate value as sfix: (i * n + j + 1.0)
            val = sfix(i) * sfix(n) + sfix(j) + sfix(1.0)
            matrix[i][j] = val
            print_ln("matrix[%s][%s] = %s", i, j, matrix[i][j].reveal())

    print_ln("Saving matrix to file...")
    MatSatUtils.save_posterior(matrix, n)
    print_ln("Successfully saved %sx%s matrix to file", n, n)


if __name__ == "__main__":
    compiler.compile_func()
