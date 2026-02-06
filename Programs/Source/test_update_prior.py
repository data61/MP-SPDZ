from Compiler.compilerLib import Compiler
from Compiler.types import sfix, sint, Matrix, Array
from Compiler.library import print_ln, for_range
from matsat_utils import MatSatUtils

""" compilation instructions
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/test_update_prior.py --n 3 --path_length 3
make -j8 shamir-party.x
./shamir-party.x -N 3 -p 0 -pn 5001 test_update_prior
./shamir-party.x -N 3 -p 1 -pn 5001 test_update_prior
./shamir-party.x -N 3 -p 2 -pn 5001 test_update_prior
"""

compiler = Compiler()
compiler.parser.add_option("--n", dest="n", type=int, default=3)
compiler.parser.add_option("--path_length", dest="path_length", type=int, default=3)


@compiler.register_function("test_update_prior")
def test_update_prior():
    compiler.parse_args()
    n = compiler.options.n or 3
    path_length = compiler.options.path_length or 3

    print_ln("=== Testing update_prior ===")
    print_ln("Grid size: %sx%s, Path length: %s", n, n, path_length)

    # Create prior matrix initialized to 0.5
    prior = Matrix(n, n, sfix)
    print_ln("Initializing prior matrix to 0.5...")

    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            prior[i][j] = sfix(0.5)
            print_ln("prior[%s][%s] = %s", i, j, prior[i][j].reveal())

    # Create test path: simple horizontal path (0,0) -> (0,1) -> (0,2)
    qx = Array(path_length, sint)
    qy = Array(path_length, sint)

    print_ln("Creating test path...")
    @for_range(path_length)
    def _(i):
        qx[i] = sint(0)  # All x-coordinates are 0
        qy[i] = sint(i)  # y-coordinates: 0, 1, 2, ...
        print_ln("Path step %s: (%s, %s)", i, qx[i].reveal(), qy[i].reveal())

    # Test 1: Safe path (is_solved == 1)
    print_ln("\n=== Test 1: Safe Path (is_solved = 1) ===")
    is_solved_safe = sint(1)
    posterior_safe, info_gain_safe = MatSatUtils.update_prior(
        prior, qx, qy, n, path_length, is_solved_safe
    )

    print_ln("Information gain (safe path): %s", info_gain_safe.reveal())
    print_ln("Posterior matrix after safe path update:")
    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            print_ln("posterior_safe[%s][%s] = %s", i, j, posterior_safe[i][j].reveal())

    # Test 2: Dangerous path (is_solved == 0)
    # Reset prior to 0.5 for second test
    print_ln("\n=== Test 2: Dangerous Path (is_solved = 0) ===")
    print_ln("Resetting prior matrix to 0.5...")
    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            prior[i][j] = sfix(0.5)

    is_solved_dangerous = sint(0)
    posterior_dangerous, info_gain_dangerous = MatSatUtils.update_prior(
        prior, qx, qy, n, path_length, is_solved_dangerous
    )

    print_ln("Information gain (dangerous path): %s", info_gain_dangerous.reveal())
    print_ln("Posterior matrix after dangerous path update:")
    @for_range(n)
    def _(i):
        @for_range(n)
        def __(j):
            print_ln(
                "posterior_dangerous[%s][%s] = %s",
                i,
                j,
                posterior_dangerous[i][j].reveal(),
            )

    print_ln("\n=== Tests Complete ===")


if __name__ == "__main__":
    compiler.compile_func()
