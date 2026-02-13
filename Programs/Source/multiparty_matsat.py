from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Matrix
from Compiler.library import print_ln
import sys
from matsat_utils import MatSatUtils

"""Compilation and run instructions (stdin-based inputs).

Compile from project root:
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ

# Uniform rows per party (example: 3 parties, n=4 vars, 2 rows each)
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/multiparty_matsat.py \
  --num_parties 3 --num_vars 4 --rows_per_party 2

# Per-party row counts (example: party0=2 rows, party1=3 rows, party2=1 row)
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/multiparty_matsat.py \
  --num_parties 3 --num_vars 1 --row_counts 1,1,1

# Optional weighted run with explicit variable-weight vector from party 0.
# Party 0 must append `num_vars` weight values to its stdin payload.
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/multiparty_matsat.py \
  --num_parties 3 --num_vars 2 --row_counts 1,1,1 --use_weight_vector

make -j8 shamir-party.x

Run (each party reads its own stdin payload):
./shamir-party.x -N 3 -I -p 0 -pn 5001 matsat < /path/to/party0.input
./shamir-party.x -N 3 -I -p 1 -pn 5001 matsat < /path/to/party1.input
./shamir-party.x -N 3 -I -p 2 -pn 5001 matsat < /path/to/party2.input

Input format details:
- All parties: provide their Q rows, each row has 2*num_vars integers.
- Party 0 only (when --use_weight_vector): after Q rows, provide num_vars
  additional sfix values for variable weights.
"""

compiler = Compiler()
compiler.parser.add_option("--num_parties", dest="num_parties", type=int)
compiler.parser.add_option("--num_vars", dest="num_vars", type=int)
compiler.parser.add_option("--rows_per_party", dest="rows_per_party", type=int)
compiler.parser.add_option("--row_counts", dest="row_counts", type=str, default="")
compiler.parser.add_option(
    "--use_weight_vector", dest="use_weight_vector", action="store_true", default=False
)


@compiler.register_function("matsat")
def matsat():
    compiler.parse_args()

    if not compiler.options.num_parties:
        print("Error: --num_parties is required")
        sys.exit(1)
    if not compiler.options.num_vars:
        print("Error: --num_vars is required")
        sys.exit(1)

    num_parties = compiler.options.num_parties
    n = compiler.options.num_vars

    if compiler.options.row_counts:
        row_counts = [int(x.strip()) for x in compiler.options.row_counts.split(",")]
        if len(row_counts) != num_parties:
            print("Error: --row_counts length must match --num_parties")
            sys.exit(1)
        if any(r < 0 for r in row_counts):
            print("Error: --row_counts must contain non-negative integers")
            sys.exit(1)
    elif compiler.options.rows_per_party is not None:
        if compiler.options.rows_per_party < 0:
            print("Error: --rows_per_party must be non-negative")
            sys.exit(1)
        row_counts = [compiler.options.rows_per_party for _ in range(num_parties)]
    else:
        print("Error: provide either --rows_per_party or --row_counts")
        sys.exit(1)

    m = sum(row_counts)
    print_ln(
        "Args: num_parties=%s num_vars=%s total_rows=%s",
        num_parties,
        n,
        m,
    )
    lit_len = 2 * n

    # Input Q matrix (m x lit_len)
    Q = Matrix(m, lit_len, sfix)
    row_index = 0
    for i in range(num_parties):
        for _ in range(row_counts[i]):
            for j in range(lit_len):
                Q[row_index][j] = sint.get_input_from(i)
            row_index += 1

    variable_weights = None
    if compiler.options.use_weight_vector:
        variable_weights = Matrix(n, 1, sfix)
        for i in range(n):
            variable_weights[i][0] = sfix.get_input_from(0)

    # Use MatSat solve from utility class
    u_tilde, u, is_solved, satisfied_clauses = MatSatUtils.solve_matsat(
        Q=Q,
        n=n,
        m=m,
        active=None,  # No active gating for standard MatSat
        variable_weights=variable_weights,
        l=2.0,
        beta=sfix(0.5),
        max_try=5,
        max_itr=10,
        print_results=True,
        weighted=True,
    )


if __name__ == "__main__":
    compiler.compile_func()
