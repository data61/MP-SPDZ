from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Array, Matrix
from Compiler.library import print_ln, for_range_opt, for_range, for_range_multithread
from argparse import ArgumentParser
import sys
from typing import Tuple
from matsat_utils import MatSatUtils
from private_path_query_utils import PrivatePathQueryUtils

""" compilation instructions
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/private_path_query.py --num_parties 3 --grid_size 4 --query_size 3
make -j8 shamir-party.x
python3 MP-SPDZ/run-parties.py /Users/joshuamayhugh/Projects/aima-python/path-encodings shamir private_path_query

"""

usage = "usage: %prog [options] [args]"
compiler = Compiler(usage=usage)
compiler.parser.add_option("--num_parties", dest="num_parties", type=int)
compiler.parser.add_option("--grid_size", dest="grid_size", type=int)
compiler.parser.add_option("--query_size", dest="query_size", type=int)
compiler.parser.add_option(
    "--is_graph", dest="is_graph", action="store_true", default=False
)
compiler.parser.add_option("--iteration_no", dest="iteration_no", type=int, default=0)
compiler.parser.add_option("--num_threads", dest="num_threads", type=int, default=4)


@compiler.register_function("private_path_query")
def private_path_query():

    def get_arg_info() -> Tuple[int, int, int]:
        compiler.parse_args()

        if not compiler.options.num_parties:
            print("Error: num_parties argument is required")
            sys.exit(1)
        if not compiler.options.grid_size:
            print("Error: grid_size argument is required")
            sys.exit(1)
        if not compiler.options.query_size:
            print("Error: query_size argument is required")
            sys.exit(1)
        print(
            "Arguments: num_parties={}, grid_size={}, query_size={}, num_threads={}".format(
                compiler.options.num_parties,
                compiler.options.grid_size,
                compiler.options.query_size,
                compiler.options.num_threads,
            )
        )
        return (
            compiler.options.num_parties,
            compiler.options.grid_size,
            compiler.options.query_size,
            compiler.options.num_threads,
            compiler.options.is_graph,
        )

    def build_Q(
        num_parties: int,
        grid_size: int,
        query_size: int,
        num_threads: int,
        qx: Array,
        qy: Array,
        path_length: int,
        is_graph: bool = False,
    ) -> Tuple[Matrix, Matrix, int, int]:
        n = grid_size * grid_size  # number of variables
        lit_len = 2 * n  # positive + negative literals
        m = n + path_length  # N (number of rows) bob-rows + path rows

        Q = Matrix(m, lit_len, sfix)  # MatSat uses sfix arithmetic
        Q.assign_all(0)

        # active mask: 1 => clause counts, 0 => ignore clause (treat as satisfied)
        active = Matrix(m, 1, sfix)
        active.assign_all(0)

        def cell_idx(r, c):
            return r * grid_size + c

        one = sfix(1)

        # --- Bob (assume party 1 is "Bob"; if multiple Bobs, OR them) ---
        # In grid mode: 0 = safe, 1 = dangerous
        # In graph mode: grid represents adjacency matrix where 1 = safe edge, 0 = dangerous/no edge
        # Party IDs 1..num_parties-1
        # We'll build a single "danger" bit per cell as OR across Bobs.
        danger_bits = Array(n, sint)
        danger_bits.assign_all(0)

        for bob in range(1, num_parties):

            @for_range_opt(grid_size)
            def _(r):
                @for_range_opt(grid_size)
                def __(c):
                    idx = cell_idx(r, c)
                    d = sint.get_input_from(bob)
                    if is_graph:
                        # In graph mode: grid represents adjacency matrix where 1 = safe edge, 0 = dangerous/no edge
                        # So we invert: danger = 1 - d (if d=1 safe, danger=0; if d=0 dangerous, danger=1)
                        danger_bits[idx] = (danger_bits[idx] + (sint(1) - d)) > 0
                    else:
                        # In grid mode: 0 = safe, 1 = dangerous
                        danger_bits[idx] = (danger_bits[idx] + d) > 0

        # Now expand into N rows: row = cell index
        @for_range_multithread(
            n_threads=num_threads,
            n_parallel=(grid_size // num_threads) + 1,
            n_loops=grid_size,
        )
        def _(r):
            @for_range(grid_size)
            def __(c):
                cell = cell_idx(r, c)
                row = cell  # rows 0..n-1 reserved for Bob-constraints

                d = danger_bits[cell]  # sint 0/1
                active[row][0] = sfix(d)  # only dangerous cells create active clauses
                # Clause is ¬x_cell, so put coefficient in NEGATIVE half column (n + cell)
                Q[row][n + cell] = sfix(
                    d
                )  # if d=0 this stays 0; gated by active anyway

        # For each step, add an active clause row that one-hots the visited cell in the POSITIVE half
        @for_range_multithread(
            n_threads=num_threads,
            n_parallel=(path_length // num_threads) + 1,
            n_loops=path_length,
        )
        def _(i):
            row = n + i
            active[row][0] = sfix(1)

            @for_range_opt(grid_size)
            def __(r):
                @for_range_opt(grid_size)
                def ___(c):
                    cell = cell_idx(r, c)
                    cond = (qx[i] == r) * (qy[i] == c)  # sint bit
                    Q[row][cell] = sfix(cond)  # positive literal x_cell

        print_ln(Q.reveal())
        return Q, active, n, m

    # -----------------------
    # MatSat solve loop (with active gating)
    # -----------------------
    num_parties, grid_size, query_size, num_threads, is_graph = get_arg_info()

    # Create path first
    qx, qy, path_length = PrivatePathQueryUtils.create_path(query_size, is_graph)

    # Build Q matrix using the path
    Q, active, n, m = build_Q(
        num_parties, grid_size, query_size, num_threads, qx, qy, path_length, is_graph
    )

    # Use MatSat solve from utility class with active gating
    u_tilde, u, is_solved = MatSatUtils.solve_matsat(
        Q=Q,
        n=n,
        m=m,
        active=active,  # Use active gating for private path query
        l=2.0,
        beta=sfix(0.5),
        max_try=5,
        max_itr=10,
        print_results=True,
    )

    # Load prior and update using is_solved
    iteration_no = compiler.options.iteration_no or 0
    prior, _ = MatSatUtils.load_prior(grid_size, iteration_no)

    # Print prior matrix
    print_ln("=== Prior Matrix (iteration_no=%s) ===", iteration_no)

    @for_range(grid_size)
    def _(i):
        @for_range(grid_size)
        def __(j):
            print_ln("prior[%s][%s] = %s", i, j, prior[i][j].reveal())

    posterior, info_gain = MatSatUtils.update_prior(
        prior, qx, qy, grid_size, path_length, is_solved
    )

    # Print posterior matrix and information gain
    print_ln("=== Posterior Matrix ===")

    @for_range(grid_size)
    def _(i):
        @for_range(grid_size)
        def __(j):
            print_ln("posterior[%s][%s] = %s", i, j, posterior[i][j].reveal())

    print_ln("information_gain= %s", info_gain.reveal())
    print_ln("is_solved= %s", is_solved.reveal())

    # Save posterior for next iteration
    MatSatUtils.save_posterior(posterior, grid_size)


if __name__ == "__main__":
    compiler.compile_func()
