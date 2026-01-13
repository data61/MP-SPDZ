from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Array, Matrix
from Compiler.library import print_ln, for_range
from argparse import ArgumentParser
import sys
from typing import Tuple
from matsat_utils import MatSatUtils

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
            "Arguments: num_parties={}, grid_size={}, query_size={}".format(
                compiler.options.num_parties,
                compiler.options.grid_size,
                compiler.options.query_size,
            )
        )
        return (
            compiler.options.num_parties,
            compiler.options.grid_size,
            compiler.options.query_size,
        )

    def build_Q(num_parties: int, grid_size: int, query_size: int):
        alice = 0
        path_length = (
            query_size + 1
        )  # Alice sends initial starting location and then query_size steps

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
        # If you actually have multiple Bobs, we OR their danger bits so a cell is dangerous if any Bob says so.
        # Party IDs 1..num_parties-1
        # We'll build a single "danger" bit per cell as OR across Bobs.
        danger_bits = Array(n, sint)
        danger_bits.assign_all(0)

        for bob in range(1, num_parties):

            @for_range(grid_size)
            def _(r):
                @for_range(grid_size)
                def __(c):
                    idx = cell_idx(r, c)
                    d = sint.get_input_from(bob)  # 0 safe, 1 dangerous
                    danger_bits[idx] = (danger_bits[idx] + d) > 0

        # Now expand into N rows: row = cell index
        @for_range(grid_size)
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

        # --- Alice path rows (positive literals x_cell for visited cells) ---
        qx = Array(path_length, sint)
        qy = Array(path_length, sint)

        currx, curry = sint.get_input_from(alice), sint.get_input_from(alice)
        qx[0] = currx
        qy[0] = curry

        @for_range(1, path_length)
        def _(i):
            dx = sint.get_input_from(alice)
            dy = sint.get_input_from(alice)

            currx.update(currx + dx)
            curry.update(curry + dy)

            qx[i] = currx
            qy[i] = curry

        print_ln("ALice path length is %s", path_length)

        print_ln(
            "Alice path x: %s",
            [(qx[i].reveal(), qy[i].reveal()) for i in range(path_length)],
        )

        # For each step, add an active clause row that one-hots the visited cell in the POSITIVE half
        @for_range(path_length)
        def _(i):
            row = n + i
            active[row][0] = sfix(1)

            @for_range(grid_size)
            def __(r):
                @for_range(grid_size)
                def ___(c):
                    cell = cell_idx(r, c)
                    cond = (qx[i] == r) * (qy[i] == c)  # sint bit
                    Q[row][cell] = sfix(cond)  # positive literal x_cell

        print_ln(Q.reveal())
        return Q, active, n, m

    # -----------------------
    # MatSat solve loop (with active gating)
    # -----------------------
    num_parties, grid_size, query_size = get_arg_info()
    Q, active, n, m = build_Q(num_parties, grid_size, query_size)

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


if __name__ == "__main__":
    compiler.compile_func()
