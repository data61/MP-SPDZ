from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Array, Matrix
from Compiler.library import print_ln, for_range
from argparse import ArgumentParser
import sys
from typing import Tuple

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
    # -----------------------
    # Helper functions (MatSat-style)
    # -----------------------
    def min1(x: sfix) -> sfix:
        one = sfix(1)
        cond = x < one
        return cond * x + (one - cond) * one

    def vector_norm(v: Matrix) -> sfix:
        total = sfix(0)

        @for_range(len(v))
        def _(i):
            nonlocal total
            total.update(total + v[i][0] * v[i][0])

        return total

    def create_constant_vector(size: int, val) -> Matrix:
        mat = Matrix(size, 1, sfix)

        @for_range(size)
        def _(i):
            mat[i][0] = sfix(val)

        return mat

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

        print_ln("Alice path x: %s", [(qx[i].reveal(), qy[i].reveal()) for i in range(path_length)])

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
    # MatSat-like solve loop (with active gating)
    # -----------------------
    num_parties, grid_size, query_size = get_arg_info()
    Q, active, n, m = build_Q(num_parties, grid_size, query_size)

    # Derive Qpos/Qneg difference the way MatSat expects: Qneg_part - Qpos_part
    Qpos = Matrix(m, n, sfix)
    Qneg = Matrix(m, n, sfix)

    @for_range(m)
    def _(i):
        @for_range(n)
        def __(j):
            Qpos[i][j] = Q[i][j]
            Qneg[i][j] = Q[i][j + n]

    Q_diff = Qneg - Qpos

    l = 2.0
    beta = sfix(0.5)
    max_try = 5
    max_itr = 10

    one_n = create_constant_vector(n, 1)
    one_m = create_constant_vector(m, 1)
    two_n = create_constant_vector(n, 2)
    l_n = create_constant_vector(n, l)

    # relaxed assignment u_tilde in [0,1]^n
    u_tilde = Matrix(n, 1, sfix)

    @for_range(n)
    def _(i):
        u_tilde[i][0] = sfix.get_random(0, 1)

    u = Matrix(n, 1, sint)
    err = sfix(0)
    is_solved = sint(0)

    @for_range(max_try)
    def _(try_idx):
        nonlocal is_solved

        @for_range(max_itr)
        def __(iter_idx):
            nonlocal is_solved, err
            err.update(0)

            # dual vector u_d = [u; 1-u]
            u_tilde_d = Matrix(2 * n, 1, sfix)

            @for_range(n)
            def ___(i):
                u_tilde_d[i][0] = u_tilde[i][0]
                u_tilde_d[i + n][0] = sfix(1) - u_tilde[i][0]

            Q_utilde_d = Q.dot(u_tilde_d)  # m x 1

            # sat_i = active_i * min1(Q·u_d) + (1-active_i)*1
            sat = Matrix(m, 1, sfix)

            @for_range(m)
            def ___(i):
                a = active[i][0]
                sat[i][0] = a * min1(Q_utilde_d[i][0]) + (sfix(1) - a) * sfix(1)

            # Jsat = sum_i (1 - sat_i) + regularizer
            jsat_first_term = one_m.dot((one_m - sat).transpose())
            jsat_reg_term = (l / 2) * vector_norm(u_tilde.schur(one_n - u_tilde))
            jsat = jsat_first_term[0][0] + jsat_reg_term

            # bin_Qud = 1{ Q·u_d < 1 }  (gate by active so inactive rows contribute 0)
            bin_Qud = Matrix(m, 1, sfix)

            @for_range(m)
            def ___(i):
                bin_Qud[i][0] = active[i][0] * (Q_utilde_d[i][0] < sfix(1))

            jsatacb_first_term = Q_diff.transpose().dot(bin_Qud)
            jsatacb_reg_term = l_n.schur(
                u_tilde.schur(one_n - u_tilde).schur(one_n - two_n.schur(u_tilde))
            )
            jsatacb = jsatacb_first_term + jsatacb_reg_term
            jsatacb_norm = vector_norm(jsatacb)

            epsilon = sfix(1e-8)
            alpha = jsat / (jsatacb_norm + epsilon)

            # gradient step
            new_u_tilde = Matrix(n, 1, sfix)

            @for_range(n)
            def ___(i):
                new_u_tilde[i][0] = u_tilde[i][0] - alpha * jsatacb[i][0]

            # threshold
            threshold = sfix(0.5)
            new_u = Matrix(n, 1, sint)

            @for_range(n)
            def ___(i):
                new_u[i][0] = sint(1) - (new_u_tilde[i][0] < threshold)

            # compute gated error using new_u
            u_d = Matrix(2 * n, 1, sfix)

            @for_range(n)
            def ___(i):
                u_d[i][0] = sfix(new_u[i][0])
                u_d[i + n][0] = sfix(1) - sfix(new_u[i][0])

            Q_ud = Q.dot(u_d)

            @for_range(m)
            def ___(i):
                a = active[i][0]
                sat_i = a * min1(Q_ud[i][0]) + (sfix(1) - a) * sfix(1)
                err.update(err + (sfix(1) - sat_i))

            zero_err = err == sfix(0)

            # freeze if solved
            @for_range(n)
            def ___(i):
                u_tilde[i][0] = (
                    is_solved * u_tilde[i][0]
                    + (sfix(1) - is_solved) * new_u_tilde[i][0]
                )
                u[i][0] = is_solved * u[i][0] + (sint(1) - is_solved) * new_u[i][0]

            is_solved.update(is_solved + zero_err - is_solved * zero_err)

        # perturb if not solved
        mask = sfix(1) - sfix(is_solved)
        delta = Matrix(n, 1, sfix)

        @for_range(n)
        def _(i):
            delta[i][0] = sfix.get_random(0, 1)

        @for_range(n)
        def _(i):
            perturbed = (sfix(1) - beta) * u_tilde[i][0] + beta * delta[i][0]
            u_tilde[i][0] = mask * perturbed + (sfix(1) - mask) * u_tilde[i][0]

    # Outputs
    print_ln("is_solved = %s", is_solved.reveal())


if __name__ == "__main__":
    compiler.compile_func()
