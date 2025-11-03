from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Matrix
from Compiler.library import print_ln, for_range
from Compiler.mpc_math import sqrt
import argparse
import sys
import os

compiler = Compiler()


@compiler.register_function("matsat")
def matsat():

    # Helper functions
    def min1(x):
        one = sfix(1)
        cond = x < one
        return cond * x + (one - cond) * one

    def less_than_threshold(a: Matrix, theta: sfix) -> Matrix:
        m_len = len(a)
        b = Matrix(m_len, 1, sfix)

        @for_range(m_len)
        def _(i):
            b[i][0] = sfix.less_than(a[i][0], theta)

        return b

    def vector_norm(v: Matrix) -> sfix:
        total = sfix(0)

        @for_range(len(v))
        def _(i):
            nonlocal total
            total.update(total + v[i][0] * v[i][0])

        return total

    def create_constant_vector(size, val) -> Matrix:
        """
        Creates a constant vector with `size` entries of value `val`.
        """
        mat = Matrix(size, 1, sfix)

        @for_range(size)
        def _(i):
            mat[i][0] = sfix(val)

        return mat

    def get_dims():
        parser = argparse.ArgumentParser()
        parser.add_argument("-d", "--dir", type=str, required=True)
        args, _ = parser.parse_known_args(sys.argv[1:])
        input_dir = args.dir

        filepaths = sorted(
            [
                os.path.join(input_dir, f)
                for f in os.listdir(input_dir)
                if f.endswith(".qmat")
            ]
        )
        print_ln("INPUT DIR %s", input_dir)
        if not filepaths:
            raise ValueError("No .qmat files found in input_dir")

        expected_cols = None
        row_counts = []
        for idx, path in enumerate(filepaths):
            row_count = 0
            with open(path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    row = list(map(int, line.strip().split()))
                    if expected_cols is None:
                        if len(row) % 2 != 0:
                            raise ValueError(
                                f"{path} line {line_num} has odd number of columns"
                            )
                        expected_cols = len(row)
                    elif len(row) != expected_cols:
                        raise ValueError(
                            f"{path} line {line_num} has"
                            f"{len(row)} columns, expected {expected_cols}"
                        )
                    row_count += 1
            row_counts.append(row_count)

        n = expected_cols // 2
        m = sum(row_counts)
        return n, m, row_counts

    n, m, row_counts = get_dims()
    lit_len = 2 * n
    l = 2.0
    beta = sfix(0.5)
    max_try = 5
    max_itr = 10

    # Input Q matrix (m x lit_len)
    Q = Matrix(m, lit_len, sfix)
    row_index = 0
    for i in range(len(row_counts)):
        for _ in range(row_counts[i]):
            for j in range(lit_len):
                Q[row_index][j] = sint.get_input_from(i)
            row_index += 1

    # @for_range(m)
    # def _(i):
    #    print_ln("%s", Q[i].reveal())
    # Initialize u_tilde with random values
    """u_tilde is the relaxed real assignment vector"""
    u_tilde = Matrix(n, 1, sfix)

    @for_range(n)
    def _(i):
        u_tilde[i][0] = sfix.get_random(0, 1)

    is_solved = sint(0)

    # Constants
    one_n = create_constant_vector(n, 1)
    one_m = create_constant_vector(m, 1)
    two_n = create_constant_vector(n, 2)
    l_n = create_constant_vector(n, l)

    Q1 = Matrix(m, n, sfix)
    Q2 = Matrix(m, n, sfix)

    @for_range(m)
    def ___(i):
        @for_range(n)
        def ____(k):
            Q1[i][k] = Q[i][k]
            Q2[i][k] = Q[i][k + n]

    Q_diff = Q2 - Q1

    """u is the final binary assignment vector"""
    u = Matrix(n, 1, sint)
    err = sfix(-1)

    # Outer try loop
    @for_range(max_try)
    def _(try_idx):
        nonlocal is_solved

        # print_ln("Try ======================")

        # Inner iteration loop

        @for_range(max_itr)
        def __(iter_idx):
            nonlocal is_solved, err

            err.update(0)

            # Initialize dual u vector
            u_tilde_d = Matrix(2 * n, 1, sfix)

            @for_range(n)
            def ___(i):
                u_tilde_d[i][0] = u_tilde[i][0]
                u_tilde_d[i + n][0] = sfix(1) - u_tilde[i][0]

            # print_ln("u_tilde_d")

            # @for_range(2)
            # def _(i):
            #    print_ln("u_tilde[%s] = %s", i, u_tilde_d[i][0].reveal())

            # Q · u^d
            Q_utilde_d = Q.dot(u_tilde_d)

            # Calculate min1(Q · u^d)
            min1_Q_utilde_d = Matrix(m, 1, sfix)

            @for_range(m)
            def ___(i):
                min1_Q_utilde_d[i][0] = min1(Q_utilde_d[i][0])

            # Calculate cost (Jsat)
            jsat_first_term = one_m.dot((one_m - min1_Q_utilde_d).transpose())
            jsat_reg_term = (l / 2) * vector_norm(u_tilde.schur(one_n - u_tilde))
            jsat = jsat_first_term[0][0] + jsat_reg_term

            # Calculate Jacobian of Jsat
            bin_Qud = less_than_threshold(Q_utilde_d, sfix(1))
            jsatacb_first_term = Q_diff.transpose().dot(bin_Qud)
            jsatacb_reg_term = l_n.schur(
                u_tilde.schur(one_n - u_tilde).schur(one_n - two_n.schur(u_tilde))
            )
            jsatacb = jsatacb_first_term + jsatacb_reg_term
            jsatacb_norm = vector_norm(jsatacb)

            epsilon = sfix(1e-8)
            alpha = jsat / (jsatacb_norm + epsilon)
            # alpha = jsat / jsatacb_norm

            # Update u_tilde
            new_u_tilde = Matrix(n, 1, sfix)

            @for_range(n)
            def ___(i):
                new_u_tilde[i][0] = u_tilde[i][0] - alpha * jsatacb[i][0]

            # @for_range(2)
            # def _(i):
            #    print_ln("new_u_tilde[%s] = %s", i, new_u_tilde[i][0].reveal())

            # Threshold to binary vector
            threshold = sfix(0.5)

            # Update u with thresholded version of u_tilde
            new_u = Matrix(n, 1, sint)

            @for_range(n)
            def ___(i):
                new_u[i][0] = sint(1) - (new_u_tilde[i][0] < threshold)

            # Dual binary vector u
            u_d = Matrix(2 * n, 1, sfix)

            @for_range(n)
            def ___(i):
                u_d[i][0] = sfix(new_u[i][0])
                u_d[i + n][0] = sfix(1) - sfix(new_u[i][0])

            # Compute error
            # current_err = sfix(0)
            Q_ud = Q.dot(u_d)
            min1_Q_ud = Matrix(m, 1, sfix)

            @for_range(m)
            def ___(i):
                nonlocal err
                min1_Q_ud[i][0] = min1(Q_ud[i][0])
                err.update(err + sfix(1) - min1_Q_ud[i][0])

            # Update solving status and mask
            zero_err = err == sfix(0)

            # err.update((is_solved * err) +
            #            ((sfix(1) - is_solved) * current_err))
            # print_ln("iter %s, err: %s", iter_idx, err.reveal())

            # Update u_tilde
            @for_range(n)
            def ___(i):
                u_tilde[i][0] = (
                    is_solved * u_tilde[i][0]
                    + (sfix(1) - is_solved) * new_u_tilde[i][0]
                )

            # Update binary u
            @for_range(n)
            def ___(i):
                u[i][0] = is_solved * u[i][0] + (sint(1) - is_solved) * new_u[i][0]

            is_solved.update(is_solved + zero_err - is_solved * zero_err)

        # Mask for perturbation after inner loop
        mask = sfix(1) - sfix(is_solved)

        # Perturbation step
        delta = Matrix(n, 1, sfix)

        @for_range(n)
        def _(i):
            delta[i][0] = sfix.get_random(0, 1)

        @for_range(n)
        def _(i):
            perturbed = (sfix(1) - beta) * u_tilde[i][0] + beta * delta[i][0]
            u_tilde[i][0] = mask * perturbed + (sfix(1) - mask) * u_tilde[i][0]

        # Reveal results
        # print_ln("Thresholded binary vector u:")

        # @for_range(n)
        # def _(i):
        #     print_ln("u[%s] = %s", i, u[i][0].reveal())
    print_ln("is_solved = %s", is_solved.reveal())


if __name__ == "__main__":
    compiler.compile_func()
