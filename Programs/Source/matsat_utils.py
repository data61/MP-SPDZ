from Compiler.types import sint, sfix, Matrix
from Compiler.library import for_range
from typing import Optional, Tuple


class MatSatUtils:
    """Utility class for MatSat operations and helper functions."""

    @staticmethod
    def min1(x: sfix) -> sfix:
        """Returns min(x, 1)."""
        one = sfix(1)
        cond = x < one
        return cond * x + (one - cond) * one

    @staticmethod
    def vector_norm(v: Matrix) -> sfix:
        """Computes the L2 norm of a vector."""
        total = sfix(0)

        @for_range(len(v))
        def _(i):
            nonlocal total
            total.update(total + v[i][0] * v[i][0])

        return total

    @staticmethod
    def create_constant_vector(size: int, val) -> Matrix:
        """Creates a constant vector with `size` entries of value `val`."""
        mat = Matrix(size, 1, sfix)

        @for_range(size)
        def _(i):
            mat[i][0] = sfix(val)

        return mat

    @staticmethod
    def less_than_threshold(a: Matrix, theta: sfix) -> Matrix:
        """Returns a matrix where each element is 1 if a[i] < theta, else 0."""
        m_len = len(a)
        b = Matrix(m_len, 1, sfix)

        @for_range(m_len)
        def _(i):
            b[i][0] = sfix.less_than(a[i][0], theta)

        return b

    @staticmethod
    def compute_Q_diff(Q: Matrix, m: int, n: int) -> Tuple[Matrix, Matrix]:
        """
        Computes Qpos, Qneg, and Q_diff from Q matrix.
        Returns (Qpos, Qneg, Q_diff).
        """
        Qpos = Matrix(m, n, sfix)
        Qneg = Matrix(m, n, sfix)

        @for_range(m)
        def _(i):
            @for_range(n)
            def __(j):
                Qpos[i][j] = Q[i][j]
                Qneg[i][j] = Q[i][j + n]

        Q_diff = Qneg - Qpos
        return Qpos, Qneg, Q_diff

    @staticmethod
    def solve_matsat(
        Q: Matrix,
        n: int,
        m: int,
        active: Optional[Matrix] = None,
        l: float = 2.0,
        beta: sfix = None,
        max_try: int = 5,
        max_itr: int = 10,
        print_results: bool = True,
    ) -> Tuple[Matrix, Matrix, sint]:
        """
        MatSat solve algorithm.

        Args:
            Q: Matrix of size (m x 2*n) where first n columns are positive literals,
               and next n columns are negative literals.
            n: Number of variables.
            m: Number of clauses/rows.
            active: Optional matrix of size (m x 1) for active clause gating.
                   If None, all clauses are active.
            l: Regularization parameter.
            beta: Perturbation parameter (defaults to sfix(0.5)).
            max_try: Maximum number of tries.
            max_itr: Maximum number of iterations per try.
            print_results: Whether to print results.

        Returns:
            Tuple of (u_tilde, u, is_solved) where:
            - u_tilde: Relaxed assignment vector (n x 1)
            - u: Binary assignment vector (n x 1)
            - is_solved: Whether the problem was solved (sint)
        """
        from Compiler.library import print_ln

        if beta is None:
            beta = sfix(0.5)

        # Compute Q_diff
        _, _, Q_diff = MatSatUtils.compute_Q_diff(Q, m, n)

        # Constants
        one_n = MatSatUtils.create_constant_vector(n, 1)
        one_m = MatSatUtils.create_constant_vector(m, 1)
        two_n = MatSatUtils.create_constant_vector(n, 2)
        l_n = MatSatUtils.create_constant_vector(n, l)

        # Initialize relaxed assignment u_tilde in [0,1]^n
        u_tilde = Matrix(n, 1, sfix)

        @for_range(n)
        def _(i):
            u_tilde[i][0] = sfix.get_random(0, 1)

        u = Matrix(n, 1, sint)
        err = sfix(0)
        is_solved = sint(0)

        # Outer try loop
        @for_range(max_try)
        def _(try_idx):
            nonlocal is_solved

            # Inner iteration loop
            @for_range(max_itr)
            def __(iter_idx):
                nonlocal is_solved, err
                err.update(0)

                # Dual vector u_d = [u; 1-u]
                u_tilde_d = Matrix(2 * n, 1, sfix)

                @for_range(n)
                def ___(i):
                    u_tilde_d[i][0] = u_tilde[i][0]
                    u_tilde_d[i + n][0] = sfix(1) - u_tilde[i][0]

                Q_utilde_d = Q.dot(u_tilde_d)  # m x 1

                # Compute satisfaction with optional active gating
                if active is not None:
                    # sat_i = active_i * min1(Q·u_d) + (1-active_i)*1
                    sat = Matrix(m, 1, sfix)

                    @for_range(m)
                    def ___(i):
                        a = active[i][0]
                        sat[i][0] = a * MatSatUtils.min1(Q_utilde_d[i][0]) + (
                            sfix(1) - a
                        ) * sfix(1)

                    # Jsat = sum_i (1 - sat_i) + regularizer
                    jsat_first_term = one_m.dot((one_m - sat).transpose())
                else:
                    # Without active gating: sat_i = min1(Q·u_d)
                    min1_Q_utilde_d = Matrix(m, 1, sfix)

                    @for_range(m)
                    def ___(i):
                        min1_Q_utilde_d[i][0] = MatSatUtils.min1(Q_utilde_d[i][0])

                    # Jsat = sum_i (1 - min1(Q·u_d)) + regularizer
                    jsat_first_term = one_m.dot((one_m - min1_Q_utilde_d).transpose())

                jsat_reg_term = (l / 2) * MatSatUtils.vector_norm(
                    u_tilde.schur(one_n - u_tilde)
                )
                jsat = jsat_first_term[0][0] + jsat_reg_term

                # Compute bin_Qud = 1{ Q·u_d < 1 }
                if active is not None:
                    # Gate by active so inactive rows contribute 0
                    bin_Qud = Matrix(m, 1, sfix)

                    @for_range(m)
                    def ___(i):
                        bin_Qud[i][0] = active[i][0] * (Q_utilde_d[i][0] < sfix(1))

                else:
                    bin_Qud = MatSatUtils.less_than_threshold(Q_utilde_d, sfix(1))

                jsatacb_first_term = Q_diff.transpose().dot(bin_Qud)
                jsatacb_reg_term = l_n.schur(
                    u_tilde.schur(one_n - u_tilde).schur(one_n - two_n.schur(u_tilde))
                )
                jsatacb = jsatacb_first_term + jsatacb_reg_term
                jsatacb_norm = MatSatUtils.vector_norm(jsatacb)

                epsilon = sfix(1e-8)
                alpha = jsat / (jsatacb_norm + epsilon)

                # Gradient step
                new_u_tilde = Matrix(n, 1, sfix)

                @for_range(n)
                def ___(i):
                    new_u_tilde[i][0] = u_tilde[i][0] - alpha * jsatacb[i][0]

                # Threshold
                threshold = sfix(0.5)
                new_u = Matrix(n, 1, sint)

                @for_range(n)
                def ___(i):
                    new_u[i][0] = sint(1) - (new_u_tilde[i][0] < threshold)

                # Compute error using new_u
                u_d = Matrix(2 * n, 1, sfix)

                @for_range(n)
                def ___(i):
                    u_d[i][0] = sfix(new_u[i][0])
                    u_d[i + n][0] = sfix(1) - sfix(new_u[i][0])

                Q_ud = Q.dot(u_d)

                if active is not None:
                    # Gated error computation
                    @for_range(m)
                    def ___(i):
                        a = active[i][0]
                        sat_i = a * MatSatUtils.min1(Q_ud[i][0]) + (sfix(1) - a) * sfix(
                            1
                        )
                        err.update(err + (sfix(1) - sat_i))

                else:
                    # Standard error computation
                    @for_range(m)
                    def ___(i):
                        nonlocal err
                        min1_val = MatSatUtils.min1(Q_ud[i][0])
                        err.update(err + sfix(1) - min1_val)

                zero_err = err == sfix(0)

                # Freeze if solved
                @for_range(n)
                def ___(i):
                    u_tilde[i][0] = (
                        is_solved * u_tilde[i][0]
                        + (sfix(1) - is_solved) * new_u_tilde[i][0]
                    )
                    u[i][0] = is_solved * u[i][0] + (sint(1) - is_solved) * new_u[i][0]

                is_solved.update(is_solved + zero_err - is_solved * zero_err)

            # Perturb if not solved
            mask = sfix(1) - sfix(is_solved)
            delta = Matrix(n, 1, sfix)

            @for_range(n)
            def _(i):
                delta[i][0] = sfix.get_random(0, 1)

            @for_range(n)
            def _(i):
                perturbed = (sfix(1) - beta) * u_tilde[i][0] + beta * delta[i][0]
                u_tilde[i][0] = mask * perturbed + (sfix(1) - mask) * u_tilde[i][0]

            # Print results if requested (after each try, matching original behavior)
            if print_results:

                @for_range(n)
                def _(i):
                    print_ln("u[%s] = %s", i, u[i][0].reveal())

        if print_results:
            print_ln("is_solved = %s", is_solved.reveal())

        return u_tilde, u, is_solved
