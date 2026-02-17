from Compiler.types import sint, sfix, Matrix, Array, MemValue
from Compiler.library import for_range
from Compiler.mpc_math import log_fx
from typing import Optional, Tuple
import math


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
    def entropy(p: sfix) -> sfix:
        """
        Computes the entropy of a probability: H(p) = -(p * log(p) + (1-p) * log(1-p))

        Args:
            p: Probability value (sfix)

        Returns:
            Entropy value (sfix)
        """
        eps = sfix(1e-12)
        one = sfix(1)

        # Clamp p to [eps, 1-eps] to avoid log(0)
        p_clamped = (p < eps).if_else(eps, (p > (one - eps)).if_else(one - eps, p))

        # Compute log(p) and log(1-p) using natural logarithm
        log_p = log_fx(p_clamped, math.e)
        log_one_minus_p = log_fx(one - p_clamped, math.e)

        # H(p) = -(p * log(p) + (1-p) * log(1-p))
        entropy_val = -(p_clamped * log_p + (one - p_clamped) * log_one_minus_p)
        return entropy_val

    @staticmethod
    def total_entropy(matrix: Matrix, n: int) -> sfix:
        """
        Computes the total entropy of a probability matrix.
        Sum of entropies of all cells: sum_i sum_j H(p_ij)

        Args:
            matrix: Probability matrix of size (n x n) with sfix elements
            n: Dimension of the matrix

        Returns:
            Total entropy (sfix)
        """
        total = sfix(0)

        @for_range(n)
        def _(i):
            @for_range(n)
            def __(j):
                nonlocal total
                cell_entropy = MatSatUtils.entropy(matrix[i][j])
                total.update(total + cell_entropy)

        return total

    @staticmethod
    def information_gain(prior: Matrix, posterior: Matrix, n: int) -> sfix:
        """
        Computes information gain from Bayesian update.
        Information gain = H(prior) - H(posterior)

        Args:
            prior: Prior probability matrix of size (n x n)
            posterior: Posterior probability matrix of size (n x n)
            n: Dimension of the matrix

        Returns:
            Information gain (sfix)
        """
        entropy_before = MatSatUtils.total_entropy(prior, n)
        entropy_after = MatSatUtils.total_entropy(posterior, n)
        info_gain = entropy_before - entropy_after
        return info_gain

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
        variable_weights: Optional[Matrix] = None,
        l: float = 2.0,
        beta: sfix = None,
        max_try: int = 5,
        max_itr: int = 10,
        print_results: bool = False,
        weighted: bool = True,
    ) -> Tuple[Matrix, Matrix, sint, sfix]:
        """
        MatSat solve algorithm.

        Args:
            Q: Matrix of size (m x 2*n) where first n columns are positive literals,
               and next n columns are negative literals.
            n: Number of variables.
            m: Number of clauses/rows.
            active: Optional matrix of size (m x 1) for active clause gating.
                   If None, all clauses are active.
            variable_weights: Optional matrix of size (n x 1). When provided and
                   weighted=True, these values are used as variable weights.
            l: Regularization parameter.
            beta: Perturbation parameter (defaults to sfix(0.5)).
            max_try: Maximum number of tries.
            max_itr: Maximum number of iterations per try.
            print_results: Whether to print results.
            weighted: Whether to run the unweighted/weighted version of MatSat

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

        w_v, w_v_sq, w_c = None, None, None
        # In unweighted mode, we still support clause gating through `active`.
        # If no active mask is provided, treat all clauses as active.
        active_mask = active if active is not None else one_m

        if weighted:
            # Weight vectors for weighted MATSAT
            w_v = MatSatUtils.create_constant_vector(n, 1)  # Variable weights
            w_v_sq = MatSatUtils.create_constant_vector(n, 1)
            w_c = MatSatUtils.create_constant_vector(m, 1)  # Clause weights

            if variable_weights is not None:

                @for_range(n)
                def _(i):
                    val = variable_weights[i][0]
                    w_v[i][0] = val
                    w_v_sq[i][0] = val * val

            else:
                Q_t = Q.transpose()
                col_sums = Q_t.dot(one_m)
                raw_variable_counts = Matrix(n, 1, sfix)
                total_count = sfix(0)

                @for_range(n)
                def _(i):
                    count = col_sums[i][0] + col_sums[i + n][0]
                    raw_variable_counts[i][0] = count
                    total_count.update(total_count + count)

                avg_weight = total_count / n

                # Normalize w_v
                @for_range(n)
                def _(i):
                    val = raw_variable_counts[i][0] / avg_weight
                    w_v[i][0] = val
                    w_v_sq[i][0] = val * val

            # [IMPORTANT] This efectively replaces the old clause active gating
            # logic. If there is an active weight vector as input, then we are
            # solving for weighted MAXSAT.
            if active is not None:
                w_c = active
            else:
                w_v_expanded = Matrix(2 * n, 1, sfix)

                @for_range(n)
                def _(i):
                    val = w_v[i][0]
                    w_v_expanded[i][0] = val
                    w_v_expanded[i + n][0] = val

                w_c = Q.dot(w_v_expanded)

            # End of weighted setup

        # Initialize relaxed assignment u_tilde in [0,1]^n
        u_tilde = Matrix(n, 1, sfix)

        @for_range(n)
        def _(i):
            u_tilde[i][0] = sfix.get_random(0, 1)

        u = Matrix(n, 1, sint)
        err = sfix(0)
        is_solved = sint(0)

        # Track best solution found so far
        best_u = Matrix(n, 1, sint)
        min_err = sfix(m + 1.0)

        # -- Main optimization loop --
        # Outer try loop
        @for_range(max_try)
        def _(try_idx):
            nonlocal is_solved

            # Inner iteration loop
            @for_range(max_itr)
            def __(iter_idx):
                nonlocal is_solved, err, min_err
                err.update(0)

                # Dual vector u_d = [u; 1-u]
                u_tilde_d = Matrix(2 * n, 1, sfix)

                @for_range(n)
                def ___(i):
                    u_tilde_d[i][0] = u_tilde[i][0]
                    u_tilde_d[i + n][0] = sfix(1) - u_tilde[i][0]

                Q_utilde_d = Q.dot(u_tilde_d)  # m x 1

                # Compute satisfaction with optional active gating
                min1_Q_utilde_d = Matrix(m, 1, sfix)

                @for_range(m)
                def ___(i):
                    min1_Q_utilde_d[i][0] = MatSatUtils.min1(Q_utilde_d[i][0])

                # Cost calculation
                if weighted:
                    # Jsat_w = 1_{m \times 1} \dot (w_c \odot (1_{m \times 1} -
                    # \min_1(Q\tilde{u}^d))) + \|w_c \odot \tilde{u} \odot (1_{n
                    # \times 1} - \tilde{u})\|_2^2
                    jsat_first_term = one_m.transpose().dot(
                        w_c.schur(one_m - min1_Q_utilde_d)
                    )
                    jsat_reg_term = (l / 2) * MatSatUtils.vector_norm(
                        w_v.schur(u_tilde.schur(one_n - u_tilde))
                    )

                else:
                    # Jsat = 1_{m \times 1} \dot (1_{m \times 1} - \min_1(Q\tilde{u}^d)))
                    jsat_first_term = one_m.transpose().dot(
                        active_mask.schur(one_m - min1_Q_utilde_d)
                    )
                    jsat_reg_term = (l / 2) * MatSatUtils.vector_norm(
                        u_tilde.schur(one_n - u_tilde)
                    )

                jsat = jsat_first_term[0][0] + jsat_reg_term

                # Jacobian calculation

                # Compute bin_Qud = 1{ Q·u_d < 1 }
                bin_Qud = MatSatUtils.less_than_threshold(Q_utilde_d, sfix(1))

                if weighted:
                    jsatacb_first_term = (Q_diff.transpose()).dot(w_c.schur(bin_Qud))

                    jsatacb_reg_term = l_n.schur(
                        w_v_sq.schur(
                            (
                                (u_tilde.schur(one_n - u_tilde)).schur(
                                    one_n - two_n.schur(u_tilde)
                                )
                            )
                        )
                    )
                else:
                    jsatacb_first_term = Q_diff.transpose().dot(
                        active_mask.schur(bin_Qud)
                    )

                    jsatacb_reg_term = l_n.schur(
                        u_tilde.schur(one_n - u_tilde).schur(
                            one_n - two_n.schur(u_tilde)
                        )
                    )

                jsatacb = jsatacb_first_term + jsatacb_reg_term
                jsatacb_norm = MatSatUtils.vector_norm(jsatacb)

                epsilon = sfix(1e-8)
                alpha = jsat / (jsatacb_norm + epsilon)
                # Keep gradient updates numerically stable in fixed-point.
                alpha_cap = sfix(1)
                alpha = (alpha > alpha_cap).if_else(
                    alpha_cap, (alpha < -alpha_cap).if_else(-alpha_cap, alpha)
                )

                # Gradient step
                new_u_tilde = Matrix(n, 1, sfix)

                @for_range(n)
                def ___(i):

                    updated = u_tilde[i][0] - alpha * jsatacb[i][0]
                    # Project to [0,1] to prevent runaway values and NaN in sfix ops.
                    new_u_tilde[i][0] = (updated < sfix(0)).if_else(
                        sfix(0), (updated > sfix(1)).if_else(sfix(1), updated)
                    )

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

                # Error computation
                @for_range(m)
                def ___(i):
                    nonlocal err
                    min1_val = MatSatUtils.min1(Q_ud[i][0])
                    err.update(err + active_mask[i][0] * (sfix(1) - min1_val))

                zero_err = err == sfix(0)

                # Update best solution if current error is lower than min_err
                update_best = err < min_err
                min_err.update(update_best.if_else(err, min_err))

                @for_range(n)
                def ___(i):
                    best_u[i][0] = update_best.if_else(new_u[i][0], best_u[i][0])

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
                mixed = mask * perturbed + (sfix(1) - mask) * u_tilde[i][0]
                u_tilde[i][0] = (mixed < sfix(0)).if_else(
                    sfix(0), (mixed > sfix(1)).if_else(sfix(1), mixed)
                )

            # Print results if requested (after each try, matching original behavior)
            if print_results:

                @for_range(n)
                def _(i):
                    print_ln("u[%s] = %s", i, u[i][0].reveal())

        # Calculate number of satisfied clauses only after last iteration
        satisfied_clauses = sfix(0)

        # Use the best u found across all iterations
        @for_range(n)
        def _(i):
            u[i][0] = best_u[i][0]

        u_final_d = Matrix(2 * n, 1, sfix)

        @for_range(n)
        def _(i):
            u_final_d[i][0] = u[i][0]
            u_final_d[i + n][0] = sint(1) - u[i][0]

        check_final = Q.dot(u_final_d)

        @for_range(m)
        def _(i):
            is_satisfied = MatSatUtils.min1(check_final[i][0])
            satisfied_clauses.update(
                satisfied_clauses + active_mask[i][0] * is_satisfied
            )

        if print_results:
            print_ln("is_solved = %s", is_solved.reveal())
            print_ln("satisfied clauses = %s", satisfied_clauses.reveal())

        return u_tilde, u, is_solved, satisfied_clauses

    @staticmethod
    def save_posterior(matrix: Matrix, n: int):
        """
        Saves an n×n matrix of sfix to file.

        Args:
            matrix: Matrix of size (n x n) with sfix elements
            n: Dimension of the square matrix

        The matrix is saved row by row (flattened).
        """
        # Flatten matrix to list (row by row)
        matrix_list = []
        for i in range(n):
            for j in range(n):
                matrix_list.append(matrix[i][j])

        # Write to file
        sfix.write_to_file(matrix_list)

    @staticmethod
    def load_prior(
        n: int,
        iteration_no: int,
    ) -> Tuple[Matrix, int]:
        """
        Loads an n×n matrix of sfix from file.

        Args:
            n: Dimension of the square matrix
            iteration_no: index of iterations, if it is the first iteration, it should be 0 and we provide a default prior

        Returns:
            Tuple of (matrix, stop_position) where:
            - matrix: Matrix of size (n x n) with sfix elements
            - stop_position: Final position in file after reading (regint), or 0 for iteration_no == 0
        """

        if iteration_no == 0:
            matrix = Matrix(n, n, sfix)
            matrix.assign_all(sfix(0.5))
            return matrix, 0  # Return consistent tuple format

        # Read n*n elements from file
        # Each save writes n*n elements, so offset is (iteration_no - 1) * n * n
        num_elements = n * n
        start_offset = (iteration_no - 1) * num_elements
        stop_pos, values_list = sfix.read_from_file(
            start=start_offset, n_items=num_elements, crash_if_missing=True
        )

        # Reconstruct matrix from flat list (row by row)
        matrix = Matrix(n, n, sfix)
        for i in range(n):
            for j in range(n):
                matrix[i][j] = values_list[i * n + j]

        return matrix, stop_pos

    @staticmethod
    def update_prior(
        prior: Matrix,
        qx: Array,
        qy: Array,
        n: int,
        path_length: int,
        is_solved: sint,
    ) -> Tuple[Matrix, sfix]:
        """
        Performs Bayesian update on prior probability matrix based on path observation.

        If is_solved == 1 (safe path): sets all visited cells to probability 0.
        If is_solved == 0 (unsafe path): updates probabilities using Bayes' rule:
            p'_k = p_k / P(unsafe)
        where P(unsafe) = 1 - P(all safe) = 1 - product(1 - p_i) for all visited cells.

        Args:
            prior: Prior probability matrix of size (n x n) with sfix elements
            qx: Array of x-coordinates of visited cells, length is path_length
            qy: Array of y-coordinates of visited cells, length is path_length
            n: Dimension of the grid (n x n)
            path_length: Number of cells in the path
            is_solved: sint (1 if path is safe, 0 if unsafe)

        Returns:
            Tuple of (posterior_matrix, information_gain) where:
            - posterior_matrix: Updated probability matrix of size (n x n)
            - information_gain: Information gain from the update (sfix)
        """
        # Small epsilon to avoid division by zero and exact 0/1
        eps = sfix(1e-12)
        one = sfix(1)

        # Collect probabilities of visited cells and compute P(all safe)
        # P(all safe) = product of (1 - p_k) for all UNIQUE visited cells
        # We need to track which cells were visited to avoid double-counting
        p_all_safe = MemValue(sfix(1))

        # For each unique cell, compute (1 - p_k) and multiply into p_all_safe
        @for_range(n)
        def _(r):
            @for_range(n)
            def __(c):
                # Check if this cell was visited at least once
                was_visited = MemValue(sint(0))

                @for_range(path_length)
                def ___(i):
                    matches = (qx[i] == r) * (qy[i] == c)  # sint bit
                    was_visited.write(was_visited.read() + matches)

                # If cell was visited, multiply (1 - p_k) into p_all_safe
                visited_bit = sfix(was_visited.read() > sint(0))
                p_k = prior[r][c]
                # Only multiply if visited: visited_bit * (1 - p_k) + (1 - visited_bit) * 1
                p_all_safe.write(
                    p_all_safe.read()
                    * (visited_bit * (one - p_k) + (one - visited_bit) * one)
                )

        # Compute P(unsafe) = 1 - P(all safe), with epsilon to avoid division by zero
        p_unsafe = one - p_all_safe.read()
        p_unsafe = p_unsafe + eps  # Add epsilon to avoid exact zero

        # Create posterior matrix
        posterior = Matrix(n, n, sfix)
        safe_mask = sfix(is_solved)
        unsafe_mask = sfix(1) - safe_mask

        @for_range(n)
        def _(i):
            @for_range(n)
            def __(j):
                # Check if this cell was visited
                was_visited = MemValue(sint(0))

                @for_range(path_length)
                def ___(k):
                    matches = (qx[k] == i) * (qy[k] == j)
                    was_visited.write(was_visited.read() + matches)

                was_visited_bit = sfix(was_visited.read() > sint(0))

                # Get prior probability
                p_prior = prior[i][j]

                # Update logic:
                # - If safe (is_solved == 1) and visited: set to eps (near 0)
                # - If unsafe (is_solved == 0) and visited: p_post = p_prior / p_unsafe
                # - If not visited: keep prior
                p_post = (
                    was_visited_bit
                    * (
                        safe_mask * eps  # Safe: set to epsilon (near 0)
                        + unsafe_mask * (p_prior / p_unsafe)  # Unsafe: Bayesian update
                    )
                    + (sfix(1) - was_visited_bit) * p_prior  # Not visited: keep prior
                )

                # Clamp to [eps, 1-eps] to avoid exact 0/1
                # Use if_else on comparison results
                p_post_clamped = (p_post < eps).if_else(
                    eps, (p_post > (one - eps)).if_else(one - eps, p_post)
                )

                posterior[i][j] = p_post_clamped

        # Compute information gain
        info_gain = MatSatUtils.information_gain(prior, posterior, n)

        return posterior, info_gain
