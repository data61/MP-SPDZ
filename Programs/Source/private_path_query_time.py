# Programs/Source/private_path_query_time.py
from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Array, Matrix
from Compiler.library import print_ln, for_range_opt, for_range, for_range_multithread
import sys
from typing import Tuple
from matsat_utils import MatSatUtils

"""
Compilation / run (example):
export PYTHONPATH=/path/to/your/repo/MP-SPDZ

Please change into the MP-SPDZ directory before running these commands.

# compile (num_parties includes Alice=0 and Bobs=1..num_parties-1)
python3 ./MP-SPDZ/Programs/Source/private_path_query_time.py \
  --num_parties 3 --grid_size 2 --query_size 2 --num_threads 4

# build VM / protocol binary (example)
make -j8 shamir-party.x

# run parties (typically in 3 terminals)
./shamir-party.x -N 3 -p 0 -I -pn 5001 private_path_query_time
./shamir-party.x -N 3 -p 1 -I -pn 5001 private_path_query_time
./shamir-party.x -N 3 -p 2 -I -pn 5001 private_path_query_time

Input order (IMPORTANT):
- For each Bob party b in {1..num_parties-1}:
  for t in 0..T-1:
    for r in 0..grid_size-1:
      for c in 0..grid_size-1:
        input d_{t,r,c} (0 or 1)

- For Alice party 0:
  input start_x, start_y
  for i in 1..T-1:
    input dx_i, dy_i   (so time i location = time i-1 + (dx,dy))
"""

usage = "usage: %prog [options] [args]"
compiler = Compiler(usage=usage)
compiler.parser.add_option("--num_parties", dest="num_parties", type=int)
compiler.parser.add_option("--grid_size", dest="grid_size", type=int)
compiler.parser.add_option("--query_size", dest="query_size", type=int)
compiler.parser.add_option("--num_threads", dest="num_threads", type=int, default=4)


@compiler.register_function("private_path_query_time")
def private_path_query_time():

    def get_arg_info() -> Tuple[int, int, int, int]:
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
        )

    def build_Q_time(
        num_parties: int, grid_size: int, query_size: int, num_threads: int
    ) -> Tuple[Matrix, Matrix, int, int, int]:
        """
        Time-indexed encoding.

        Variables: x_{cell,t} where cell in [0..n-1], t in [0..T-1]
          N = n*T variables

        Columns (2N):
          [ x_{*,*} | ¬x_{*,*} ]

        Rows (m):
          - hazard rows: one per (cell,t): row = var_idx(cell,t) in [0..N-1]
            clause is ¬x_{cell,t} but only active if d_{cell,t}=1
          - path rows: one per t: row = N + t
            clause selects x_{cell_t,t} (one-hot) and always active
        """
        alice = 0
        T = query_size + 1  # time steps
        n = grid_size * grid_size  # cells
        N = n * T  # time-indexed variables
        lit_len = 2 * N
        m = N + T

        Q = Matrix(m, lit_len, sfix)
        Q.assign_all(0)

        active = Matrix(m, 1, sfix)
        active.assign_all(0)

        def cell_idx(r, c):
            return r * grid_size + c

        def var_idx(cell, t):
            # 0..N-1
            return t * n + cell

        # ------------------------------------------------------------
        # 1) OR danger bits across all Bobs for each (cell,t)
        #    danger[(cell,t)] = OR_bob d_bob(cell,t)
        # ------------------------------------------------------------
        danger = Array(N, sint)
        danger.assign_all(0)

        for bob in range(1, num_parties):

            @for_range_opt(T)
            def _(t):
                @for_range_opt(grid_size)
                def __(r):
                    @for_range_opt(grid_size)
                    def ___(c):
                        cell = cell_idx(r, c)
                        v = var_idx(cell, t)
                        d = sint.get_input_from(bob)  # 0 safe, 1 dangerous at time t
                        # secret OR: danger[v] := (danger[v] OR d)
                        danger[v] = (danger[v] + d) > 0

        # ------------------------------------------------------------
        # 2) Hazard rows: for each (cell,t) add ¬x_{cell,t} if dangerous
        #    row = v in [0..N-1]
        # ------------------------------------------------------------
        @for_range_multithread(
            n_threads=num_threads,
            n_parallel=(T // num_threads) + 1,
            n_loops=T,
        )
        def _(t):
            @for_range(grid_size)
            def __(r):
                @for_range(grid_size)
                def ___(c):
                    cell = cell_idx(r, c)
                    v = var_idx(cell, t)
                    row = v
                    d = danger[v]  # sint bit
                    active[row][0] = sfix(d)
                    # put ¬x_{cell,t} in negative half at column N + v
                    Q[row][N + v] = sfix(d)

        # ------------------------------------------------------------
        # 3) Alice inputs: path location per time (start + deltas)
        # ------------------------------------------------------------
        qx = Array(T, sint)
        qy = Array(T, sint)

        currx = sint.get_input_from(alice)
        curry = sint.get_input_from(alice)
        qx[0] = currx
        qy[0] = curry

        @for_range_opt(1, T)
        def _(i):
            dx = sint.get_input_from(alice)
            dy = sint.get_input_from(alice)
            currx.update(currx + dx)
            curry.update(curry + dy)
            qx[i] = currx
            qy[i] = curry

        # ------------------------------------------------------------
        # 4) Path rows: for each time t, assert x_{cell_t,t}
        #    row = N + t, always active
        # ------------------------------------------------------------
        @for_range_multithread(
            n_threads=num_threads,
            n_parallel=(T // num_threads) + 1,
            n_loops=T,
        )
        def _(t):
            row = N + t
            active[row][0] = sfix(1)

            @for_range_opt(grid_size)
            def __(r):
                @for_range_opt(grid_size)
                def ___(c):
                    cell = cell_idx(r, c)
                    v = var_idx(cell, t)
                    cond = (qx[t] == r) * (qy[t] == c)  # sint bit
                    Q[row][v] = sfix(cond)  # x_{cell,t} in positive half

        return Q, active, n, N, m

    # -----------------------
    # main
    # -----------------------
    num_parties, grid_size, query_size, num_threads = get_arg_info()
    Q, active, n_cells, N_vars, m_rows = build_Q_time(
        num_parties=num_parties,
        grid_size=grid_size,
        query_size=query_size,
        num_threads=num_threads,
    )

    # Solve
    u_tilde, u, is_solved = MatSatUtils.solve_matsat(
        Q=Q,
        n=N_vars,  # IMPORTANT: now n is time-indexed variable count N
        m=m_rows,
        active=active,
        l=2.0,
        beta=sfix(0.5),
        max_try=5,
        max_itr=10,
        print_results=True,
    )

    # Minimal final output
    print_ln("SAT (safe-in-time) = %s", is_solved.reveal())


if __name__ == "__main__":
    compiler.compile_func()
