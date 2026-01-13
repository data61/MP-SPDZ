from Compiler.compilerLib import Compiler
from Compiler.types import sint, sfix, Matrix
from Compiler.library import print_ln, for_range
import argparse
import sys
import os
from matsat_utils import MatSatUtils

compiler = Compiler()


@compiler.register_function("matsat")
def matsat():

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

    # Input Q matrix (m x lit_len)
    Q = Matrix(m, lit_len, sfix)
    row_index = 0
    for i in range(len(row_counts)):
        for _ in range(row_counts[i]):
            for j in range(lit_len):
                Q[row_index][j] = sint.get_input_from(i)
            row_index += 1

    # Use MatSat solve from utility class
    u_tilde, u, is_solved = MatSatUtils.solve_matsat(
        Q=Q,
        n=n,
        m=m,
        active=None,  # No active gating for standard MatSat
        l=2.0,
        beta=sfix(0.5),
        max_try=5,
        max_itr=10,
        print_results=True,
    )


if __name__ == "__main__":
    compiler.compile_func()
