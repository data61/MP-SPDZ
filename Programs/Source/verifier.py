from Compiler.compilerLib import Compiler
import sys
from Compiler.types import Matrix, Array, sint, MemValue
from Compiler.library import for_range, print_ln
from typing import Tuple
from private_path_query_utils import PrivatePathQueryUtils

""" compilation instructions
export PYTHONPATH=/Users/joshuamayhugh/Projects/aima-python/MP-SPDZ
python3 /Users/joshuamayhugh/Projects/aima-python/MP-SPDZ/Programs/Source/verifier.py --num_parties 3 --grid_size 4 --query_size 3
make -j8 shamir-party.x

# run parties (typically in 3 terminals)
./shamir-party.x -N 3 -p 0 -I -pn 5001 verifier
./shamir-party.x -N 3 -p 1 -I -pn 5001 verifier
./shamir-party.x -N 3 -p 2 -I -pn 5001 verifier

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


@compiler.register_function("verifier")
def verifier():
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
        return (
            compiler.options.num_parties,
            compiler.options.grid_size,
            compiler.options.query_size,
        )

    num_parties, grid_size, query_size = get_arg_info()

    def get_path_from_bob(hazard_matrix: Matrix, bob_id: int) -> None:
        """gets all the locations from bob and Ors over them inserting into the matrix"""
        assert (
            bob_id >= 1 and bob_id < num_parties
        ), "Bob ID must be between 1 and num_parties-1"
        for i in range(grid_size):
            for j in range(grid_size):
                d = sint.get_input_from(bob_id)
                hazard_matrix[i][j] = (hazard_matrix[i][j] + d) > 0

    path_length = query_size + 1
    qx, qy, _ = PrivatePathQueryUtils.create_path(query_size)

    hazard_matrix = Matrix(grid_size, grid_size, sint)
    hazard_matrix.assign_all(0)
    result_array = Array(path_length, sint)
    result_array.assign_all(0)

    for bob in range(1, num_parties):
        get_path_from_bob(hazard_matrix, bob)

    # We are going to loop through every element in qx, qy and every element in the grid and if
    for i in range(path_length):
        for j in range(grid_size):
            for k in range(grid_size):
                # we will create a confition
                condition = (qx[i] == j) * (qy[i] == k) * hazard_matrix[j][k]
                result_array[i] = result_array[i] + condition

    # return the sum of result array is greater than 0
    total = MemValue(sint(0))

    @for_range(path_length)
    def _(i):
        total.write(total.read() + result_array[i])

    hits = total.read().reveal()
    print_ln("Path is safe: %s", hits == 0)
    print_ln("Hazards on path (count of matches): %s", hits)


if __name__ == "__main__":
    compiler.compile_func()
