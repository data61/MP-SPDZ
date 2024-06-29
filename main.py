from pathlib import Path
import os

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

from mpcstats_lib import read_data, print_data, mean, join, median, covariance, correlation, where, geometric_mean


MPC_PROTOCOL = "semi"
PROGRAM_NAME = "testmpc"
PROJECT_ROOT = Path(__file__).parent
SCRIPTS_DIR = PROJECT_ROOT / "Scripts"
# E.g. Scripts/semi.sh testmpc
LOCAL_EXECUTION_EXE = SCRIPTS_DIR / f"{MPC_PROTOCOL}.sh"
PLAYER_DATA_DIR = PROJECT_ROOT / "Player-Data"
PLAYER_DATA_DIR.mkdir(parents=True, exist_ok=True)


PLAYER_DATA = [
    # party 0
    [
        [0, 1, 2, 3],  # column 0
        [170, 160, 152, 180],  # column 1
    ],
    # party 1
    [
        [3, 0, 4, 5],
        [50, 60, 70, 100],
    ]
]
NUM_PARTIES = len(PLAYER_DATA)


def compile_run(computation):
    """
    Compile and run the computation.
    """
    compiler = Compiler()
    compiler.register_function(PROGRAM_NAME)(computation)
    compiler.compile_func()
    code = os.system(f"PLAYERS={NUM_PARTIES} {str(LOCAL_EXECUTION_EXE)} {PROGRAM_NAME}")
    if code != 0:
        raise ValueError(f"Failed to compile circom. Error code: {code}")


def prepare_data():
    """
    Save PLAYER_DATA to each party input file.
    """
    for party_index, player_data in enumerate(PLAYER_DATA):
        player_data_file = PLAYER_DATA_DIR / f"Input-P{party_index}-0"
        with open(player_data_file, "w") as f:
            for column in player_data:
                f.write(" ".join(map(str, column)))
                f.write("\n")


if __name__ == "__main__":
    # Save PLAYER_DATA to each party input file
    prepare_data()

    # Computation defined by the user
    def computation():
        # Read all data from all parties
        # 0 1 2 3
        # 170 160 152 180
        data_party_0 = PLAYER_DATA[0]
        matrix_0 = read_data(0, len(data_party_0), len(data_party_0[0]))
        print_ln("data_party_0:")
        print_data(matrix_0)

        # 3 0 1 2
        # 50 60 70 80
        data_party_1 = PLAYER_DATA[1]
        matrix_1 = read_data(1, len(data_party_1), len(data_party_1[0]))
        print_ln("data_party_1:")
        print_data(matrix_1)

        # Get the column 1
        column_index = 1
        column_1 = [matrix_0[column_index][i] for i in range(matrix_0.shape[1])]
        _filter_1 = [ele >160 for ele in column_1]
        column_2 = [matrix_1[column_index][i] for i in range(matrix_1.shape[1])]
        # Calculate the mean of column 1
        column_mean = mean(column_1)
        print_ln("column_mean: %s", column_mean.reveal())

        # Join the two matrices based on the matching index in the specified columns
        # [
        #     [0, 1, 2, 3],
        #     [170, 160, 152, 180],
        #     [0, MAGIC_NUMBER, MAGIC_NUMBER, 3, MAGIC_NUMEBER],
        #     [60, MAGIC_NUMBER, MAGIC_NUMBER, 50, MAGIC_NUMBER],
        # ]
        new_data = join(matrix_0, matrix_1, 0, 0)
        print_ln("new_data:")
        print_data(new_data)
        result = mean([new_data[3][i] for i in range(new_data.shape[1])])

        # Some other tests
        # result = median(column_1)
        # result = where(_filter_1, column_1)
        # result = covariance(column_1, column_2)
        # result = correlation(column_1, column_2)
        # result = geometric_mean(column_1)

        print_ln("result: %s", result.reveal())


    # Compile and run the computation with the given data with all parties in the local machine
    compile_run(computation)
