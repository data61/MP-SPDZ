from pathlib import Path
import os

from Compiler.library import print_ln
from Compiler.types import Matrix, sint, sfix
from Compiler.compilerLib import Compiler

from mpcstats_lib import read_data, print_data, mean


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
        [152, 160, 170, 180],  # column 1
    ],
    # party 1
    [
        [3, 0, 1, 2],  # column 0
        [50, 60, 70, 80],  # column 1
    ],
]
NUM_PARTIES = len(PLAYER_DATA)
NUM_COLUMNS = len(PLAYER_DATA[0])
NUM_ROWS = len(PLAYER_DATA[0][0])


# To enforce round to the nearest integer, instead of probabilistic truncation
# Ref: https://github.com/data61/MP-SPDZ/blob/e93190f3b72ee2d27837ca1ca6614df6b52ceef2/doc/machine-learning.rst?plain=1#L347-L353
sfix.round_nearest = True


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
        all_data = read_data(NUM_PARTIES, NUM_COLUMNS, NUM_ROWS)
        # 0 1 2 3
        # 152 160 170 180
        data_party_0 = all_data[0]
        print_ln("data_party_0:")
        print_data(NUM_COLUMNS, NUM_ROWS, data_party_0)

        # 3 0 1 2
        # 50 60 70 80
        data_party_1 = all_data[1]
        print_ln("data_party_1:")
        print_data(NUM_COLUMNS, NUM_ROWS, data_party_1)

        # Get the column 1
        column_index = 1
        column_1 = [data_party_0[column_index][i] for i in range(NUM_ROWS)]
        # Calculate the mean of column 1
        column_mean = mean(column_1)
        print_ln("column_mean: %s", column_mean.reveal())

    # Compile and run the computation with the given data with all parties in the local machine
    compile_run(computation)
