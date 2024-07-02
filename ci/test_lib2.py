import glob, os, random, shutil, statistics
from dataclasses import dataclass
from pathlib import Path

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

from mpcstats_lib import read_data
import mpcstats_lib

from enum import Enum
from typing import NamedTuple
import subprocess

class Exp(Enum):
    Success = 1
    Failure = 2

def gen_computation(
    player_data_id,
    player_data,
    tc,
):
    def get_col(party_id):
        data = player_data[party_id]
        mat = read_data(party_id, len(data), len(data[0]))
        col = [mat[tc.selected_col][i] for i in range(mat.shape[1])]
        return col

    def computation():
        party_ids = list(range(tc.num_params))
        col1 = get_col(party_ids[0])

        if tc.num_params == 1:
            res = tc.mpcstats_func(col1).reveal()

        elif tc.num_params == 2:
            col2 = get_col(party_ids[1])
            res = tc.mpcstats_func(col1, col2).reveal()
        else:
            runtime_error(f'# of func params is expected to be 1 or 2, but got {num_func_params}')

        print_ln('result: %s', res)

    return computation

def compile_and_run(computation, num_parties, mpc_script, prog):
    # compile .x
    compiler = Compiler()
    compiler.register_function(prog)(computation)
    compiler.compile_func()

    # execute .x
    cmd = f'PLAYERS={num_parties} {mpc_script} {prog}'

    try:
        res = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

        return (True, (res.stdout, res.stderr))

    except subprocess.CalledProcessError as e:
        return (False, None)

def create_player_data_files(data_dir, player_data):
    # prepare an empty data dir
    data_dir.mkdir(parents=True, exist_ok=True)

    for file in glob.glob(os.path.join(data_dir, '*')):
        if os.path.isfile(file):
            os.remove(file)

    # create data files for all parties
    for party_index, player_data in enumerate(player_data):
        file = data_dir / f'Input-P{party_index}-0'
        with open(file, 'w') as f:
            for col in player_data:
                f.write(' '.join(map(str, col)))
                f.write('\n')

def gen_player_data(
    num_rows,
    num_cols,
    num_parties,
    num_range_beg,
    num_range_end,
):
    res = []
    for _ in range(num_parties):
        mat = []
        for _ in range(num_cols):
            col = [random.randrange(num_range_beg, num_range_end) for _ in range(num_rows)]
            mat.append(col)
        
        res.append(mat)
    return res

def run_python_stats_func(
    player_data_id,
    player_data,
    tc,
    prefix_tag_beg,
    prefix_tag_end,
): 
    party_ids = list(range(tc.num_params))
    col1 = player_data[party_ids[0]][tc.selected_col]

    if tc.num_params == 1:
        res = tc.python_stats_func(col1) 

    elif tc.num_params == 2:
        col2 = player_data[party_ids[1]][tc.selected_col]

        res = tc.python_stats_func(col1, col2) 
    else:
        runtime_error(f'# of func params is expected to be 1 or 2, but got {num_func_params}')

    print(f'{prefix_tag_beg}{player_data_id}:p:{tc.name}{prefix_tag_end}{res}')

root = Path(__file__).parent
mpc_script = root / 'Scripts' / 'semi.sh'

# create player data dir
data_dir = root / "Player-Data"

num_rows = 10
num_cols = 2
num_parties = 2
num_iterations = 1

computation = gen_computation(
    player_data_id,
    player_data,
    test_case,
)

create_player_data_files(data_dir, player_data)

compile_and_run(
    computation,
    num_parties,
    mpc_script,
    'testmpc',
)

def test_function(
    mpcstats_func,
    python_stats_func,
    player_data,
    exp
):
    res = exec_computation(player_data)

    if exp[0] == Exp.Success:
        pass
    elif exp[1] == Exp.Failure:
        pass


