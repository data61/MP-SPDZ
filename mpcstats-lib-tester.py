import glob, os, random, shutil, statistics
from dataclasses import dataclass
from pathlib import Path

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

from mpcstats_lib import read_data
import mpcstats_lib

def gen_computation(
    player_data,
    tc,
    prefix_tag_beg,
    prefix_tag_end,
):

    def get_col(party_id):
        data = player_data[party_id]
        mat = read_data(party_id, len(data), len(data[0]))
        col = [mat[tc.selected_col][i] for i in range(mat.shape[1])]
        return col

    def computation():
        party_ids = list(range(tc.num_params))
        col1 = get_col(party_ids[0])
        raw_col1 = player_data[party_ids[0]][tc.selected_col]

        if tc.num_params == 1:
            mpc_res = tc.mpcstats_func(col1).reveal()
            python_stats_res = tc.python_stats_func(raw_col1) 
        elif tc.num_params == 2:
            col2 = get_col(party_ids[1])
            raw_col2 = player_data[party_ids[1]][tc.selected_col]

            mpc_res = tc.mpcstats_func(col1, col2).reveal()
            python_stats_res = tc.python_stats_func(raw_col1, raw_col2) 
        else:
            runtime_error(f'# of func params is expected to be 1 or 2, but got {num_func_params}')

        print_ln('%s%s%s%s,%s', prefix_tag_beg, tc.name, prefix_tag_end, mpc_res, python_stats_res)

    return computation

def compile_and_run(computation, num_ptys, mpc_script, prog):
    # compile .x
    compiler = Compiler()
    compiler.register_function(prog)(computation)
    compiler.compile_func()

    # execute .x
    cmd = f'PLAYERS={num_ptys} {mpc_script} {prog}'
    r = os.system(cmd)
    if r != 0:
        raise ValueError(f'Executing mpc failed: {r}')

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

root = Path(__file__).parent
mpc_script = root / 'Scripts' / 'semi.sh'

# create player data dir
data_dir = root / "Player-Data"

@dataclass
class TestCase:
    name: str
    mpcstats_func: any
    python_stats_func: any
    num_params: int
    selected_col: int
    num_range_beg: int
    num_range_end: int

test_cases = [
    TestCase(
        'geometric_mean', 
        mpcstats_lib.geometric_mean,
        statistics.geometric_mean,
        num_params = 1,
        selected_col = 1,
        num_range_beg = 1,
        num_range_end = 10000,
    ),
    TestCase(
        'correlation', 
        mpcstats_lib.correlation,
        statistics.correlation,
        num_params = 2,
        selected_col = 1,
        num_range_beg = 1,
        num_range_end = 100,
    ),
]

num_rows = 10
num_cols = 2
num_parties = 2
num_tests = 1

for _ in range(num_tests):
    for test_case in test_cases:
        player_data = gen_player_data(
            num_rows,
            num_cols,
            num_parties,
            test_case.num_range_beg,
            test_case.num_range_end,
        )

        computation = gen_computation(
            player_data,
            test_case,
            '<<<|',
            '|>>>',
        )
        create_player_data_files(data_dir, player_data)

        compile_and_run(
            computation,
            num_parties,
            mpc_script,
            'testmpc',
        )

