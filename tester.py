from pathlib import Path
import os, random, shutil, statistics

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

from mpcstats_lib import read_data, geometric_mean

def gen_computation(
    player_data,
    party_id,
    selected_col
):
    def computation():
        data = player_data[party_id]
        mat= read_data(party_id, len(data), len(data[0]))
        col = [mat[selected_col][i] for i in range(mat.shape[1])]

        mpc_res = geometric_mean(col).reveal()

        raw_col = player_data[party_id][selected_col]
        stats_lib_res = statistics.geometric_mean(raw_col) 

        diff = abs(mpc_res - stats_lib_res)

        print_ln('===>%s,%s,%s', mpc_res, stats_lib_res, diff)

    return computation

def compile_and_run(computation, num_ptys, mpc_script, prog):
    # compile computation
    compiler = Compiler()
    compiler.register_function(prog)(computation)
    compiler.compile_func()

    # execute
    cmd = f'PLAYERS={num_ptys} {mpc_script} {prog}'
    r = os.system(cmd)
    if r != 0:
        raise ValueError(f'Executing mpc script failed. Error code: {r}')

def create_player_data_files(data_dir, player_data):
    # creaet an empty data dir
    if os.path.isdir(data_dir):
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)

    # create data files for all parties
    for party_index, player_data in enumerate(player_data):
        file = data_dir / f'Input-P{party_index}-0'
        with open(file, 'w') as f:
            for col in player_data:
                f.write(' '.join(map(str, col)))
                f.write('\n')

def gen_player_data(num_rows, num_cols, num_ptys, num_range_beg, num_range_end):
    res = []
    for _ in range(num_ptys):
        mat = []
        for _ in range(num_cols):
            col = [random.randint(num_range_beg, num_range_end) for _ in range(num_rows)]
            mat.append(col)
        
        res.append(mat)
    return res

root = Path(__file__).parent
mpc_script = root / 'Scripts' / 'semi.sh'

# create player data dir
data_dir = root / "Player-Data"

party_id_g = 0  # use party 1 data
selected_col_g = 1

result_csv = root / 'result.csv'

for _ in range(1):
    num_rows = 10
    num_cols = 2
    num_ptys = 2

    player_data = gen_player_data(
        num_rows,
        num_cols,
        num_ptys,
        1,
        10000
    )
    party_id = 0
    selected_col = 1

    computation = gen_computation(player_data, party_id, selected_col)
    create_player_data_files(data_dir, player_data)
    compile_and_run(computation, num_ptys, mpc_script, 'testmpc')

