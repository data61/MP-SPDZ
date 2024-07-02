import os, sys

# add parent dir to Python path
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.append(parent_dir)

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler

from mpcstats_lib import MAGIC_NUMBER, read_data
from pathlib import Path
import ast, glob, random, re, shutil, statistics, subprocess

def get_col(player_data, party_id, selected_col):
    data = player_data[party_id]
    mat = read_data(party_id, len(data), len(data[0]))
    col = [mat[selected_col][i] for i in range(mat.shape[1])]
    return col

def gen_stat_func_comp(
    player_data,
    selected_col,
    func,
    num_params,
):
    def get_col_wrap(party_id):
        return get_col(player_data, party_id, selected_col)

    if num_params == 1:
        def computation():
            party_ids = list(range(num_params))
            col = get_col_wrap(party_ids[0])
            res = func(col).reveal()
            print_ln('result: %s', res)
        return computation

    elif num_params == 2:
        def computation():
            party_ids = list(range(num_params))
            col1 = get_col_wrap(party_ids[0])
            col2 = get_col_wrap(party_ids[1])
            res = func(col1, col2).reveal()
            print_ln('result: %s', res)
        return computation

    else:
        raise Exception(f'# of func params is expected to be 1 or 2, but got {num_params}')

def gen_elem_filter_comp(
    player_data,
    selected_col,
    func,
    elem_filter_gen,
):
    def computation():
        party_ids = [0]
        col = get_col(player_data, party_ids[0], selected_col)

        elem_filter = elem_filter_gen(col)
        res = func(elem_filter, col).reveal()
        print_ln('result: %s', res)

    return computation

def run_mpcstats_func(
    computation,
    num_parties,
    mpc_script,
    prog,
):
    # compile .x
    compiler = Compiler()
    compiler.register_function(prog)(computation)
    compiler.compile_func()

    # execute .x
    cmd = f'PLAYERS={num_parties} {mpc_script} {prog}'

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return (res.stdout, res.returncode)

    except subprocess.CalledProcessError as e:
        raise Exception(f'Executing MPC failed ({e.returncode}): stdout: {e.stdout}, stderr: {e.stderr}')

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

def generate_col(
    rows,
    magic_num_rate,
    range_beg,
    range_end,
):
    # generate column with random numbers
    col = [random.randrange(range_beg, range_end) for _ in range(rows)]

    # replace numbers with magic numbers at a given rate
    num_magic_nums = int(rows * magic_num_rate)
    magic_num_idxs = random.sample(range(rows), num_magic_nums)
    for idx in magic_num_idxs:
        col[idx] = MAGIC_NUMBER

    return col

def gen_player_data(
    rows,
    cols,
    num_parties,
    range_beg,
    range_end,
    magic_num_rate,
):
    res = []
    for _ in range(num_parties):
        mat = []
        for _ in range(cols):
            col = generate_col(rows, magic_num_rate, range_beg, range_end)
            mat.append(col)
        res.append(mat)

    return res

def run_pystats_func(
    player_data,
    num_params,
    selected_col,
    func,
): 
    party_ids = list(range(num_params))
    col1 = player_data[party_ids[0]][selected_col]

    if num_params == 1:
        return func(col1) 

    elif num_params == 2:
        col2 = player_data[party_ids[1]][selected_col]

        return func(col1, col2) 
    else:
        raise Exception(f'# of func params is expected to be 1 or 2, but got {num_params}')

def extract_result_from_mpspdz_out(out):
    stdout, _ = out
    succ_re = r'^result: (.*)$'
    fail_re = r'^User exception: (.*)$'

    for line in stdout.splitlines():
        succ_m = re.search(succ_re, line)
        if succ_m:
            return (True, succ_m.group(1))

        fail_m = re.search(fail_re, line)
        if fail_m:
            return (False, fail_m.group(1))
            
    raise Exception('Result missing in MP-SPDZ output')

def execute_stat_func_test(
    mpcstats_func,
    pystats_func,
    num_params,
    player_data,
    selected_col,
    tolerance,
):
    computation = gen_stat_func_comp(
        player_data,
        selected_col,
        mpcstats_func,
        num_params,
    )

    root = Path(__file__).parent.parent

    data_dir = root / "Player-Data"
    create_player_data_files(data_dir, player_data)

    protocol = 'semi'
    mpc_script = root / 'Scripts' / f'{protocol}.sh'
    num_parties = len(player_data)
    mpspdz_out = run_mpcstats_func(
        computation,
        num_parties,
        mpc_script,
        'testmpc',
    )
    mpspdz_res = extract_result_from_mpspdz_out(mpspdz_out)

    assert mpspdz_res[0] is True

    pystats_res = run_pystats_func(
        player_data,
        num_params,
        selected_col,
        pystats_func,
    )
    assert abs(float(mpspdz_res[1]) - pystats_res) < tolerance

def execute_elem_filter_test(
    func,
    elem_filter_gen,
    player_data,
    selected_col,
    exp,
):
    computation = gen_elem_filter_comp(
        player_data,
        selected_col,
        func,
        elem_filter_gen,
    )

    root = Path(__file__).parent.parent

    data_dir = root / "Player-Data"
    create_player_data_files(data_dir, player_data)

    protocol = 'semi'
    mpc_script = root / 'Scripts' / f'{protocol}.sh'
    num_parties = len(player_data)
    mpspdz_out = run_mpcstats_func(
        computation,
        num_parties,
        mpc_script,
        'testmpc',
    )
    mpspdz_res = extract_result_from_mpspdz_out(mpspdz_out)
    mpspdz_res_val = ast.literal_eval(mpspdz_res[1]) 

    assert mpspdz_res[0] is True
    assert mpspdz_res_val == exp

def run_func_many_times_with_random_data(
    mpcstats_func,
    pystats_func,
    num_interation,
    gen_player_data,
):
    raise NotImplementedError(__name__)

