from pathlib import Path
repo_root = Path(__file__).parent.parent.parent
mpcstats_dir = repo_root / 'mpcstats'

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')

from Compiler.library import print_ln
from Compiler.compilerLib import Compiler
from Compiler.types import sfix
from mpcstats_lib import MAGIC_NUMBER, read_data
import ast
import glob
import os
import random
import re
import shutil
import statistics
from common_lib import compile_computation, execute_computation

def load_to_matrices(player_data):
    return [read_data(i, len(p), len(p[0])) for i,p in enumerate(player_data)]

def load_column(m, selected_col):
    return [m[selected_col][i] for i in range(m.shape[1])]

def gen_stat_func_comp(
    player_data,
    selected_col,
    func,
    num_params,
):
    if num_params == 1:
        def computation():
            ms = load_to_matrices(player_data)
            col = load_column(ms[0], selected_col)
            res = func(col).reveal()
            print_ln('result: %s', res)
        return computation

    elif num_params == 2:
        def computation():
            ms = load_to_matrices(player_data)
            col1 = load_column(ms[0], selected_col)
            col2 = load_column(ms[1], selected_col)
            res = func(col1, col2).reveal()
            print_ln('result: %s', res)
        return computation

    else:
        raise Exception(f'# of func params is expected to be 1 or 2, but got {num_params}')

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

def gen_magic_num_indices(rows, magic_num_rate):
    num_magic_nums = int(rows * magic_num_rate)
    return random.sample(range(rows), num_magic_nums)

def generate_col(
    rows,
    magic_num_indices,
    range_beg,
    range_end,
):
    # generate column with random numbers
    col = [random.randrange(range_beg, range_end) for _ in range(rows)]

    # replace numbers by magic numbers
    for idx in magic_num_indices:
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
    magic_num_indices = gen_magic_num_indices(rows, magic_num_rate)

    res = []
    for _ in range(num_parties):
        mat = []
        for _ in range(cols):
            col = generate_col(rows, magic_num_indices, range_beg, range_end)
            mat.append(col)
        res.append(mat)

    return res

def gen_player_data_for_1_param_func(
    col,
    num_parties,
    selected_col
):
    m = []
    dummy_col = [0 for _ in range(len(col))]

    for _ in range(num_parties):
        party_data = []
        for col_idx in range(selected_col + 1):
            if col_idx == selected_col:
                party_data.append(col)
            else:
                party_data.append(dummy_col)
        m.append(party_data)
    return m

def exclude_magic_number(col):
    return [x for x in col if x != MAGIC_NUMBER]

def run_pystats_func(
    player_data,
    num_params,
    selected_col,
    func,
): 
    party_ids = list(range(num_params))
    col1 = player_data[party_ids[0]][selected_col]
    print(f'col1: {col1}')
    col1 = exclude_magic_number(col1)
    print(f'col1 excl M: {col1}')

    if num_params == 1:
        return func(col1) 

    elif num_params == 2:
        col2 = player_data[party_ids[1]][selected_col]
        print(f'col2: {col2}')
        col2 = exclude_magic_number(col2)
        print(f'col2 excl M: {col2}')
        return func(col1, col2) 
    else:
        raise Exception(f'# of func params is expected to be 1 or 2, but got {num_params}')

def extract_result_from_mpspdz_stdout(stdout):
    succ_re = r'^result: (.*)$'

    for line in stdout.splitlines():
        succ_m = re.search(succ_re, line)
        if succ_m:
            return succ_m.group(1)

    raise Exception('Result missing in MP-SPDZ output')

def assert_mp_py_diff(mp, py, tolerance):
    mp = float(mp)
    py = float(py)

    if py == 0:
        if mp == 0:
            print(f'mp={mp}, py={py}, diff=0')
        else:
            print(f'mp={mp}, py={py}, diff=?')
            assert False
    else:
        diff = (py - mp) / py
        print(f'mp={mp}, py={py}, diff={diff*100:.5f}%')
        assert abs(diff) < tolerance

def execute_stat_func_test(
    mpcstats_func,
    pystats_func,
    num_params,
    player_data,
    selected_col,
    tolerance,
    vector_res_parser = None, # None or callable 
):
    computation = gen_stat_func_comp(
        player_data,
        selected_col,
        mpcstats_func,
        num_params,
    )

    data_dir = mpcstats_dir / 'Player-Data'
    create_player_data_files(data_dir, player_data)

    protocol = 'semi'
    mpc_script = repo_root / 'Scripts' / f'{protocol}.sh'
    num_parties = len(player_data)
    name = 'test_mpcstats'
    compile_computation(name, computation)
    mpspdz_stdout = execute_computation(
        num_parties,
        mpc_script,
        name,
    )
    print(f'stdout:{mpspdz_stdout}')
    mpspdz_res = extract_result_from_mpspdz_stdout(mpspdz_stdout)

    pystats_res = run_pystats_func(
        player_data,
        num_params,
        selected_col,
        pystats_func,
    )

    if callable(vector_res_parser):
        mpspdz_res = ast.literal_eval(mpspdz_res) 
        pystats_res = vector_res_parser(pystats_res)

        for mp, py in zip(mpspdz_res, pystats_res):
            assert_mp_py_diff(mp, py, tolerance)
    else:
        assert_mp_py_diff(mpspdz_res, pystats_res, tolerance)

def execute_elem_filter_test(
    func,
    elem_filter_gen,
    player_data,
    selected_col,
    exp,
):
    def computation():
        ms = load_to_matrices(player_data)
        col = load_column(ms[0], selected_col)

        elem_filter = elem_filter_gen(col)
        res = func(elem_filter, col).reveal()
        print_ln('result: %s', res)

    data_dir = mpcstats_dir / "Player-Data"
    create_player_data_files(data_dir, player_data)

    protocol = 'semi'
    mpc_script = repo_root / 'Scripts' / f'{protocol}.sh'
    num_parties = len(player_data)
    name = 'test_mpcstats'
    compile_computation(name, computation)
    mpspdz_stdout = execute_computation(
        num_parties,
        mpc_script,
        name,
    )
    mpspdz_res = extract_result_from_mpspdz_stdout(mpspdz_stdout)
    mpspdz_res_val = ast.literal_eval(mpspdz_res) 

    assert mpspdz_res_val == exp

def execute_join_test(
    func,
    player_data,
    p1_key_col,
    p2_key_col,
    exp_m,
):
    data_dir = mpcstats_dir / 'Player-Data'
    create_player_data_files(data_dir, player_data)

    def computation():
        ms = load_to_matrices(player_data)
        res = func(
            ms[0],
            ms[1],
            p1_key_col,
            p2_key_col,
        ).reveal()
        print_ln('result: %s', res)

    protocol = 'semi'
    mpc_script = repo_root / 'Scripts' / f'{protocol}.sh'
    print(f'mpc_script: {mpc_script}')
    num_parties = len(player_data)
    name = 'test_mpcstats'
    compile_computation(name, computation)
    mpspdz_stdout = execute_computation(
        num_parties,
        mpc_script,
        name,
    )
    mpspdz_res = extract_result_from_mpspdz_stdout(mpspdz_stdout)
    mpspdz_res_val = ast.literal_eval(mpspdz_res) 

    print(f'---> {mpspdz_res_val}')
    assert mpspdz_res_val == exp_m

