from pathlib import Path
repo_root = Path(__file__).parent.parent.parent

import sys
sys.path.append(f'{repo_root}/mpcstats')

import pytest, statistics

import mpcstats_lib
from .lib import execute_elem_filter_test, execute_join_test, execute_stat_func_test, gen_player_data_for_1_param_func, gen_player_data
from common_lib import execute_computation
import subprocess

player_data_4x2_2_party = [
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

M = mpcstats_lib.MAGIC_NUMBER

TOLERANCE_SMALL = 0.0001  # 0.01%

@pytest.fixture(scope='module')
def build_vm():
  semi_party_x = repo_root / 'semi-party.x'
  if not semi_party_x.exists():
    subprocess.run(['make', 'semi-party.x'], check=True, cwd=repo_root)

def pd1(col):
    return gen_player_data_for_1_param_func(col, 2, 1)

def test_correlation_success(build_vm):
    execute_stat_func_test(
        mpcstats_lib.correlation,
        statistics.correlation,
        num_params = 2,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = 0.02,
    )

def test_covariance_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.covariance,
        statistics.covariance,
        num_params = 2,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_geometric_mean_success(build_vm):
    execute_stat_func_test(
        mpcstats_lib.geometric_mean,
        statistics.geometric_mean,
        num_params = 1,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_median_success(build_vm):
    execute_stat_func_test(
        mpcstats_lib.median,
        statistics.median,
        num_params = 1,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_where_success(build_vm):
    player_data = [
        [
            [-123, 0, 20, 40],
            [0, 0, 0, 0],
        ],
        [
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ],
    ]
    def test(elem_filter_gen, exp):
        execute_elem_filter_test(
            func = mpcstats_lib.where,
            elem_filter_gen = elem_filter_gen,
            player_data = player_data,
            selected_col = 0,
            exp = exp,
        )

    test(
        lambda col: [n < -123 for n in col],
        [M, M, M, M],
    )
    test(
        lambda col: [n < 0 for n in col],
        [-123, M, M, M],
    )
    test(
        lambda col: [n == 0 for n in col],
        [M, 0, M, M],
    )
    test(
        lambda col: [n >= 20 for n in col],
        [M, M, 20, 40],
    )
    test(
        lambda col: [n >= 40 for n in col],
        [M, M, M, 40],
    )
    test(
        lambda col: [n > 40 for n in col],
        [M, M, M, M],
    )

def test_join_success(build_vm):
    # 1. 0 and 3 of col 0 mat 1 match 3 and 0 in col 0 mat 2
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
                [152, 160, 170, 180],
            ],
            [
                [3, 0, 4],
                [50, 60, 70],
            ],
        ],
        0,
        0,
        [
            [0, 1, 2, 3],
            [152, 160, 170, 180],
            [0, M, M, 3],
            [60, M, M, 50],
        ],
    )

    # 2. the same as 1 except that mat 2 has 3 columns
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
                [152, 160, 170, 180],
            ],
            [
                [3, 0, 4],
                [50, 60, 70],
                [12, 34, 56],
            ],
        ],
        0,
        0,
        [
            [0, 1, 2, 3],
            [152, 160, 170, 180],
            [0, M, M, 3],
            [60, M, M, 50],
            [34, M, M, 12],
        ],
    )

    # 3. col 0 mat 1 and col 1 mat 2 have no elems in common
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
                [152, 160, 170, 180],
            ],
            [
                [3, 0, 4],
                [50, 60, 70],
            ],
        ],
        0,
        1,
        [
            [0, 1, 2, 3],
            [152, 160, 170, 180],
            [M, M, M, M],
            [M, M, M, M],
        ],
    )

    # 4. Every element in col 0 mat 1 has a match in col 0 mat 2
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
                [152, 160, 170, 180],
            ],
            [
                [3, 1, 0, 2],
                [50, 60, 70, 80],
            ],
        ],
        0,
        0,
        [
            [0, 1, 2, 3],
            [152, 160, 170, 180],
            [0, 1, 2, 3],
            [70, 60, 80, 50],
        ],
    )

    # 5. mat 2 has 1 column only
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
                [152, 160, 170, 180],
            ],
            [
                [9, 11, 0, 2],
            ],
        ],
        0,
        0,
        [
            [0, 1, 2, 3],
            [152, 160, 170, 180],
            [0, M, 2, M],
        ],
    )

    # 6. mat 1 has 1 column only
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1, 2, 3],
            ],
            [
                [3, 0, 1],
                [50, 60, 70],
            ],
        ],
        0,
        0,
        [
            [0, 1, 2, 3],
            [0, 1, M, 3],
            [60, 70, M, 50],
        ],
    )

    # 7. mat 2 has more rows than mat 1
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1],
                [10, 20],
            ],
            [
                [3, 1, 9],
                [50, 60, 70],
            ],
        ],
        0,
        0,
        [
            [0, 1],
            [10, 20],
            [M, 1],
            [M, 60],
        ],
    )

    # 8. mat 2 has multiple matches for a mat 1 key
    execute_join_test(
        mpcstats_lib.join,
        [
            [
                [0, 1],
                [10, 20],
            ],
            [
                [3, 1, 9, 1],
                [50, 60, 70, 80],
            ],
        ],
        0,
        0,
        [
            [0, 1],
            [10, 20],
            [M, 1],
            [M, 80],
        ],
    )

def test_mode_success(build_vm):
    test_cases = [
        pd1([11, 99, 100, M]),
        pd1([11, 100, 100, M]),
        pd1([M, 100, 100, 9]),
        pd1([M, 11, 100, 5]),
        pd1([M, 11, 100, M]),
        pd1([1]),
        pd1([1, 2]),
        pd1([1, 2, 2]),
        pd1([1, 1, 2]),
        pd1([1, 1, 2, 2]),
        pd1([1, 3, 3, 2, 2, 5]),
        pd1([1, 2, 2, 3, 3, 5]),
        pd1([1, 2, 3, 4, 5, 6]),
        pd1([6, 5, 4, 3, 2, 1]),
    ]

    for tc in test_cases:
        execute_stat_func_test(
            mpcstats_lib.mode,
            statistics.mode,
            num_params = 1,
            player_data = tc,
            selected_col = 1,
            tolerance = TOLERANCE_SMALL,
        )

@pytest.mark.xfail(raises=IndexError, reason='list index out of range')
def test_mode_fail_empty_input(build_vm):
    execute_stat_func_test(
        mpcstats_lib.mode,
        statistics.mode,
        num_params = 1,
        player_data = pd1([]),
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

@pytest.mark.xfail(raises=statistics.StatisticsError, reason='no mode for empty data')
def test_mode_fail_all_magic_numbers(build_vm):
    execute_stat_func_test(
        mpcstats_lib.mode,
        statistics.mode,
        num_params = 1,
        player_data = pd1([M, M, M, M]),
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_mean_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.mean,
        statistics.mean,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_variance_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.variance,
        statistics.variance,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_linear_regression_success(build_vm):
    def vector_res_parser(x):
        return [x.slope, x.intercept]

    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.linear_regression,
        statistics.linear_regression,
        num_params = 2,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
        vector_res_parser = vector_res_parser,
    )

def test_harmonic_mean_non_zero_input_success(build_vm):
    # python harmonic_mean doesn't support negative values
    player_data = gen_player_data(30, 2, 2, 1, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.harmonic_mean,
        statistics.harmonic_mean,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        tolerance = 0.005,
    )

def test_harmonic_mean_input_contains_0_success(build_vm):
    # python harmonic_mean doesn't support negative values
    player_data = gen_player_data(30, 2, 2, 1, 100, 0.5)
    player_data[0][1][0] = 0
    execute_stat_func_test(
        mpcstats_lib.harmonic_mean,
        statistics.harmonic_mean,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_pvariance_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.pvariance,
        statistics.pvariance,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        tolerance = TOLERANCE_SMALL,
    )

def test_pstdev_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.pstdev,
        statistics.pstdev,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        # due to use of sfix and sqrt, the result can differ up to 5%
        tolerance = 0.05,
    )

def test_stdev_success(build_vm):
    player_data = gen_player_data(30, 2, 2, -100, 100, 0.5)
    execute_stat_func_test(
        mpcstats_lib.stdev,
        statistics.stdev,
        num_params = 1,
        player_data = player_data,
        selected_col = 1,
        # due to use of sfix and sqrt, the result can differ up to 5%
        tolerance = 0.05,
    )

