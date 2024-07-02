import pytest, statistics

import mpcstats_lib
from .lib import execute_test
from .player_data import player_data_4x2_2_party

def test_correlation_success():
    execute_test(
        mpcstats_lib.correlation,
        statistics.correlation,
        num_params = 2,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = 0.01,
    )

def test_covariance_success():
    execute_test(
        mpcstats_lib.covariance,
        statistics.covariance,
        num_params = 2,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = 0.01,
    )

def test_geometric_mean_success():
    execute_test(
        mpcstats_lib.geometric_mean,
        statistics.geometric_mean,
        num_params = 1,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = 0.01,
    )

def test_median_success():
    execute_test(
        mpcstats_lib.median,
        statistics.median,
        num_params = 1,
        player_data = player_data_4x2_2_party,
        selected_col = 1,
        tolerance = 0.01,
    )

