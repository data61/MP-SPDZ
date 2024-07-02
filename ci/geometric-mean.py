from test_lib import Succ, Fail, gen_player_data, test_function
from player_data import player_data_4x2_2_party
import mpcstats_lib
import statistics

magic_num_only = gen_player_data(
    rows = 4,
    cols = 2,
    num_parties = 2,
    range_beg = 1,
    range_end = 100,
    magic_num_rate = 1.0
)

non_positives = gen_player_data(
    rows = 4,
    cols = 2,
    num_parties = 2,
    range_beg = -100,
    range_end = 0,
    magic_num_rate = 0.3
)

test_function(
    'magic number only',
    mpcstats_lib.geometric_mean,
    statistics.geometric_mean,
    num_params = 1,
    player_data = magic_num_only,
    selected_col = 1,
    exp = Fail('dataset is empty'),
)

test_function(
    'non-positive input',
    mpcstats_lib.geometric_mean,
    statistics.geometric_mean,
    num_params = 1,
    player_data = non_positives,
    selected_col = 1,
    exp = Fail('all numbers in the dataset must be positive'),
)

test_function(
    'good input',
    mpcstats_lib.geometric_mean,
    statistics.geometric_mean,
    num_params = 1,
    player_data = player_data_4x2_2_party,
    selected_col = 1,
    exp = Succ(0.01),
)

