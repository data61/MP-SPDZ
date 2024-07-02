from test_lib import Succ, test_function
from player_data import player_data_4x2_2_party
import mpcstats_lib
import statistics

test_function(
    'good input',
    mpcstats_lib.median,
    statistics.median,
    num_params = 1,
    player_data = player_data_4x2_2_party,
    selected_col = 1,
    exp = Succ(0.01),
)

