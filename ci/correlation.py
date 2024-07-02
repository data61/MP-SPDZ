from test_lib import Succ, test_function
import mpcstats_lib
import statistics

good_input = [
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

test_function(
    'good input',
    mpcstats_lib.correlation,
    statistics.correlation,
    num_params = 2,
    player_data = good_input,
    selected_col = 1,
    exp = Succ(0.01),
)

