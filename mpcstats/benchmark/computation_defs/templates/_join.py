from common_lib import create_party_data_files, load_party_data_to_matrices, write_result, datasets_dir
from mpcstats_lib import join

NUM_PARTIES = 2
M1_COL_INDEX = 1
M2_COL_INDEX = 2

def prepare_data():
    dataset_file = datasets_dir / '::DATASET_FILE::'
    create_party_data_files(dataset_file, NUM_PARTIES)

def computation():
    m1, m2 = load_party_data_to_matrices(NUM_PARTIES, (M1_COL_INDEX, M2_COL_INDEX))
    m3 = join(m1, m2, M1_COL_INDEX, M2_COL_INDEX)
    write_result(0)

