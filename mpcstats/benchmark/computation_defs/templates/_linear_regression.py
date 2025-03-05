from common_lib import create_party_data_files, get_aggr_party_data_vecs, write_result, datasets_dir
from mpcstats_lib import linear_regression

NUM_PARTIES = '::NUM_PARTIES::'
COL_INDEX_1 = 1
COL_INDEX_2 = 2

def prepare_data():
    dataset_file = datasets_dir / '::DATASET_FILE::'
    create_party_data_files(dataset_file, NUM_PARTIES)

def computation():
    vec1, vec2 = get_aggr_party_data_vecs(NUM_PARTIES, [COL_INDEX_1, COL_INDEX_2]) 
    res = linear_regression(vec1, vec2)
    write_result(res.reveal())

