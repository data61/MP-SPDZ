from common_lib import create_party_data_files, get_aggr_party_data_vecs, write_result, datasets_dir
from mpcstats_lib import mean_incl_magic_num

NUM_PARTIES = '::NUM_PARTIES::'
COL_INDEX = 1

def prepare_data():
    dataset_file = datasets_dir / '::DATASET_FILE::'
    create_party_data_files(dataset_file, NUM_PARTIES)

def computation():
    [vec] = get_aggr_party_data_vecs(NUM_PARTIES, [COL_INDEX]) 
    res = mean_incl_magic_num(vec)
    write_result(res.reveal())

