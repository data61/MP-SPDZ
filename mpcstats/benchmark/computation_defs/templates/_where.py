from common_lib import create_party_data_files, get_aggr_party_data_vecs, write_result, datasets_dir
from mpcstats_lib import where

NUM_PARTIES = '::NUM_PARTIES::'
COL_INDEX = 1

def prepare_data():
    dataset_file = datasets_dir / '::DATASET_FILE::'
    create_party_data_files(dataset_file, NUM_PARTIES)

def computation():
    [data_vec] = get_aggr_party_data_vecs(NUM_PARTIES, [COL_INDEX]) 
    selector = [elem > 0 for elem in data_vec] 
    res = where(selector, data_vec)
    # writes number of Trues in selector as result
    write_result(sum(selector).reveal())

