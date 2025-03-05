from common_lib import create_party_data_files, write_result, datasets_dir
from Compiler.GC.types import sbitintvec

NUM_PARTIES = '::NUM_PARTIES::'
COL_INDEX = 1

def prepare_data():
    pass
    #dataset_file = datasets_dir / '::DATASET_FILE::'
    #create_party_data_files(dataset_file, NUM_PARTIES)

def computation():
    sfix = sbitintvec.get_type(256)

    data = [sfix(1), sfix(2), sfix(3), sfix(4)]
    total = sfix(sum(if_else(i != 999, i, 0) for i in data))
    count = sfix(sum(if_else(i != 999, 1, 0) for i in data))
    res = total / count
    #write_result('5')
    write_result(f'{res.reveal()}')

