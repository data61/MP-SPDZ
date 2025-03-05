from pathlib import Path
repo_root = Path(__file__).parent.parent
mpcstats_dir = repo_root / 'mpcstats'
benchmark_dir = mpcstats_dir / 'benchmark'
player_data_dir = benchmark_dir / 'Player-Data'
datasets_dir = benchmark_dir / 'datasets'

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')
sys.path.append(f'{repo_root}/mpcstats/benchmark')

from Compiler.compilerLib import Compiler
from Compiler.types import sfix
from Compiler.types import Matrix
from Compiler.library import print_ln
from Compiler.util import if_else
import subprocess
import config
import os
from typing import Callable, Any, Literal, TextIO
from dataclasses import dataclass
from constants import RESULT
import random

DIMENTION_FILE = player_data_dir / 'file-dimentions.txt'
DIMENTION_FILE_SEP = ' '

@dataclass
class Dimention:
    rows: int
    cols: int

    def num_elements(self):
        return self.rows * self.cols

def read_script(maybe_file: TextIO) -> str:
    if maybe_file is None:
        return sys.stdin.read()
    else:
        # assumes that file is already opened
        try:
            return maybe_file.read()
        finally:
            maybe_file.close()

def create_party_data_files(dataset_file: Path, num_parties: int) -> None:
    if not dataset_file.exists():
        raise FileNotFoundError(f'{dataset_file} not found')

    player_data_dir.mkdir(parents=True, exist_ok=True)

    try:
        dims = open(DIMENTION_FILE, 'w')
        party_files = [open(player_data_dir / f'Input-P{i}-0', 'w') for i in range(num_parties)]
        file = dataset_file.open('r')

        curr_party = 0
        num_rows = [0] * num_parties
        num_columns = [None] * num_parties

        # read from dataset_file and create party data files
        # keeping track of the dimention of each file
        with open(dataset_file) as file:
            while line := file.readline():
                toks = [tok.strip() for tok in line.split(',')]
                if num_columns[curr_party] is None:
                    num_columns[curr_party] = len(toks)

                line = ' '.join(toks)
                party_files[curr_party].write(f'{line}\n')

                num_rows[curr_party] += 1
                curr_party = (curr_party + 1) % num_parties

        # write dimentions of party files to file
        for i in range(num_parties):
            dims.write(f'{num_rows[i]}{DIMENTION_FILE_SEP}{num_columns[i]}\n')

    finally:
        for f in party_files:
            f.close()
        dims.close()

def load_file_dimentions() -> list[Dimention]:
    if not Path(DIMENTION_FILE).is_file():
        raise FileNotFoundError(f'{DIMENTION_FILE} not found')
    dims = []
    with open(DIMENTION_FILE) as f:
        while (line := f.readline().strip()) is not None:
            if line == '': # if the last line
                return dims
            toks = line.split(DIMENTION_FILE_SEP) 
            rows, cols = toks
            dim = Dimention(int(rows), int(cols))
            dims.append(dim)

# has to be called from inside computation
# assumes that DIMENTION_FILE has already been created
def load_party_data_to_matrices(num_parties: int, join_tweak: (int, int) = None) -> list[Matrix]:
    dims = load_file_dimentions()
    ms = []
    for i in range(num_parties):
        with open(player_data_dir / f'Input-P{i}-0') as f:
            dim = dims[i]

            m = Matrix(dim.rows, dim.cols, sfix)
            for row in range(dim.rows):
                for col in range(dim.cols):
                    m[row][col] = sfix.get_input_from(i)
            ms.append(m)

    if join_tweak is not None:
        assert num_parties == 2
        m1, m2 = ms 
        m1_row, m2_row = join_tweak

        # shuffle m1 row and copy to m2_row
        src_row = [m1[m1_row][i] for i in range(dims[0].cols)]
        random.shuffle(src_row)
        for i in range(dims[1].cols):
            m2[m2_row][i] = src_row[i]

    return ms

def get_aggr_party_data_vecs(num_parties: int, col_indices: list[int]) -> list[list[sfix]]:
    # load party data into matrices
    ms = load_party_data_to_matrices(num_parties)

    # aggregate matrix columns of all parties
    vecs = [[] for _ in range(len(col_indices))]

    for party_id, m in enumerate(ms):
        for vec_index, col_index in enumerate(col_indices):
            elem = [m[i][col_index] for i in range(m.shape[0])]
            vecs[vec_index][:] += elem[:]
    return vecs

def compile_computation(
    name: str,
    computation: Callable[[], None],
    flags: list[str] = [],
    cfg: Any = config.DefaultMPSPDZSetting(),
) -> None:
    '''
    Compiles computation function and generates:
    - ./Programs/Schedules/{name}.sch
    - ./Programs/Bytecode/{name}-0.bc
    in the current directory
    '''
    def init_and_compute():
        sfix.round_nearest = cfg.round_nearest
        sfix.set_precision(cfg.f, cfg.k)
        computation()
    compiler = Compiler(flags)
    compiler.register_function(name)(init_and_compute)

    # temporarily clear the command line arguments passed to the caller script
    # while executing compiler.compile_func
    # since it affects how compile.compile_func works
    bak = sys.argv
    sys.argv = [sys.argv[0]]
    compiler.compile_func()
    sys.argv = bak

def exec_subprocess(cmd: str) -> str:
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, check=True, text=True)
        return f'{res.stdout}\n{res.stderr}'

    except subprocess.CalledProcessError as e:
        print(e)
        raise

def execute_computation(
    num_parties: int,
    mpc_script: str,
    name: str,
) -> str:
    cmd = f'PLAYERS={num_parties} {mpc_script} {name}'
    return exec_subprocess(cmd)

def execute_silently(f: Callable[[], None]) -> Any:
    stdout_bak = sys.stdout

    # redirect stdout to /dev/null
    sys.stdout = open(os.devnull, 'w')

    try:
        return f()
    finally:
        sys.stdout.close()
        sys.stdout = stdout_bak

def write_result(value: Any) -> None:
    print_ln(f'{RESULT}: %s', value)
