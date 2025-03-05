#!/usr/bin/env python3

from pathlib import Path
repo_root = Path(__file__).parent.parent.parent

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')

from common_lib import mpcstats_dir, benchmark_dir

import os
import re

from common_lib import compile_computation, execute_silently, read_script
from Compiler.library import print_ln
from Compiler.util import if_else
from timeit import timeit
from datetime import datetime
import argparse
import json
from typing import Any
from constants import TOTAL_BYTECODE_SIZE, COMPILATION_TIME, PROG_NAME

def parse_args() -> Any:
    parser = argparse.ArgumentParser(description='Compile script')
    parser.add_argument(
        '--name',
        type=str,
        default=f'computation',
        help='Name of the computation',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show output from Comipler module',
    )
    parser.add_argument(
        '--binary',
        type=int,
        help='Compile binary circuit with specified bit length of sit',
    )
    parser.add_argument(
        '--ring',
        type=int,
        help='Compile for rings of specified bit length',
    )
    parser.add_argument(
        '--file',
        type=argparse.FileType('r'),
        default=None,
        help='Computation definition file. If not specified, the definition will be read from stdin',
    )
    parser.add_argument(
        '--edabit',
        action='store_true',
        help='Use edaBit',
    )
    return parser.parse_args()

args = parse_args()

# inject computation definition script
script = read_script(args.file)
exec(script)

prepare_data() # from computation definition script

# compile the computation
def f():
    #flags = []
    flags = ['--optimize-hard', '--flow-optimization']
    if args.edabit:
        flags.append('--edabit')
    if args.binary:
        flags.append('-G')
        flags.append('-B')
        flags.append(args.binary)
    if args.ring:
        flags.append('--ring')
        flags.append(args.ring)

    compile_computation(args.name, computation, flags)

def g():
    return timeit(f, number=1)

time_elapsed = g() if args.verbose else execute_silently(g)

# build the json output and print
prog_name_re = re.compile(rf'^{args.name}-\d+\.bc$')
bytecode_dir = benchmark_dir / 'Programs' / 'Bytecode'

files = [
    { 'name': file.name, 'size': file.stat().st_size } for file
    in bytecode_dir.rglob(f'{args.name}-*.bc')
    if prog_name_re.match(file.name)
]
total_bytecode_size = sum(file['size'] for file in files)

output = {
    'edaBit': args.edabit,
    'binary': args.binary,
    PROG_NAME: args.name,
    COMPILATION_TIME: time_elapsed,
    'bytecodes': files,
    TOTAL_BYTECODE_SIZE: total_bytecode_size,
}

print(json.dumps(output))

