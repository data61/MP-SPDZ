#!/usr/bin/env python3

from pathlib import Path
repo_root = Path(__file__).parent.parent.parent

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')

from common_lib import datasets_dir

import os
import shutil
import random
from typing import Any

import argparse

def parse_args() -> Any:
    parser = argparse.ArgumentParser(description='Dataset gen script')
    parser.add_argument(
        'num_cols',
        type=int,
        help='Number of cols',
    )
    parser.add_argument(
        'num_rows',
        type=int,
        help='Number of rows',
    )
    parser.add_argument(
        '--multiplier',
        type=int,
        default=100,
        help='Multiplier to randomly generated numbers',
    )
    parser.add_argument(
        '--int',
        action='store_true',
        help='Use integers only',
    )
    parser.add_argument(
        '--mean',
        type=float,
        default=0,
        help='Mean of normal distribution',
    )
    parser.add_argument(
        '--stddev',
        type=float,
        default=1,
        help='Standard deviation of normal distribution',
    )
    return parser.parse_args()

args = parse_args()

opt = ''
if args.int:
    opt += '-int'
file_name = f'{args.num_cols}x{args.num_rows}{opt}.csv'

with open(datasets_dir / file_name, 'w') as file:
    for _row in range(args.num_rows):
        nums = [random.gauss(args.mean, args.stddev) * args.multiplier for _ in range(args.num_cols)]
        if args.int:
            nums = [int(n) for n in nums]
        line = ','.join([str(n) for n in nums])
        file.write(f'{line}\n')


