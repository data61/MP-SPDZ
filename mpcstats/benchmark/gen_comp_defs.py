#!/usr/bin/env python3

from pathlib import Path
repo_root = Path(__file__).parent.parent.parent

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')

from common_lib import datasets_dir, benchmark_dir

from pathlib import Path
computation_def_dir = benchmark_dir / 'computation_defs'
computation_def_tmpl_dir = computation_def_dir / 'templates'

import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Benchmark script template engine')
    parser.add_argument(
        'num_parties',
        type=int,
        help='Number of particicating parties',
    )
    return parser.parse_args()

def apply_line_filter(line: int, num_parties: int, dataset: Path) -> str:
    line = line.replace("'::NUM_PARTIES::'", str(num_parties))
    line = line.replace("'::DATASET_FILE::'", f"'{dataset.name}'")
    return line

def create_instance(template: Path, num_parties: int, dataset: Path) -> None:
    file_name = f'{template.stem}_{dataset.stem}_{num_parties}.py'
    instance = computation_def_dir / file_name
    with open(instance, 'w') as inst_file:
        with open(template) as tmpl_file:
            for line in tmpl_file:
                line = apply_line_filter(line, num_parties, dataset)
                inst_file.write(line)

args = parse_args()

datasets = [file for file in datasets_dir.iterdir()]
templates = [file for file in computation_def_tmpl_dir.iterdir()]

# delete all existing instance files
for x in computation_def_dir.iterdir():
    if x.is_file():
        x.unlink()

for dataset in datasets:
    if dataset.name.startswith('_'):
        continue
    for template in templates:
        if template.name.startswith('_'):
            continue
        create_instance(template, args.num_parties, dataset)

