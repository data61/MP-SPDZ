#!/usr/bin/env python3

from pathlib import Path
repo_root = Path(__file__).parent.parent.parent

import sys
sys.path.append(str(repo_root))
sys.path.append(f'{repo_root}/mpcstats')

from common_lib import benchmark_dir, mpcstats_dir

import argparse
import subprocess
import os
import time
from typing import List, Literal, Optional
import json
from common_lib import read_script 
from constants import MAX_MEM_USAGE_KB, EXEC_TIME_SEC

# 1.rss (Resident Set Size):
#   - Measures the physical memory the process is currently using (in RAM).
#   - This is typically the most relevant for benchmarking how much memory a process is actively using.
#    -Best for benchmarking real memory usage because it shows the actual RAM being consumed by the process.
# 2. vsz (Virtual Memory Size):
#   - Measures the total virtual memory the process is using, including memory that has been swapped out, memory that has been mapped but not used, and shared memory.
#   - Less relevant for benchmarking real memory usage because it includes parts of memory that aren’t physically loaded into RAM, such as mapped files and swapped-out memory.
 
# TODO generate list from type definition
MemoryFieldsType = Literal['rss', 'vsz']
MemoryFields = ['rss', 'vsz']

os.environ['PATH'] += os.pathsep + str(benchmark_dir)

def parse_args():
    parser = argparse.ArgumentParser(description="Benchmarking Script")
    parser.add_argument(
        'protocol',
        type=str, 
        help='MPC protocol',
    )
    parser.add_argument(
        'num_parties',
        type=int,
        help='Number of participating parties',
    )
    parser.add_argument(
        '--name',
        type=str,
        default=f'computation',
        help='Name of the computation',
    )
    parser.add_argument(
        '--mem-field',
        type=str, 
        choices=MemoryFields,
        default=MemoryFields[0],
        help='ps command field to retrieve memory usage',
    )
    parser.add_argument(
        '--edabit',
        action='store_true',
        help='Use edaBit',
    )
    parser.add_argument(
        '--mem-get-sleep',
        type=float, 
        default=1,
        help='Time interval (in seconds) to sleep between memory retrievals for execution'
    )
    parser.add_argument(
        '--file',
        type=str,
        help='Computation definition file. If not specified, the definition will be read from stdin',
    )
    parser.add_argument(
        '--comp-args',
        type=str,
        help='Arguments for `compile.py`',
    )
    parser.add_argument(
        '--remote',
        type=int,
        help='Party number in remote execution',
    )
    parser.add_argument(
        '--verbose-compiler',
        action='store_true',
        help='Show output from internally called scripts',
    )
    parser.add_argument(
        '--verbose-vm',
        action='store_true',
        help='Show output from vm',
    )
    return parser.parse_args()

def exec_ps(pid: int, field: MemoryFieldsType) -> int:
    if os.name == 'posix':
        res = subprocess.run(
            ['ps', '-o', f'{field}=', '-p', str(pid)],
            stdout=subprocess.PIPE,
        )
        return int(res.stdout.decode().strip())

def gen_compile_cmd(args: argparse.Namespace) -> list[str]:
    compile_script = benchmark_dir / 'compile.py'
    opts = []
    if args.comp_args is not None:
        opts.extend(args.comp_args.split())
    if args.name:
        opts.extend(['--name', args.name])
    if args.file:
        opts.extend(['--file', args.file])
    if args.edabit:
        opts.append('--edabit')
    if args.verbose_compiler:
        opts.append('--verbose')

    return [compile_script] + opts

def gen_executor_cmd(args: argparse.Namespace) -> list[str]:
    executor_script = benchmark_dir / 'executor.py'
    opts = []
    if args.name:
        opts.extend(['--name', args.name])
    if args.file:
        opts.extend(['--file', args.file])
    if args.remote is not None:
        opts.extend(['--remote', str(args.remote)])
    if args.verbose_vm:
        opts.append('--verbose')
 
    return [executor_script, args.protocol, str(args.num_parties)] + opts

def monitor_mem_usage(proc: subprocess.Popen, mem_field: str, mem_get_sleep: float) -> int:
    max_mem_usage = 0
    while proc.poll() is None:  # While the process is running
        ps_output = subprocess.run(['ps', '-p', str(proc.pid), '-o', f'{mem_field}='], capture_output=True, text=True)
        mem_usage = int(ps_output.stdout.strip())
        if mem_usage > max_mem_usage:
            max_mem_usage = mem_usage
        time.sleep(mem_get_sleep)

    return max_mem_usage

def read_proc_stdout(proc: subprocess.Popen) -> list[str]:
    lines = []
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.strip())
    proc.wait()
    return lines

def exec_cmd(cmd: list[str], computation_script: str, mem_field: str, mem_get_sleep: float, verbose: bool) -> object:
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(computation_script.encode())
    proc.stdin.close()

    lines = []
    beg_time = time.time()
    try:
        max_mem_usage = monitor_mem_usage(proc, mem_field, mem_get_sleep) 
        lines = read_proc_stdout(proc)
        if len(lines) == 0:
            return {}

        exec_time = time.time() - beg_time

        script = os.path.splitext(cmd[0].name)[0]

        # print out the script output excluding the last line
        if verbose:
            other_lines = [line.decode('utf-8') for line in lines[:-1]]
            print('\n'.join(other_lines))

        # parse the last line to a json object
        res = json.loads(lines[-1].decode('utf-8'))

        res[f'{script}_{MAX_MEM_USAGE_KB}'] = max_mem_usage
        res[f'{script}_{EXEC_TIME_SEC}'] = exec_time
        return res
    
    except Exception as e:
        print(f'Error occurred while monitoring subprocess: {e}\n{lines}')
        proc.terminate()
        raise    

args = parse_args()

# read computaiton script from file or stdin
computation_script = read_script(open(args.file) if args.file else None)

# execute compile script
compile_result = exec_cmd(gen_compile_cmd(args), computation_script, args.mem_field, 0.1, args.verbose_compiler)

# execute executor script
executor_result = exec_cmd(gen_executor_cmd(args), computation_script, args.mem_field, args.mem_get_sleep, args.verbose_vm)

print(json.dumps([compile_result, executor_result]), end='')
