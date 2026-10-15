#!/usr/bin/env python3

"""Benchmark compile time and check that the output stays the same.

Examples:

  Scripts/bench_compile.py --save-golden      # record hashes and timings
  Scripts/bench_compile.py --check            # compare against them
  Scripts/bench_compile.py --profile -k lenet # profile matching entries
  Scripts/bench_compile.py --python python3.12 -j 4 --check
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import pstats
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join(ROOT, '.bench')

# (label, compile.py arguments)
SUITE = [
    ('tutorial-R', ['-R', '64', 'tutorial']),
    ('tutorial-F', ['-F', '64', 'tutorial']),
    ('tutorial-B', ['-B', '32', 'tutorial']),
    ('tutorial-D', ['-D', '-R', '64', 'tutorial']),
    ('tutorial-M', ['-M', '-R', '64', 'tutorial']),
    ('tutorial-O', ['-O', '-R', '64', 'tutorial']),
    ('flow-l', ['-l', 'test_flow_optimization']),
    ('lenet', ['-R', '64', 'keras_mnist_lenet']),
    ('mnist-dense', ['-R', '64', 'keras_mnist_dense']),
    ('lenet-O', ['-O', '-R', '64', 'keras_mnist_lenet']),
    ('sbitint-B', ['-B', '64', 'test_sbitint']),
    ('aes-B', ['-B', '32', 'aes_circuit']),
    ('gc-oram', ['-B', '32', 'gc_oram']),
    ('tutorial-m', ['-m', '1000', '-R', '64', 'tutorial']),
    ('oram', ['-R', '64', 'oram_tutorial']),
    ('shuffle', ['-R', '64', os.path.join(ROOT, 'Scripts', 'bench_shuffle.mpc')]),
    ('bankers', ['-F', '64', 'bankers_bonus', '1']),
]


def run(entry, python, profile=False, root=ROOT):
    label, args = entry
    cmd = [python]
    if profile:
        cmd += ['-m', 'cProfile', '-o', prof_file(label)]
    cmd += ['./compile.py', '-o', 'bench-' + label] + args
    start = time.perf_counter()
    res = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, universal_newlines=True)
    elapsed = time.perf_counter() - start
    if res.returncode:
        return label, elapsed, None, res.stdout
    files = re.findall(r'^Writing to (.*)$', res.stdout, re.M)
    hashes = {}
    for f in files:
        with open(os.path.join(root, f), 'rb') as fh:
            data = fh.read()
        if f.endswith('.sch'):
            # relevant_opts is a set, so its order is not stable
            data = re.sub(rb'^opts: (.*)$',
                          lambda m: b'opts: ' + b' '.join(sorted(m.group(1).split())),
                          data, flags=re.M)
            # the compile command contains the path of bench_shuffle.mpc
            data = data.replace(os.fsencode(ROOT), b'ROOT')
        hashes[os.path.basename(f)] = hashlib.sha256(data).hexdigest()
    return label, elapsed, hashes, res.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--save-golden', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('-k', dest='filter',
                        help='only labels containing one of these '
                        '(comma-separated)')
    parser.add_argument('--skip', help='skip these labels (comma-separated)')
    parser.add_argument('-j', type=int, default=1, help='parallel jobs')
    parser.add_argument('-n', type=int, default=40, help='profile rows')
    parser.add_argument('--root', default=ROOT,
                        help='compile with the compiler in this directory, '
                        'e.g. a worktree of an older version')
    parser.add_argument('-r', '--repeat', type=int, default=1,
                        help='run each entry this many times and '
                        'report the fastest')
    options = parser.parse_args()

    suite = SUITE
    if options.filter:
        suite = [e for e in suite
                 if any(f in e[0] for f in options.filter.split(','))]
    if options.skip:
        suite = [e for e in suite if e[0] not in options.skip.split(',')]
    golden_file = os.path.join(BENCH_DIR, 'golden.json')
    golden = {}
    if os.path.exists(golden_file):
        with open(golden_file) as f:
            golden = json.load(f)

    with concurrent.futures.ThreadPoolExecutor(options.j) as pool:
        def best(e):
            runs = [run(e, options.python, options.profile, options.root)
                    for i in range(options.repeat)]
            return min(runs, key=lambda x: x[1])
        results = list(pool.map(best, suite))

    failed = False
    print('%-14s %9s %9s  %s' % ('label', 'time', 'golden', 'output'))
    for label, elapsed, hashes, output in results:
        ref = golden.get(label, {})
        if hashes is None:
            status = 'ERROR'
            failed = True
        elif options.check:
            status = 'same' if hashes == ref.get('hashes') else 'DIFFERENT'
            failed |= status != 'same'
        else:
            status = ''
        print('%-14s %8.2fs %8.2fs  %s' % (
            label, elapsed, ref.get('time', float('nan')), status))
        if hashes is None:
            print(output[-1500:])
        elif options.check and status != 'same':
            for name in sorted(set(hashes) | set(ref.get('hashes', {}))):
                if hashes.get(name) != ref.get('hashes', {}).get(name):
                    print('    differs:', name)
        if options.profile and hashes is not None:
            stats = pstats.Stats(prof_file(label))
            stats.sort_stats('cumulative').print_stats(options.n)
            stats.sort_stats('tottime').print_stats(options.n)

    if options.save_golden:
        os.makedirs(BENCH_DIR, exist_ok=True)
        for label, elapsed, hashes, _ in results:
            if hashes is not None:
                golden[label] = {'time': elapsed, 'hashes': hashes}
        with open(golden_file, 'w') as f:
            json.dump(golden, f, indent=1, sort_keys=True)
        print('saved', golden_file)

    sys.exit(1 if failed else 0)


def prof_file(label):
    os.makedirs(BENCH_DIR, exist_ok=True)
    return os.path.join(BENCH_DIR, label + '.prof')


if __name__ == '__main__':
    main()
