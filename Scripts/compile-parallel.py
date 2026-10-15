#!/usr/bin/env python3

"""Compile several programs or configurations in parallel.

Each job is a list of compile.py arguments, given either on the command line
(one quoted string per job) or in a file (one job per line, # for comments):

  Scripts/compile-parallel.py "-o ring -R 64 tutorial" "-o bin -B 32 tutorial"
  Scripts/compile-parallel.py -j 4 -f jobs.txt

The compiler itself is single-threaded, so this mainly helps when compiling
many programs, for example the same program for different domains. The
output of each job goes to logs/compile-<program name>.
"""

import argparse
import concurrent.futures
import os
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def program_name(args, parser):
    """ Output name as computed in Program.init_names(). """
    options, positional = parser.parse_args(args)
    if not positional:
        raise ValueError('no program in job: %s' % ' '.join(args))
    name = os.path.basename(positional[0])
    for ext in '.mpc', '.py':
        if name.endswith(ext):
            name = name[:-len(ext)]
    if options.outfile:
        name = options.outfile + '-' + name
    if len(positional) > 1:
        name += '-' + '-'.join(arg.replace('/', '_') for arg in positional[1:])
    return name


def log_name(name):
    # the output name can contain / if -o does
    return name.replace('/', '_')


def run(args, name, python):
    start = time.perf_counter()
    os.makedirs(os.path.join(ROOT, 'logs'), exist_ok=True)
    log = os.path.join(ROOT, 'logs', 'compile-' + log_name(name))
    with open(log, 'w') as out:
        res = subprocess.run([python, os.path.join(ROOT, 'compile.py')] + args,
                             cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
    return res.returncode, time.perf_counter() - start, log


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('jobs', nargs='*', help='compile.py arguments per job')
    parser.add_argument('-f', '--file', help='file with one job per line')
    parser.add_argument('-j', type=int, default=os.cpu_count(),
                        help='number of parallel jobs (default: %(default)s)')
    parser.add_argument('--python', default=sys.executable,
                        help='Python interpreter (default: %(default)s)')
    options = parser.parse_args()

    jobs = [shlex.split(job) for job in options.jobs]
    if options.file:
        with open(options.file) as f:
            for line in f:
                line = line.split('#')[0].strip()
                if line:
                    jobs.append(shlex.split(line))
    if not jobs:
        parser.error('no jobs given')

    from Compiler.compilerLib import Compiler
    compiler_parser = Compiler(custom_args=[]).parser
    names = [program_name(job, compiler_parser) for job in jobs]
    seen = {}
    for job, name in zip(jobs, names):
        # file names can be case-insensitive (default on macOS)
        key = log_name(name).casefold()
        if key in seen:
            sys.exit("Jobs '%s' and '%s' would both write %s, "
                     "use -o to distinguish them" %
                     (' '.join(seen[key]), ' '.join(job), name))
        seen[key] = job

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(options.j) as pool:
        futures = {pool.submit(run, job, name, options.python): (job, name)
                   for job, name in zip(jobs, names)}
        for future in concurrent.futures.as_completed(futures):
            job, name = futures[future]
            code, elapsed, log = future.result()
            status = 'ok' if code == 0 else 'FAILED'
            print('%-6s %7.1fs  %s' % (status, elapsed, ' '.join(job)),
                  flush=True)
            if code:
                failed += 1
                with open(log) as f:
                    print(''.join(f.readlines()[-20:]))
    if failed:
        sys.exit('%d of %d jobs failed, see logs/compile-*' %
                 (failed, len(jobs)))


if __name__ == '__main__':
    main()
