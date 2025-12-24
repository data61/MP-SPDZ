#!/usr/bin/env python3

import sys, os

sys.path.append('.')

from Compiler.instructions_base import Instruction
from Compiler.program import *

if len(sys.argv) <= 1:
    print('Usage: %s <program>' % sys.argv[0])

def run(tapename):
    filename = 'Programs/Bytecode/%s.asm' % tapename
    print('Creating', filename)
    with open(filename, 'w') as out:
        for i, inst in enumerate(Tape.read_instructions(tapename)):
            print(inst, '#', i, file=out)

if sys.argv[1].endswith('.bc'):
    run(os.path.basename(sys.argv[1][:-3]))
else:
    for tapename in Program.read_tapes(sys.argv[1]):
        run(tapename)
