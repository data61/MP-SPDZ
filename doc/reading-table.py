#!/usr/bin/python

import glob, os, sys, csv
from collections import defaultdict

sys.path.insert(0, os.path.abspath('..'))

from Compiler.compilerLib import Compiler
from Compiler.papers import *

def protocols():
    exclude = 'no', 'bmr-program',
    for sub in '', 'BMR/':
        for filename in glob.glob('../Machines/%s*-party.cpp' % sub):
            name = os.path.basename(filename)[:-10]
            if not (name in exclude or name.endswith('-prep')):
                yield name

out = csv.writer(open('protocol-reading.csv', 'w'))

protocol_links = set()

for protocol in sorted(protocols()):
    protocol = Compiler.short_protocol_name(protocol)
    assert os.path.exists('../Scripts/%s.sh' % protocol)
    reading = reading_for_protocol(protocol)
    assert reading
    out.writerow([protocol, reading])
    protocol_links.update(reading.split(', '))

refs = defaultdict(set)

for filename in glob.glob('../Compiler/*.py'):
    for line in open(filename):
        m = re.search(r"reading.'([^']*)', '([^']*)'", line)
        if m:
            refs[m.group(2)].add(m.group(1))

out = csv.writer(open('other-reading.csv', 'w'))

for ref, keywords in sorted(refs.items(), key=lambda x: list(sorted(
        re.sub('\(', '', xx).lower() for xx in x[1]))):
    out.writerow([', '.join(sorted(keywords, key=lambda x: x.lower())),
                  papers[ref]])

del out
