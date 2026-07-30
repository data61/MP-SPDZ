import subprocess
import sys
import os

band = sys.argv[1]
submodel_path = sys.argv[2]

output_file = os.path.join(submodel_path, 'recycled.json')

subprocess.run([
    'python',
    r'C:\pavier\chakra_recycler.py',
    '--band', band,
    '--input', submodel_path,
    '--output', output_file
])
