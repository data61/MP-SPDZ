import json
import re
from typing import Any
from constants import STATISTICAL_SECURITY_PARAMETER, EXECUTION_TIME, DATA_SENT_BY_PARTY_0, GLOBAL_DATA_SENT_MB, RESULT

def parser(attrs: object, line: str, keys: list[str], regex: str) -> bool:
    m = re.match(regex, line)
    if m is None:
        return False
    for i in range(len(keys)):
        attrs[keys[i]] = m.group(i + 1)
    return True

def parse_execution_output(output: str) -> object:
    attrs = {}

    for line in output.split('\n'):
        parser(attrs, line, [RESULT], r'^{RESULT}: (.*)$'.format(RESULT=RESULT)) or \
        parser(attrs, line, [STATISTICAL_SECURITY_PARAMETER], r'^Using statistical security parameter (.*)$') or \
        parser(attrs, line, [EXECUTION_TIME], r'^Time = (.*) seconds.*$') or \
        parser(attrs, line, [DATA_SENT_BY_PARTY_0, 'rounds'], r'^Data sent = ([^\s]+) MB [^~]*~([^s]+) rounds.*$') or \
        parser(attrs, line, [GLOBAL_DATA_SENT_MB], r'^Global data sent = (.*) MB.*$') or \
        True

    return attrs

def parse_compiler_output(output: str) -> object:
    attrs = {}

    for line in output.split('\n'):
        parser(attrs, line, ['Virtual machine rounds'], r'^ +\d*) [^ ]+$') or \
        True

    return attrs
