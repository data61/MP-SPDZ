from dataclasses import dataclass

@dataclass
class DefaultMPSPDZSetting:
    # To enforce round to the nearest integer, instead of probabilistic truncation
    # Ref: https://github.com/data61/MP-SPDZ/blob/e93190f3b72ee2d27837ca1ca6614df6b52ceef2/doc/machine-learning.rst?plain=1#L347-L353
    round_nearest: bool = True

    # length of the decimal part of sfix
    f: int = 22

    # whole bit length of sfix. must be at least f+11
    k: int = 40

