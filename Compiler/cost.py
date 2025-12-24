import re
import math
import os
import itertools

class Comm:
    def __init__(self, comm=0, offline=0):
        try:
            comm = comm()
        except:
            pass
        try:
            self.online, self.offline = comm
            assert not offline
        except:
            self.online = comm or 0
            assert isinstance(self.online, (int, float))
            self.offline = offline

    def __getitem__(self, index):
        return self.offline if index else self.online

    def __iter__(self):
        return iter((self.online, self.offline))

    def __add__(self, other):
        return Comm(x + y for x, y in zip(self, other))

    def __sub__(self, other):
        return self + -1 * other

    def __mul__(self, other):
        return Comm(x * other for x in self)
    __rmul__ = __mul__

    def __repr__(self):
        return 'Comm(%d, %d)' % tuple(self)

    def __bool__(self):
        return bool(sum(self))

    def sanitize(self):
        try:
            return tuple(int(x) for x in self)
        except:
            return (0, 0)

dishonest_majority = {
    'emi',
    'mascot',
    'spdz',
    'soho',
    'gear',
}

semihonest = {
    'emi|soho',
    'atlas|^shamir',
    'dealer',
}

ring = {
    'ring',
    '2k',
}

fixed = {
    '^(ring|rep-field)': 3,
    'rep4': 6,
    'mal-rep-field': (6, 9),
    'mal-rep-ring': (lambda l: (6 * l, (l + 5) * 9)),
    'sy-rep-field': 6,
    'sy-rep-ring': lambda l: (6 * (l + 5), 0),
    'ps-rep-field': 9,
    'ps-rep-ring': lambda l: 9 * (l + 5),
    'brain': lambda l: (3 * 2 * l, 3 * (2 * (l + 5) + 3 * (2 * l + 15))),
}

ot_cost = 64
spdz2k_sec = 64

def lowgear_cipher_length(l):
    res = (30 + 2 * l) // 8
    return res

def highgear_cipher_lengths(l):
    res = 71 + 16 * l, 57 + 8 * l
    return res

def highgear_cipher_limbs(l):
    res = sum(int(math.ceil(x / 64)) for x in highgear_cipher_lengths(l))
    return res

def highgear_decrypt_length(l):
    return highgear_cipher_lengths(l)[0] / 8 + 1

def hemi_cipher_length(l):
    res = 16 * l + 77
    return res

def hemi_cipher_limbs(l):
    res = int(math.ceil(hemi_cipher_length(l) / 64))
    return res

variable = {
    '^shamir': lambda N: N * (N - 1) // 2,
    'atlas': lambda N: N // 2 * 4,
    'dealer': lambda N: (2 * (N - 1), 1),
    'semi': lambda N: lambda l: (
        4 * (N - 1) * l, N * (N - 1) * (l * (ot_cost + 8 * l))),
    'mascot': lambda N: lambda l: (
        4 * (N - 1) * l, N * (N - 1) * (l * (3 * ot_cost + 64 * l))),
    'spdz2k': lambda N: lambda l: (
        4 * (N - 1) * l,
        N * (N - 1) * (ot_cost * (2 * l + 4 * spdz2k_sec // 8) + \
                       (l + spdz2k_sec // 8) * (4 * spdz2k_sec + 2 * l * 8) + \
                       (5 * (l + 2 * spdz2k_sec // 8) * spdz2k_sec))),
    'hemi': lambda N: lambda l: (
        4 * (N - 1) * l, N * (N - 1) * hemi_cipher_limbs(l) * 8 * 2 * 2),
    'temi': lambda N: lambda l: (
        4 * (N - 1) * l, (N - 1) * (hemi_cipher_limbs(l) * 8 * 2 * 2 +
                                    hemi_cipher_length(l) / 8 + 1) * 2),
    'soho': lambda N: lambda l: (
        4 * (N - 1) * l,
        (N - 1) * (N * highgear_cipher_limbs(l) * 8 * 2 +
                   highgear_decrypt_length(l)) * 2),
    'owgear': lambda N: lambda l: (
        4 * (N - 1) * l,
        N * ((N - 1) * (lowgear_cipher_length(l) * (128 + 48) + 64) + 2 * l)),
    '.*i.*gear': lambda N: lambda l: (
        4 * (N - 1) * l,
        (N - 1) * (highgear_cipher_limbs(l) * 96 * 3 +
                   highgear_decrypt_length(l) * 16 + N * 192 + 6 * l)),
    'sy-shamir': lambda N: 2 * variable['^shamir'](N) + variable_random['^shamir|atlas'](N)
}

variable_square = {
    'soho': lambda N: lambda l: (
        0, (N - 1) * (N * highgear_cipher_limbs(l) * 8 + 46) * 2),
    'i.*gear': lambda N: lambda l: (
        0, (N - 1) * (highgear_cipher_limbs(l) * 64 * 3 +
                      highgear_decrypt_length(l) * 12 + N * 128 + 4 * l)),
    'ps-rep-ring': lambda N: lambda l: fixed['ps-rep-ring'](l),
    'sy-shamir': lambda N: (
        0, variable['sy-shamir'](N) + variable_random['sy-shamir'](N))
}

matrix_triples = {
    'dealer': lambda N: (N - 1, 1),
}

diag_matrix =  {
    'hemi': lambda N, l, dims: N * (N - 1) * hemi_cipher_limbs(l) * 8 * 2 * \
    (dims[0] * dims[1] + dims[0] * dims[2]),
    'temi': lambda N, l, dims: (N - 1) * (
        hemi_cipher_limbs(l) * 8 * 2 * 2 * (
            dims[0] * dims[1] + dims[0] * dims[2]) +
        (hemi_cipher_length(l) / 8 + 1) * 2 * (dims[0] * dims[2])),
}

fixed_bit = {
    'mal-rep-field': (0, 11),
    'rep4': (0, 8),
}

fixed_square = {
    'mal-rep-ring': lambda l: fixed['mal-rep-ring'](l)[1],
}

variable_bit =  {
    'dealer': lambda N: (0, 1),
    # missing OT cost
    'emi': lambda N: lambda l: (0, l + ot_cost / 8) if N == 2 else None,
    'mal-shamir': lambda N: (
        0, variable_random['^shamir|atlas'](N) + \
        math.ceil(N / 2) * variable_input['^shamir|atlas'](N) + \
        (math.ceil(N / 2) - 0) * variable['^shamir'](N) + \
        2 * reveal_variable['(mal|sy)-shamir'](N)),
}

fixed_and = {
    '(mal|sy|ps)-rep': lambda bucket_size=4: (6, 3 * (3 * bucket_size - 2)),
}

variable_and = {
    'emi': lambda N: (4 * (N - 1), N * (N - 1) * ot_cost)
}

trunc_pr = {
    '^ring': 4,
    'rep-field': 1,
    'rep4': 12,
}

bit2a = {
    '^(ring|rep-field)': 3,
}

dabit_from_bit = {
    'ring',
    '-rep-ring',
    'semi2k',
}

bits_from_squares = {
    'atlas': lambda N: N > 4,
    'sy-shamir': lambda N: True,
    'soho': lambda N: True,
    'gear': lambda N: True,
    'ps-rep-ring': lambda N: True,
    'spdz2k': lambda N: True,
    'mascot': lambda N: True,
    'mal-rep-ring': lambda N: True,
    'emi$': lambda N: True,
}

reveal = {
    '((^|rep.*)ring|rep-field|brain)': 3,
    'rep4': 4,
}

reveal_variable = {
    '^shamir|atlas': lambda N: 3 * (N - 1) // 2,
    '(mal|sy)-shamir': lambda N: (N - 1) // 2 * 2 * N,
    'dealer': lambda N: 2 * (N - 2),
    'spdz2k': lambda N: N * variable_input['mascot|spdz2k'](N),
}

fixed_input = {
    '(^|ps-|mal-)(ring|rep-)': 1,
    'sy-rep-ring': lambda l: 4 * (l + 5),
    'sy-rep-field': 4,
    'rep4': 2,
}

variable_input = {
    '^shamir|atlas': lambda N: N // 2,
    'mal-shamir': lambda N: N // 2,
    'sy-shamir': lambda N: \
    N // 2 + variable['^shamir'](N) + variable_random['^shamir|atlas'](N),
    'mascot|spdz2k': lambda N: (N - 1) * Comm(1, ot_cost * 2),
    'owgear': lambda N: lambda l: (
        (N - 1) * l, (N - 1) * lowgear_cipher_length(l) * 16),
    'i.*gear': lambda N: lambda l: (
        (N - 1) * l, (N - 1) * (highgear_cipher_limbs(l) * 24 + 32 +
                                highgear_decrypt_length(l) * 4)),
}

variable_random = {
    '^shamir|atlas': lambda N: N * (N // 2) / ((N + 2) // 2),
    'mal-shamir': lambda N: N // 2 * N,
    'sy-shamir': lambda N: \
    2 * variable_random['^shamir|atlas'](N) + variable['^shamir'](N),
}

# cut random values
fixed_randoms = {
    'sy-rep-ring': lambda l: 3 * (l + 5),
}

cheap_dot_product = {
    '^(ring|rep-field)',
    'sy-*',
    '^shamir',
    'rep4',
    'atlas',
}

shuffle_application = {
    '^(ring|rep-field)': 6,
    'sy-rep-field': 12,
    'sy-rep-ring': lambda l: 12 * (l + 5)
}

variable_edabit = {
    'dealer': lambda N: lambda n_bits: lambda l: l + n_bits / 8
}

def find_match(data, protocol):
    for x in data:
        if re.search(x, protocol):
            return x

def get_match(data, protocol):
    x = find_match(data, protocol)
    try:
        return data.get(x)
    except:
        return bool(x)

def get_match_variable(data, protocol, n_parties):
    f = get_match(data, protocol)
    if f:
        return f(n_parties)

def apply_length(unit, length):
    try:
        return Comm(unit(length))
    except:
        return Comm(unit) * length

def get_cost(fixed, variable, protocol, n_parties):
    return get_match(fixed, protocol) or \
        get_match_variable(variable, protocol, n_parties)

def get_mul_cost(protocol, n_parties):
    return get_cost(fixed, variable, protocol, n_parties)

def get_and_cost(protocol, n_parties):
    return get_cost(fixed_and, variable_and, protocol, n_parties)

def expected_communication(protocol, req_num, length, n_parties=None,
                           force_triple_use=False):
    from Compiler.instructions import shuffle_base
    from Compiler.program import Tape
    get_int = lambda x: req_num.get(('modp', x), 0)
    get_bit = lambda x: req_num.get(('bit', x), 0)
    res = Comm()
    if not protocol:
        return res
    if not n_parties:
        try:
            if get_match(fixed, protocol):
                raise TypeError()
            n_parties = int(os.getenv('PLAYERS'))
        except TypeError:
            if find_match(dishonest_majority, protocol):
                n_parties = 2
            else:
                n_parties = 3
    if find_match(dishonest_majority, protocol):
        threshold = n_parties - 1
    elif re.match('rep4', protocol):
        n_parties = 4
        threshold = 1
    elif re.match('dealer', protocol):
        threshold = 0
    else:
        threshold = n_parties // 2
    malicious = not find_match(semihonest, protocol)
    x = find_match(fixed, protocol)
    y = get_mul_cost(protocol, n_parties)
    unit = apply_length(y, length)
    n_mults = get_int('simple multiplication')
    matrix_cost = apply_length(
        get_match_variable(matrix_triples, protocol, n_parties), length)
    use_diag_matrix = get_match(diag_matrix, protocol)
    use_triple_number = False
    if find_match(cheap_dot_product, protocol):
        n_mults += get_int('dot product')
    elif (not matrix_cost and not use_diag_matrix) or force_triple_use:
        use_triple_number = True
        n_mults = get_int('triple')
    and_cost = get_and_cost(protocol, n_parties)
    if and_cost:
        res += Comm(and_cost) * math.ceil(get_bit('triple') / 8)
    else:
        n_mults += get_bit('triple') / (length * 8)
    bit_cost = Comm(apply_length(
        bit2a.get(x) or get_match(fixed_bit, protocol) or
        get_match_variable(variable_bit, protocol, n_parties),
        length))
    input_cost = apply_length(
        get_match(fixed_input, protocol) or \
        get_match_variable(variable_input, protocol, n_parties), length)
    output_cost = Comm(
        get_match(reveal, protocol) or \
        get_match_variable(reveal_variable, protocol, n_parties) or \
        (n_parties - 1) * 2)
    random_cost = apply_length(
        get_match_variable(variable_random, protocol, n_parties), length)
    if not random_cost:
        random_cost = n_parties * input_cost
    square_unit = get_cost(fixed_square, variable_square, protocol, n_parties)
    if not square_unit:
        def square_unit(l):
            unit = apply_length(y, l)
            return Comm(0, (unit[1] or unit[0]) + sum(
                apply_length(output_cost, l)))
    square_cost = apply_length(square_unit, length)
    res += square_cost * get_int('square')
    if bit_cost:
        res += bit_cost * get_int('bit')
    elif get_match_variable(bits_from_squares, protocol, n_parties):
        if square_cost:
            if get_match(ring, protocol):
                sb_cost = apply_length(square_unit, length + 1)
            else:
                sb_cost = square_cost
            bit_cost = Comm(0, offline=sum(sb_cost + output_cost * length))
        else:
            bit_cost = Comm(0, offline=sum(
                unit + random_cost + length * output_cost))
        res += bit_cost * get_int('bit')
    else:
        bit_cost = Comm(0, offline=sum(
            threshold * unit + (threshold + 1) * input_cost))
        res += bit_cost * get_int('bit')
    res += unit * n_mults
    if not unit:
        sh_protocol = re.sub('mal-', '', protocol)
        sh_unit = get_mul_cost(sh_protocol, n_parties)
        sh_random_unit = get_match_variable(
            variable_random, sh_protocol, n_parties)
        if sh_unit:
            res += length * Comm(
                sum(2 * output_cost * n_mults),
                int(n_mults * (3 * sh_random_unit + 2 * sh_unit + \
                    2 * sum(output_cost))))
    res += Comm(get_match(trunc_pr, protocol)) * length * \
        get_int('probabilistic truncation')
    res += Comm(bit2a.get(x)) * length * get_int('bit2A')
    res += output_cost * length * get_int('open')
    res += output_cost * get_bit('open')
    res += get_match(dabit_from_bit, protocol) * bit_cost * get_int('dabit')
    res += random_cost * get_int('random')
    res += get_int('cut random') * apply_length(
        get_match(fixed_randoms, protocol), length)
    shuffle_correction = not find_match(shuffle_application, protocol)
    def get_node():
        req_node = Tape.ReqNode("")
        req_node.aggregate()
        return req_node
    for x in req_num:
        if len(x) >= 3 and x[0] == 'modp':
            if x[1] == 'input':
                res += input_cost * req_num[x]
            elif x[1] == 'shuffle application':
                shuffle_cost = apply_length(
                    get_match(shuffle_application, protocol), length)
                if shuffle_cost:
                    res += Comm(shuffle_cost) * req_num[x] * x[2]
                elif find_match(cheap_dot_product, protocol) or \
                     'dealer' in protocol:
                    res += shuffle_base.n_swaps(x[2]) * (threshold + 1) * \
                        req_num[x] * unit * (x[3] + malicious)
                elif shuffle_correction:
                    node = get_node()
                    shuffle_base.add_apply_usage(
                        node, x[2], x[3], add_shuffles=False)
                    node.num = -node.num
                    if not use_triple_number:
                        node.num['modp', 'triple'] = 0
                    shuffle_base.add_apply_usage(
                        node, x[2], x[3], add_shuffles=False,
                        malicious=malicious, n_relevant_parties=threshold + 1)
                    res += req_num[x] * \
                        expected_communication(protocol, node.num, length,
                                               force_triple_use=True)
            elif x[1] == 'shuffle generation':
                if 'dealer' in protocol:
                    res += Comm(
                        req_num[x] * shuffle_base.n_swaps(x[2]) * length)
                else:
                    req_node = get_node()
                    shuffle_base.add_gen_usage(
                        req_node, x[2], add_shuffles=False)
                    req_node.num = -req_node.num
                    if shuffle_correction:
                        shuffle_base.add_gen_usage(
                            req_node, x[2], add_shuffles=False,
                            malicious=malicious,
                            n_relevant_parties=threshold + 1)
                    res += req_num[x] * \
                        expected_communication(protocol, req_node.num, length)
        elif x[0] == 'matmul':
            mm_unit = Comm()
            if use_diag_matrix:
                dims = list(x[1])
                if dims[0] > dims[2]:
                    dims[0::2] = dims[2::-2]
                mm_unit += Comm(
                    offline=use_diag_matrix(n_parties, length, dims))
                matrix_cost = Comm(unit.online / 2)
            for idx in ((0, 1), (1, 2)):
                mm_unit += Comm(matrix_cost.online) * \
                    x[1][idx[0]] * x[1][idx[1]]
            mm_unit += Comm(offline=matrix_cost.offline) * x[1][0] * x[1][2]
            res += mm_unit * req_num[x]
        elif re.search('edabit', x[0]):
            edabit = get_match_variable(variable_edabit, protocol, n_parties)
            if edabit:
                res += Comm(offline=edabit(x[1])(length)) * req_num[x]
    res.n_parties = n_parties
    return res
