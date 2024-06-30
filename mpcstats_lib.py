"""
Contains functions can be used in MP-SPDZ circuits.
"""

from Compiler.library import print_ln, for_range, runtime_error
from Compiler.types import sint, sfix, Matrix, sfloat, Array
from Compiler.util import if_else
from Compiler.mpc_math import sqrt, exp2_fx, log2_fx


# geometric_mean assumes MAGIC_NUMBER to be non-negative
MAGIC_NUMBER = 999

# To enforce round to the nearest integer, instead of probabilistic truncation
# Ref: https://github.com/data61/MP-SPDZ/blob/e93190f3b72ee2d27837ca1ca6614df6b52ceef2/doc/machine-learning.rst?plain=1#L347-L353
sfix.round_nearest = True


def read_data(party_index: int, num_columns: int, num_rows: int) -> Matrix:
    """
    Read data from each party's input file to a Matrix in MP-SPDZ circuit.
    """
    data = Matrix(num_columns, num_rows, sint)
    # TODO: use @for_range_opt instead?
    for i in range(num_columns):
        for j in range(num_rows):
            data[i][j] = sint.get_input_from(party_index)
    return data


def print_data(data: Matrix):
    """
    Print the data in the Matrix.
    """
    num_columns = data.shape[0]
    num_rows = data.shape[1]
    for i in range(num_columns):
        for j in range(num_rows):
            print_ln("data[{}][{}]: %s".format(i, j), data[i][j].reveal())


# Top 5 functions to implement

def mean(data: list[sint]):
    total = sum(if_else(i != MAGIC_NUMBER, i, 0) for i in data)
    count = sum(if_else(i != MAGIC_NUMBER, 1, 0) for i in data)
    return total / count


def median(data: list[sint]):
    # TODO: Check if Array.create_from is properly constrained // if I dont put reference, it's just from the mp-spdz doc itself
    data = Array.create_from(data)
    # TODO: Check if there's a need to use sint(0), can we just use 0? would that violate constraint?
    median_odd = sint(0)
    median_even = sint(0)
    data.sort()
    size = sum(if_else(i!= MAGIC_NUMBER, 1, 0) for i in data)

    # TODO: Check if for_range is any different than naive Python for-loop
    @for_range(len(data))
    def _(i):
        # TODO: Check if wrapping sint() makes sense/ properly constrained
        # TODO: Check why we cannot just use size.int_div(2) -> it returns wrong result, so now we use the method below instead.
        median_odd.update(median_odd+(size==2*sint(i)+size%2)*data[i])
        # TODO: Check if there's the need to use update: See example in Compiler.library.for_range(start, stop=None, step=None) in the mp-spdz doc itself
        median_even.update(median_even+(size==2*sint(i)+size%2)*data[i]/2+(size-2==2*sint(i)+size%2)*data[i]/2)
    # TODO: Check if size%2 is properly constrained
    return (size%2)*median_odd + (1-size%2)*median_even


def join(data1: Matrix, data2: Matrix, data1_column_index: int, data2_column_index: int) -> Matrix:
    """
    Join two matrices based on the matching index in the specified columns.

    :param data1: The first matrix
    :param data2: The second matrix
    :param data1_column_index: The column index in data1 to match with data2_column_index
    :param data2_column_index: The column index in data2 to match with data1_column_index

    For example, if data1 = [
        [0, 1, 2, 3],
        [152, 160, 170, 180]
    ], data2 = [
        [3, 0, 4],
        [50, 60, 70],
    ], data1_column_index = 0, data2_column_index = 0, then the output will be [
        [0, 1, 2, 3],
        [152, 160, 170, 180],
        [0, MAGIC_NUMBER, MAGIC_NUMBER, 3],
        [60, MAGIC_NUMBER, MAGIC_NUMBER, 50],
    ]
    """
    # E.g. [2, 4]
    num_columns_1 = data1.shape[0]
    num_rows_1 = data1.shape[1]

    # E.g. [2, 3]
    num_columns_2 = data2.shape[0]
    num_rows_2 = data2.shape[1]

    new_data = Matrix(num_columns_1 + num_columns_2, num_rows_1, sint)
    # Initialize the first part of the matrix with data1
    for i in range(num_columns_1):
        for j in range(num_rows_1):
            new_data[i][j] = data1[i][j]
    # Initialize the rest of the matrix with MAGIC_NUMBER
    for i in range(num_columns_2):
        for j in range(num_rows_1):
            new_data[num_columns_2 + i][j] = MAGIC_NUMBER

    # Check the matching index in data1 and data2
    for i in range(num_rows_1):
        # Find the corresponding index in data2[data2_column] for data1[data1_column][i]
        id_in_data1 = data1[data1_column_index][i]
        for j in range(num_rows_2):
            # Now checking if data2[data2_column][j] is the same as data1[data1_column][i]
            id_in_data2 = data2[data2_column_index][j]
            match = id_in_data1 == id_in_data2
            # If the match is found, set the entire row of data2[data2_column] to the new_data
            for k in range(num_columns_2):
                new_data[num_columns_1 + k][i] = if_else(
                    match,
                    data2[k][j],
                    new_data[num_columns_1 + k][i]
                )
    return new_data


def covariance(data1: list[sint], data2: list[sint]):
    n = len(data1)
    total1 = sum(if_else(i!= MAGIC_NUMBER, i, 0) for i in data1)
    total2 = sum(if_else(i!= MAGIC_NUMBER, i, 0) for i in data2)
    count = sum(if_else(i!= MAGIC_NUMBER, 1, 0) for i in data1)
    mean1 = total1/count
    mean2 = total2/count
    data1 = Array.create_from(if_else(i!=MAGIC_NUMBER, i, mean1) for i in data1)
    data2 = Array.create_from(if_else(i!=MAGIC_NUMBER, i, mean2) for i in data2)
    # TODO: Check if there's a need to use sfloat(0), can we do something like 0.0
    x = sfloat(0)
    @for_range(n)
    def _(i):
        x.update(x+(data1[i]-mean1)*(data2[i]-mean2))
    return x/(count-1)


def correlation(data1: list[sint], data2: list[sint]):
    n = len(data1)
    total1 = sum(if_else(i!= MAGIC_NUMBER, i, 0) for i in data1)
    total2 = sum(if_else(i!= MAGIC_NUMBER, i, 0) for i in data2)
    count = sum(if_else(i!= MAGIC_NUMBER, 1, 0) for i in data1)
    mean1 = total1/count
    mean2 = total2/count
    data1 = Array.create_from(if_else(i!=MAGIC_NUMBER, i, mean1) for i in data1)
    data2 = Array.create_from(if_else(i!=MAGIC_NUMBER, i, mean2) for i in data2)
    numerator = sfloat(0)
    denominator1 = sfloat(0)
    denominator2 = sfloat(0)
    @for_range(n)
    def _(i):
        numerator.update(numerator+(data1[i]-mean1)*(data2[i]-mean2))
        denominator1.update(denominator1+(data1[i]-mean1).square())
        denominator2.update(denominator2+(data2[i]-mean2).square())
    # Check if wrapping sfix() is properly constrainted.
    return numerator/(sqrt(sfix(denominator1))*sqrt(sfix(denominator2)))


def where(_filter: list[sint], data: list[sint]):
    n = len(data)
    data = Array.create_from(data)
    _filter = Array.create_from(_filter)
    res = sint.Array(n)
    @for_range(n)
    def _(i):
        res[i] = if_else(_filter[i], data[i], MAGIC_NUMBER)
    return res


def geometric_mean(data: list[sint]):
    # check the validity of the dataset
    num_non_positives = sum(if_else(i <= 0, 1, 0) for i in data).reveal()
    if num_non_positives > 0:
        runtime_error('geometric_mean: all numbers in the dataset must be positive')

    num_magic_nums = sum(if_else(i == MAGIC_NUMBER, 1, 0) for i in data).reveal()
    if len(data) == num_magic_nums:
        runtime_error('geometric_mean: dataset is empty')

    # comupte geometric mean
    log_sum = sum(if_else(i != MAGIC_NUMBER, log2_fx(i), 0) for i in data)
    num_log_sums = sum(if_else(i != MAGIC_NUMBER, 1, 0) for i in data)
    exponent = log_sum / num_log_sums

    return exp2_fx(exponent)


# LATER

def harmonic_mean(data: list[sint]):
    # TODO: implement harmonic_mean
    raise NotImplementedError


def mode(data: list[sint]):
    # TODO: implement mode
    raise NotImplementedError


def pstdev(data: list[sint]):
    # TODO: implement pstdev
    raise NotImplementedError


def pvariance(data: list[sint]):
    # TODO: implement pvariance
    raise NotImplementedError


def stdev(data: list[sint]):
    # TODO: implement stdev
    raise NotImplementedError


def variance(data: list[sint]):
    # TODO: implement variance
    raise NotImplementedError


def linear_regression(data1: list[sint], data2: list[sint]):
    # TODO: implement linear_regression
    raise NotImplementedError
