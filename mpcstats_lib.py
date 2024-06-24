"""
Contains functions can be used in MP-SPDZ circuits.
"""

from Compiler.library import print_ln
from Compiler.types import sint, sfix, Matrix
from Compiler.util import if_else


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
    # TODO: implement median
    raise NotImplementedError


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
    # TODO: implement covariance
    raise NotImplementedError


def correlation(data1: list[sint], data2: list[sint]):
    # TODO: implement correlation
    raise NotImplementedError


def where(_filter: list[sint], data: list[sint]):
    # TODO: implement where
    raise NotImplementedError


# LATER

def geometric_mean(data: list[sint]):
    # TODO: implement geometric_mean
    raise NotImplementedError


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
