from Compiler.library import print_ln
from Compiler.types import sint, Matrix



def read_data(num_parties: int, num_columns: int, num_rows: int) -> list[Matrix]:
    """
    Read data from each party's input file to a Matrix in MP-SPDZ circuit.
    """
    data = [Matrix(num_columns, num_rows, sint) for i in range(num_parties)]
    # TODO: use @for_range_opt instead?
    for party_index in range(num_parties):
        for i in range(num_columns):
            for j in range(num_rows):
                data[party_index][i][j] = sint.get_input_from(party_index)
    return data


def print_data(num_columns: int, num_rows: int, data: Matrix):
    """
    Print the data in the Matrix.
    """
    for i in range(num_columns):
        for j in range(num_rows):
            print_ln("data[{}][{}]: %s".format(i, j), data[i][j].reveal())



# Top 5 functions to implement

def mean(data: list[sint]):
    return sum(data) / len(data)


def median(data: list[sint]):
    # TODO: implement median
    raise NotImplementedError


def join(data1: list[sint], data2: list[sint]):
    # TODO: implement join
    raise NotImplementedError


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
