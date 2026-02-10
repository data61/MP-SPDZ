from Compiler.types import Array, sint
from typing import Tuple
from Compiler.library import for_range_opt, for_range_multithread, print_ln


class PrivatePathQueryUtils:
    @staticmethod
    def create_path(query_size: int) -> Tuple[Array, Array, int]:
        """
        Creates Alice's path from input.

        Args:
            query_size: Number of steps in the path (excluding starting position)

        Returns:
            Tuple of (qx, qy, path_length) where:
            - qx: Array of x-coordinates
            - qy: Array of y-coordinates
            - path_length: Total length of path (query_size + 1)
        """
        alice = 0
        path_length = (
            query_size + 1
        )  # Alice sends initial starting location and then query_size steps

        qx = Array(path_length, sint)
        qy = Array(path_length, sint)

        currx, curry = sint.get_input_from(alice), sint.get_input_from(alice)
        qx[0] = currx
        qy[0] = curry

        @for_range_opt(1, path_length)
        def _(i):
            dx = sint.get_input_from(alice)
            dy = sint.get_input_from(alice)

            currx.update(currx + dx)
            curry.update(curry + dy)

            qx[i] = currx
            qy[i] = curry

        print_ln("ALice path length is %s", path_length)

        print_ln(
            "Alice path x: %s",
            [(qx[i].reveal(), qy[i].reveal()) for i in range(path_length)],
        )

        return qx, qy, path_length
