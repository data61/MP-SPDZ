from Compiler.types import Array, sint
from typing import Tuple
from Compiler.library import for_range_opt, for_range_multithread, print_ln


class PrivatePathQueryUtils:
    @staticmethod
    def create_path(
        query_size: int, is_graph: bool = False
    ) -> Tuple[Array, Array, int]:
        """
        Creates Alice's path from input. if we are using the grid approach it
        returns x,y coordinates that index into Bobs grid, if we are using the
        graph approach it returns the vertex ids that index into bobs adj list

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

        if is_graph:
            print("Creating graph path")
            qx = Array(query_size, sint)
            qy = Array(query_size, sint)
            for i in range(query_size):
                x, y = sint.get_input_from(alice), sint.get_input_from(alice)
                qx[i] = x
                qy[i] = y
            return qx, qy, query_size

        else:
            print("Creating grid path")
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
