High-Level Interface
====================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Compiler.types module
---------------------

.. automodule:: Compiler.types
   :members:
   :no-undoc-members:
   :inherited-members:
   :exclude-members: intbitint, sgf2nfloat, sgf2nint, sgf2nint32, sgf2nuint, t,
		     unreduced_sfix, sgf2nuint32, MemFix, MemFloat, PreOp,
		     ClientMessageType, __weakref__, __repr__,
		     reg_type, int_type, clear_type, float_type, basic_type,
		     default_type, unreduced_type, bit_type, dynamic_array,
		     squant, mov,
		     write_share_to_socket, add, mul, sintbit, from_sint,
		     SubMultiArray
.. autoclass:: sintbit

Compiler.GC.types module
------------------------

.. automodule:: Compiler.GC.types
   :members:
   :no-undoc-members:
   :inherited-members:
   :exclude-members: PreOp, cbit, dynamic_array, conv_cint_vec, bitdec,
		     bit_type, bitcom, clear_type, conv_regint, default_type,
		     mov, dyn_sbits, int_type, mul, vec, load_mem,
		     DynamicArray, get_raw_input_from, bits,
		     input_tensor_from, input_tensor_from_client,
		     input_tensor_via, dot_product, Matrix, Tensor,
		     from_sint, read_from_file, receive_from_client,
		     reveal_to_clients, write_shares_to_socket,
		     write_to_file, sbitint, sbitfix

Compiler.library module
-----------------------

.. automodule:: Compiler.library
   :members:
   :no-undoc-members:
   :no-show-inheritance:
   :exclude-members: approximate_reciprocal, cint_cint_division,
		     sint_cint_division, IntDiv, FPDiv, AppRcr, Norm

Compiler.mpc\_math module
-------------------------

.. automodule:: Compiler.mpc_math
.. autofunction:: atan
.. autofunction:: acos
.. autofunction:: asin
.. autofunction:: cos
.. autofunction:: exp2_fx
.. autofunction:: InvertSqrt
.. autofunction:: log2_fx
.. autofunction:: log_fx
.. autofunction:: pow_fx
.. autofunction:: sin
.. autofunction:: sqrt
.. autofunction:: tan
.. autofunction:: tanh

Compiler.ml module
-------------------------

.. automodule:: Compiler.ml
   :members:
   :no-undoc-members:
   :exclude-members: Tensor, my_squant
   :show-inheritance:
   :inherited-members:
.. autofunction:: approx_sigmoid

Compiler.decision_tree module
-----------------------------

.. automodule:: Compiler.decision_tree
   :members:
   :no-undoc-members:

Compiler.circuit module
-----------------------

.. automodule:: Compiler.circuit
   :members:

Compiler.program module
-----------------------

.. automodule:: Compiler.program
   :members:
   :exclude-members: curr_block, curr_tape, free, malloc, write_bytes, Tape,
		     max_par_tapes

Compiler.oram module
--------------------

.. automodule:: Compiler.oram
   :members:
   :no-undoc-members:
   :exclude-members: AbstractORAM, AtLeastOneRecursionIndexStructure,
		     AtLeastOneRecursionPackedORAMWithEmpty, BaseORAM,
		     BaseORAMIndexStructure, EmptyException, Entry,
		     LinearPackedORAM,
		     LinearPackedORAMWithEmpty, List,
		     LocalIndexStructure, LocalPackedIndexStructure,
		     LocalPackedORAM, OneLevelORAM, OptimalPackedORAM,
		     OptimalPackedORAMWithEmpty,
		     PackedIndexStructure, PackedORAMWithEmpty, RAM,
		     RecursiveIndexStructure,
		     RefBucket, RefRAM, RefTrivialORAM, TreeORAM,
		     TrivialIndexORAM, TrivialORAM,
		     TrivialORAMIndexStructure, ValueTuple, demux,
		     get_log_value_size, get_parallel, get_value_size,
		     gf2nBlock, intBlock


Compiler.sqrt_oram module
-------------------------

.. automodule:: Compiler.sqrt_oram
   :members:
   :no-undoc-members:
   :exclude-members: LinearPositionMap, PositionMap, RecursivePositionMap,
		     refresh, shuffle_the_shuffle


Compiler.path_oblivious_heap module
-----------------------------------

.. automodule:: Compiler.path_oblivious_heap
   :members:
   :no-undoc-members:
   :inherited-members:
   :exclude-members: AbstractMinPriorityQueue, BasicMinTree, CircuitMinTree,
		     EmptyIndexStructure, POHVariant, PathMinTree, dprint,
		     dprint_ln, dprint_ln_if, dprint_str, indent, outdent,


Compiler.dijkstra module
------------------------

.. automodule:: Compiler.dijkstra
   :members:
   :no-undoc-members:
   :exclude-members: IntVectorArray, Matrix, Vector, VectorArray, VectorList


Compiler.sorting module
-----------------------
.. automodule:: Compiler.sorting
   :members:
   :no-undoc-members:
