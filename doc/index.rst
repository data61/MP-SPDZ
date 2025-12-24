Welcome to MP-SPDZ's documentation!
===================================

MP-SPDZ is a framework for multi-party computation, a
privacy-enhancing technology focused on input privacy. It uses
protocols running between several entities to create a conceptual
black box in which data can operated on privately. Such a black box
could be created between banks or healthcare providers to jointly
operate on privacy-sensitive data. Please see `this gentle
introduction <https://eprint.iacr.org/2020/300>`_ for more information
on multi-party computation.

If you're new to MP-SPDZ, consider the following:

1. `Quickstart tutorial <readme.html#tl-dr-binary-distribution-on-linux-or-source-distribution-on-macos>`_
2. :ref:`Machine learning quickstart <ml-quickstart>`
3. `Implemented protocols <readme.html#protocols>`_
4. :ref:`troubleshooting`
5. :ref:`io` lists all the ways of getting data in and out.

.. toctree::
   :maxdepth: 4
   :caption: Contents:

   readme
   reading
   compilation
   runtime-options
   Compiler
   utils
   journey
   optimization
   instructions
   low-level
   function-export
   navigating-c++
   ml-quickstart
   machine-learning
   networking
   io
   client-interface
   multinode
   non-linear
   preprocessing
   lowest-level
   add-protocol
   add-instruction
   homomorphic-encryption
   ecdsa
   troubleshooting


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
