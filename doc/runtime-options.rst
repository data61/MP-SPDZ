Run-Time Options
================

This section explains the command-line arguments with the virtual
machines (``<protocol>-party.x`` or
``Scripts/<protocol>.sh``). You can also use them with
``Scripts/compile-run.py`` by specifying them after an additional
``--``::

  Scripts/compile-run.py <protocol> <compile-time-args> -- <run-time-args>


Efficiency trade-offs
---------------------

.. cmdoption:: -B <bucket size>
	       --bucket-size=<bucket size>

   Some protocols use a shuffle-and-sacrifice approach for malicious
   security, for example `Araki et
   al. <https://doi.org/10.1109/SP.2017.15>`_. The bucket size offers
   a trade-off between efficiency and batch size, that is, a larger
   bucket size allows for smaller batch size and less unused
   preprocessing and memory usage for smaller computations but a
   smaller bucket size offers better efficiency for large enough
   computations. The options are 3 (batch size :math:`2^{20}`), 4
   (batch size 10386), and 5 (batch size 1024).

.. cmdoption:: -b <bucket size>
	       --batch-size=<bucket size>

   Many protocols allow freely choosing a batch size for preprocessing
   (for example, Beaver triples or random bits). The trade-off here is
   that smaller batch sizes require more rounds but might generate
   less unused data and require less memory while larger batch sizes
   reduce the number of rounds. The default is 1000 for dishonest-majority
   protocols and 10,000 for honest-majority protocols as the latter
   are usually more efficient. The virtual machines also use
   information about the program provided by the compiler to lower the
   preprocessing amount if appropriate.

.. cmdoption:: -d
	       --direct

   Some protocols allow a choice between direct communication (every
   party communicates with every other party or a constant fraction of
   the parties) and star-shaped communication (every party sends
   information to a chosen one, which then collates and sends the
   results to all parties). For example, the opening of an additive
   secret sharing could happen with all parties sending their shares to
   all others or a single party could receive all shares and then
   send the sum to all parties. In the first case, the communication
   is quadratic in one round whereas, in the second case, the
   communication is linear in two rounds. The default is star-shaped
   communication due to the asymptotic difference but you can select
   direct communication using this option.

.. cmdoption:: -Q
	       --bits-from-squares

   There are several ways to generate random secret bits such as
   XORing bits input by several parties or using the square root of
   squares of random numbers, which will be the original number with
   probability one half. This has been used by `Damgård et
   al. <https://eprint.iacr.org/2012/642>`_ for example. The virtual
   machines chose the random bit generation method depending on the
   number of players as the first method does not scale well. However,
   you can force the square method using this option.


Protocol options
----------------

.. cmdoption:: -E <error>
	       --trunc-error <error>

   Probabilistic truncation as introduced by `Mohassel and Zhang
   <https://eprint.iacr.org/2017/396>`_ requires the truncated value
   to be in a negligibly small range of the secret-sharing
   domain. Otherwise, the result will be wrong with non-negligible
   probability. This parameter controls if this kind of cheap
   truncation is used depending on the range determined by the
   compiler. The default is 40, which means that if the range is
   larger than :math:`2^-40` of the secret-sharing domain, another
   truncation is used if possible.

.. cmdoption:: -F
	       --file-preprocessing

   The default is to generate preprocessing data like Beaver triples on
   demand. With this option, it is instead read from files in
   ``Player-Data``. You need to run ``Fake-Offline.x`` or the relevant
   ``<protocol>-offline-party.x`` beforehand to makes this work.

.. cmdoption:: -f
	       --file-prep-per-thread

   This is similar to ``--file-preprocessing`` but uses a separate
   file per thread instead of global files. MP-SPDZ does not provide
   the relevant functionality to match this. Instead, it is meant for
   external software to provide preprocessing in a streaming manner
   via a named pipe. See
   :download:`../Utils/stream-fake-mascot-triples.cpp` for an example
   and `this GitHub issue
   <https://github.com/data61/MP-SPDZ/issues/418>`_ for further discussion.

.. cmdoption:: -lg2 <bit length>
	       --lg2 <bit length>

   This allows specifying :math:`n` for :math:`GF(2^n)`. The default
   is either 40, 64, or 128 depending on the protocol and the choice
   of options when compiling the binaries.

.. cmdoption:: -lgp <bit length>
	       --lgp <bit length>

   This allows specifying the bit length :math:`n` of the prime
   modulus if applicable. The prime is chosen as the smallest prime of
   the form :math:`2^{n-1} + x \cdot 2^{16} + 1` for a positive
   integer :math:`x`. This form makes it compatible with the
   LWE-based homomorphic encryption used for some protocols.

.. cmdoption:: -P <modulus>
	       --prime <modulus>

   This allows specifying the prime modulus if applicable.

.. cmdoption:: -R <bit length>
	       --ring <bit length>

   This allows specifying :math:`n` for computation modulo :math:`2^n`
   if applicable. It defaults to 64. Note that this choice has to be
   fixed during compilation for any non-linear computation, which
   means you cannot change it here anymore.

.. cmdoption:: -S <security parameter>
	       --security <security parameter>

   This allows specifying the statistical security parameter if
   applicable. The default is 40, which means that the adversary can
   get away with cheating with probability :math:`2^{-40}`. This parameter
   does not apply to SPDZ2k, see below.

.. cmdoption:: -SP <security parameter>
	       --spdz2k-security <security parameters>

   This allows specifying the statistical security parameter for
   SPDZ2k. The default is 64, and it means that the adversary can get
   away with cheating with probability roughly :math:`2^{-64+\log_2(64)} =
   2^{-58}`.


Network setup
-------------

.. cmdoption:: -e
	       --encrypted
	       -u
	       --unencrypted

   The default is to use SSL-encrypted connections with
   honest-majority protocols and unencrypted connections with
   dishonest-majority protocols. The reasoning is that a network
   adversary can reconstruct all secrets with the secret sharing used
   for honest-majority protocol but not with the additive secret
   sharing used in dishonest-majority protocols. You can use the
   relevant option to choose the non-default option. However, you will
   need to compile the binaries with ``SECURE = -DINSECURE`` in
   ``CONFIG.mine`` to use unencrypted channels with honest-majority
   protocols.

.. cmdoption:: -ext-server
	       --external-server

   At the beginning of a computation, all parties have to connect
   each other. One way of facilitating is running ``Server.x``, which
   waits for all parties to connect and broadcasts all hostnames. The
   default is to run this functionality within party 0, but this
   option makes party 0 receive the list of parties from elsewhere
   like every other party.

.. cmdoption:: -h <hostname>
	       --hostname <hostname>

   This is to specify the hostname where party 0 or the setup server
   (using ``-ext-server``) is found.

.. cmdoption:: -ip <filename>
	       --ip-file-name <filename>

   Instead of having of party 0 or an external server collecting
   hostnames, you can put all information in a file. See :ref:`io` for
   the format.

.. cmdoption:: -mp <port number>
	       --my-port <port number>

   This allows specifying the port where a party listens for
   connections from other parties. The default is the base number (see
   below) plus the party number.

.. cmdoption:: -pn <base number>
	       --portnumbase <base number>

   This allows specifying the base for computing the party-specific
   port number by adding the party number. The logic to have this
   comes from running all parties on the same host for testing
   purposes. The default is 5000.

.. cmdoption:: -p
	       --player

   This allows specifying the party number. Alternatively, you can
   give it as the first argument.

.. cmdoption:: -N
	       --nparties

   This allows specifying the number of parties if applicable. The
   default is two for dishonest-majority protocols and three for
   honest-majority protocols. If an external server is used, you can
   specify the number of parties there instead.


Local facilities
----------------

.. cmdoption:: --code-locations

   This activates the output of the most important locations in the
   C++ code that are active for a particular computation.

.. cmdoption:: -D <path>
	       --disk-memory <path>

   By default, the virtual machines store everything in memory,
   including all data structures like (multi-)arrays. With this
   option, they instead use a `memory-mapped file
   <https://en.wikipedia.org/wiki/Memory-mapped_file>`_ in the given
   path.

.. cmdoption:: -I
	       --interactive

   By default, inputs to the computation are read from files in
   ``Player-Data`` (see :ref:`io` for more details). This changes to
   reading from stdin in the main thread. Furthermore, this enables
   output on all parties rather than just party 0.

.. cmdoption:: -IF <prefix>
	       --input-file <prefix>

   By default, inputs read from
   ``Player-Data/Input-[Binary-]-P<partyno>-<threadno>``. This changes
   the prefix from ``Player-Data/Input``.

.. cmdoption:: -m <old|empty>
	       --memory <old|empty>

   By default, the memory (where data structures such as
   :py:class:`Array` are stored) is initialized to zero at the
   beginning of a computation as it is when using ``empty``. With
   ``old``, it is instead loaded from
   ``Player-Data/Memory-<type>-P<playerno>`` where it is stored at the
   end of computation (curtailed to :math:`2^{20}` for
   efficiency).

.. cmdoption:: -OF <prefix>
	       --output-file <prefix>

   By default, :py:func:`print_ln` and similar output to stdout on
   party 0 but not on other parties. This changes the output to
   ``<prefix>-P<partyno>-<threadno>``. You can also use ``.`` to
   output to stdout on all parties.

.. cmdoption:: -o <option1[,option2...]>
	       --options <option1[,option2...]>

   This provides a flexible way to add run-time options. Any mention of
   :cpp:func:`has_option` works with this. One example is ``-o
   throw_exceptions``, which prevents exceptions from being caught,
   thus allowing debugging with GDB.

.. cmdoption:: -v
	       --verbose

   Use this option to active verbose benchmarking output like the
   number of preprocessing items and the cost of different phases.
