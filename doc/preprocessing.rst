Preprocessing
-------------

Many protocols in MP-SPDZ use preprocessing, that is, producing secret
shares that are independent of the actual data but help with the
computation. Due to the independence, this can be done in batches to
save communication rounds and even communication when using
homomorphic encryption that works with large vectors such as LWE-based
encryption.

Generally, preprocessing is done on demand and per computation
threads. On demand means that batches of preprocessing data are
computed whenever there is none in storage, and a computation thread
is a thread created by control flow instructions such as
:py:func:`~Compiler.library.for_range_multithread`.

The exceptions to the general rule are edaBit generation with
malicious security and AND triples with malicious security and honest
majority, both when using bucket size three. Bucket size three implies
batches of over a million to achieve 40-bit statistical security, and
in honest-majority binary computation the item size is 64, which makes
the actual batch size 64 million triples. In multithreaded programs,
the preprocessing is run centrally using the threads as helpers.

The batching means that the cost in terms of time and communication
jump whenever another batch is generated. Note that, while some
protocols are flexible with the batch size and can thus be controlled
using ``-b``, others mandate a batch size, which can be as large as a
million.


.. _prep-files:

Separate preprocessing
======================

It is possible to separate out the preprocessing from the
input-dependent ("online") phase. This is done by either option ``-F``
or ``-f`` on the virtual machines. In both cases, the preprocessing
data is read from files, either all data per type from a single file
(``-F``) or one file per thread (``-f``). The latter allows to use
named pipes.

The file name depends on the protocol and the computation domain. It
is generally ``<prefix>/<number of players>-<protocol
shorthand>-<domain length>/<preprocessing type>-<protocol
shorthand>-P<player number>[-T<thread number>]``. For example, the
triples for party 1 in SPDZ modulo a 128-bit prime can be found in
``Player-Data/2-p-128/Triples-p-P1``. The protocol shorthand can be
found by calling ``<share type>::type_short()``. See
:ref:`share-type-reference` for a description of the share types.

Preprocessing files start with a header describing the protocol and
computation domain to avoid errors due to mismatches. The header is as
follows:

- Length to follow (little-endian 8-byte number)
- Protocol descriptor
- Domain descriptor
- MAC if applicable

The protocol descriptor is defined by ``<share
type>::type_string()``. For SPDZ modulo a prime it is ``SPDZ gfp``.

The domain descriptor depends on the kind of domain:

Modulo a prime
  Serialization of the prime

  - Sign bit (0 as 1 byte)
  - Length to follow (little-endian 4-byte number)
  - Prime (big-endian)

Modulo a power of two:
  Exponent (little-endian 4-byte number)

:math:`GF(2^n)`
  - Storage size in bytes (little-endian 8-byte number). Default is 16.
  - :math:`n` (little-endian 4-byte number)

As an example, the following output of ``hexdump -C`` describes SPDZ
modulo the default 128-bit prime
(170141183460469231731687303715885907969)::

  00000000  31 00 00 00 00 00 00 00  53 50 44 5a 20 67 66 70  |1.......SPDZ gfp|
  00000010  00 10 00 00 00 80 00 00  00 00 00 00 00 00 00 00  |................|
  00000020  00 00 1b 80 01 01 00 00  00 78 03 11 c6 61 5a 68  |.........x...aZh|
  00000030  5a

The last 128 bits denote the MAC and will differ from instance to
instance. The MAC is stored to avoid errors that are hard to track
otherwise.

The actual data is stored is by simple concatenation. For example,
triples are stored as repetitions of ``a, b, ab``, and daBits are
stored as repetitions of ``a, b`` where ``a`` is the arithmetic
share and ``b`` is the binary share.

For protocols with MAC, the value share is stored before the MAC
share.

Values are generally stored in little-endian order. Note the following
domain specifics:

Modulo a prime
  Values are stored in `Montgomery representation
  <https://en.wikipedia.org/wiki/Montgomery_modular_multiplication>`_
  with :math:`R` being the smallest power of :math:`2^{64}` larger than
  the prime. For example, :math:`R = 2^{128}` for a 128-bit prime.
  Furthermore, the values are stored in the smallest number of 8-byte
  blocks necessary, all in little-endian order. As an example,
  consider the default 128-bit prime
  :math:`p = 170141183460469231731687303715885907969`. The Montgomery
  representation of :math:`x` is :math:`xR \bmod p`. For :math:`x =
  1`, this is 170141183460469231731687303715882303487 or
  0x7fffffffffffffffffffffffffe47fff in hexadecimal. Using
  to little-endian, ``hexdump -C`` would output the following::

    ff 7f e4 ff ff ff ff ff ff ff ff ff ff ff ff 7f

Modulo a power of two:
  Values are stored in the smallest number of 8-byte blocks necessary,
  all in little-endian order, so 1 with a modulus of :math:`2^{64}`
  would result in the following ``hexdump -C`` output::

    01 00 00 00 00 00 00 00

:math:`GF(2^n)`
  Values are stored in blocks according to the storage size above,
  all in little-endian order.

For further details, have a look at ``Utils/Fake-Offline.cpp``, which
contains code that generates preprocessing data insecurely for a range
of protocols (underlying the binary ``Fake-Offline.x``).

``{mascot,cowgear,mal-shamir}-offline.x`` generate
sufficient preprocessing data for a specific high-level program with
MASCOT, CowGear, and malicious Shamir secret sharing, respectively.
