.. _troubleshooting:

Troubleshooting
---------------

This section shows how to solve some common issues.


Crash without error message, ``Killed``, or ``bad_alloc``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some protocols require several gigabytes of memory, and the virtual
machine will crash if there is not enough RAM. You can reduce the
memory usage for many protocols with ``--batch-size`` (try 1 to
confirm the issue and then increment to test the limits). Furthermore,
the batch size for some malicious protocols can be reduced with
``--bucket-size 5``. Every computation thread requires
separate resources, so consider reducing the number of threads with
:py:func:`~Compiler.library.for_range_multithreads` and similar.
Lastly, you can use ``--disk-memory <path>`` to use disk space instead
of RAM for large programs.
Use ``Scripts/memory-usage.py <program-with-args>`` to get an estimate
of the memory usage of a specific program.


List indices must be integers or slices
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You cannot access Python lists with runtime variables because the
lists only exists at compile time. Consider using
:py:class:`~Compiler.types.Array`.


Local variable referenced before assignment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This error can occur if you try to reassign a variable in a run-time
loop like :py:func:`~Compiler.library.for_range`. Use
:py:func:`~Compiler.program.Tape.Register.update` instead of assignment. See
:py:func:`~Compiler.library.for_range` for an example.
You can also use :py:func:`~Compiler.types.sint.iadd` instead of ``+=``.


``compile.py`` takes too long or runs out of memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you use Python loops (``for``), they are unrolled at compile-time,
resulting in potentially too much virtual machine code. Consider using
:py:func:`~Compiler.library.for_range` or similar. You can also use
``-l`` when compiling, which will replace simple loops by an optimized
version.


Cannot derive truth value from register
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This message appears when you try to use branching on run-time data
types, for example::

  x = cint(0)
  y = 0
  if x == 0:
    y = 1
    print_ln('x is zero')

There a number of ways to solve this:

1. Use the ``--flow-optimization`` argument during compilation.
2. Use run-time branching::

     x = cint(0)
     y = cint(0)
     @if_(x == 0)
     def _():
       y.update(1)
       print_ln('x is zero')

   See :py:func:`~Compiler.library.if_e` for the equivalent to
   if/else.
3. Use conditional statements::

     check = x == 0
     y = check.if_else(1, y)
     print_ln_if(check, 'x is zero')

Use ``bit_and`` etc. for more elaborate conditions::

  @if_(a.bit_and(b.bit_or(c)))
  def _():
    ...

The underlying reason for this is that registers are only a
placeholder during the execution in Python, the actual value of which
is only defined in the virtual machine at a later time. See
:ref:`journey` to get an understanding of the overall design.


Cannot branch on secret values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This message appears when you try to use branching on secret data
types, for example::

  x = sint(0)
  if x:
    y = 1
  else:
    y = 2

Deciding whether to execute ``y = 1`` or ``y = 2`` would reveal ``x``,
which contradicts the secrecy guarantee of
:py:class:`~Compiler.types.sint`. However, you can use the following
to achieve the desired ``y`` without revealing ``x``::

  y = (x != 0).if_else(1, 2)

If ``x`` is guaranteed to be 0 or 1, you can also use::

  y = x.if_else(1, 2)

If your use case permits revealing ``x``, see the previous section for
considerations on branching with run-time values.


Incorrect results when using :py:class:`~Compiler.types.sfix`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is most likely caused by an overflow of the precision
parameters because the default choice unlike accommodates numbers up
to around 16,000. See :py:class:`~Compiler.types.sfix` for an
introduction and :py:func:`~Compiler.types.sfix.set_precision` for how
to change the precision.


Variable results when using :py:class:`~Compiler.types.sfix`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is caused the usage of probabilistic rounding, which is used to
restore the representation after a multiplication. See `Catrina and Saxena
<https://www.ifca.ai/pub/fc10/31_47.pdf>`_ for details. You can switch
to deterministic rounding by calling ``sfix.round_nearest = True``.


Only party 0 produces outputs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is to improve readability when running all parties in the same
terminal. You can activate outputs on other parties using ``-OF .`` as
an argument to a virtual machine (``*-party.x``).


Order of memory instructions not preserved
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, the compiler runs optimizations that in some corner case
can introduce errors with memory accesses such as accessing an
:py:class:`~Compiler.types.Array`. The error message does not
necessarily mean there will be errors, but the compiler cannot
guarantee that there will not. If you encounter such errors, you
can fix this either with ``-M`` when compiling or enable memory
protection (:py:func:`~Compiler.program.Program.protect_memory`)
around specific memory accesses.


High number of rounds or slow WAN execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can increase the optimization budget using ``--budget`` during
compilation. The budget controls the trade-off between compilation
speed/memory usage and communication rounds during execution. The
default is 1000, but 100,000 might give better results while still
keeping compilation manageable.


Odd timings
~~~~~~~~~~~

Many protocols use preprocessing, which means they execute expensive
computation to generates batches of information that can be used for
computation until the information is used up. An effect of this is
that computation can seem oddly slow or fast. For example, one
multiplication has a similar cost then some thousand multiplications
when using homomorphic encryption because one batch contains
information for more than than 10,000 multiplications. Only when a
second batch is necessary the cost shoots up. Other preprocessing
methods allow for a variable batch size, which can be changed using
``-b``. Smaller batch sizes generally reduce the communication cost
while potentially increasing the number of communication rounds. Try
adding ``-b 10`` to the virtual machine (or script) arguments for very
short computations.


Disparities in round figures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The number of virtual machine rounds given by the compiler are not an
exact prediction of network rounds but the number of relevant protocol
calls (such as multiplication, input, output etc) in the program. The
actual number of network rounds is determined by the choice of
protocol, which might use several rounds per protocol
call. Furthermore, communication at the beginning and the end of a
computation such as random key distribution and MAC checks further
increase the number of network rounds.


Handshake failures
~~~~~~~~~~~~~~~~~~

If you run on different hosts, the certificates
(``Player-Data/*.pem``) must be the same on all of them. Furthermore,
party ``<i>`` requires ``Player-Data/P<i>.key`` that must match
``Player-Data/P<i>.pem``, that is, they have to be generated to
together.  The easiest way of setting this up is to run
``Scripts/setup-ssl.sh`` on one host and then copy all
``Player-Data/*.{pem,key}`` to all other hosts. This is *not* secure
but it suffices for experiments. A secure setup would generate every
key pair locally and then distributed only the public keys.  Finally,
run ``c_rehash Player-Data`` on all hosts. The certificates generated
by ``Scripts/setup-ssl.sh`` expire after a month, so you need to
regenerate them. The same holds for ``Scripts/setup-client.sh`` if you
use the client facility.


Connection failures
~~~~~~~~~~~~~~~~~~~

MP-SPDZ requires one TCP port per party to be open to other
parties. In the default setting, it's 5000 on party 0, and
5001 on party 1 etc. You change change the base port (5000) using
``--portnumbase`` and individual ports for parties using
``--my-port``. The scripts use a random base port number, which you
can also change with ``--portnumbase``.


Internally called tape has unknown offline data usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certain computations are not compatible with reading preprocessing
from disk. You can compile the binaries with ``MY_CFLAGS +=
-DINSECURE`` in ``CONFIG.mine`` in order to execute the computation in
a way that reuses preprocessing.


Illegal instruction
~~~~~~~~~~~~~~~~~~~

By default, the binaries are optimized for the machine they are
compiled on. If you try to run them an another one, make sure set
``ARCH`` in ``CONFIG`` accordingly. Furthermore, if you run on an x86
processor without AVX (produced before 2011), you need to set
``AVX_OT = 0`` to run dishonest-majority protocols.


Invalid instruction
~~~~~~~~~~~~~~~~~~~

The compiler code and the virtual machine binary have to be from the
same version because most version slightly change the bytecode. This
mean you can only use the precompiled binaries with the Python code in
the same release.


Computation used more preprocessing than expected
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This indicates an error in the internal accounting of
preprocessing. Please file a bug report.


Required prime bit length is not the same as ``-F`` parameter during compilation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is related to statistical masking that requires the prime to be a
fair bit larger than the actual "payload" (40 by default).
The technique goes to back
to `Catrina and de Hoogh
<https://www.researchgate.net/profile/Sebastiaan-Hoogh/publication/225092133_Improved_Primitives_for_Secure_Multiparty_Integer_Computation/links/0c960533585ad99868000000/Improved-Primitives-for-Secure-Multiparty-Integer-Computation.pdf>`_.
See also the paragraph on unknown prime moduli in :ref:`nonlinear`.


Prime number not compatible with encryption scheme
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

MP-SPDZ only supports homomorphic encryption based on the
number-theoretic transform, without it operations would expected to be
considerably. The requirement is that the prime number equals one
modulo a certain power of two. The exact power of two varies due to a
number of parameters, but for the standard choice it's usually
:math:`2^{14}` or :math:`2^{15}`. See `Gentry et
al. <https://eprint.iacr.org/2012/099>`_ for more details on the
underlying mathematics.


Windows/VirtualBox performance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Performance when using Windows/VirtualBox is by default abysmal, as
AVX/AVX2 instructions are deactivated (see e.g.
`here <https://stackoverflow.com/questions/65780506/how-to-enable-avx-avx2-in-virtualbox-6-1-16-with-ubuntu-20-04-64bit>`_),
which causes a dramatic performance loss. Deactivate Hyper-V/Hypervisor
using::

  bcdedit /set hypervisorlaunchtype off
  DISM /Online /Disable-Feature:Microsoft-Hyper-V


Performance can be further increased when compiling MP-SPDZ yourself:
::

 sudo apt-get update
 sudo apt-get install automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm
 git clone https://github.com/data61/MP-SPDZ.git
 cd MP-SPDZ
 make tldr

See also `this issue <https://github.com/data61/MP-SPDZ/issues/557>`_ for a discussion.


``mac_fail``
~~~~~~~~~~~~

This is a catch-all failure in protocols with malicious protocols that
can be caused by something being wrong at any level. Please file a bug
report with the specifics of your case.


Debugging errors in a virtual machine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike Python or Java, C++ gives limited information when something
goes wrong. On Linux, the `GNU Debugger (GDB)
<https://en.wikipedia.org/wiki/GNU_Debugger>`_ aims to mitigate this
by providing more introspection into where exactly something went
wrong. MP-SPDZ comes with a few scripts that facilitate its
use. First, you need to make sure gdb and `screen
<https://en.wikipedia.org/wiki/GNU_Screen>`_ are installed. On Ubuntu,
you can run the following::

  sudo apt-get install gdb screen

You can then run the following script call::

  prefix=gdb_screen Scripts/<protocol>.sh ... -o throw_exceptions

This runs every party in the background using the screen utility. You
can get a party to the foreground using::

  screen -r :<partyno>

This will show the relevant running inside GDB. You can use the
sequence "Ctrl-a d" to return to your usual terminal.

If running the different parties separately, you can also use::

  . Scripts/run-common.sh
  gdb_front ./<protocol>-party.x ... -o throw_exceptions

If the virtual machine aborts due to an error, GDB will indicate where
in the code this happened. For example, deactivating all range checks
on memory accesses and then running an illegal memory access triggers
a segfault and the following output::

  Thread 13 "shamir-party.x" received signal SIGSEGV, Segmentation fault.
  [Switching to Thread 0x7fffdffff640 (LWP 246396)]
  0x0000000000434c57 in MemoryPart<ShamirShare<gfp_<0, 2> > >::indirect_read<StackedVector<Integer> > (this=<optimised out>, inst=..., regs=..., indices=...) at ./Processor/Memory.hpp:26
  26            *dest++ = data[it->get()];

Entering ``bt`` (for backtrace) gives even more information as to
where the error happened::

  (gdb) bt
  #0  0x0000000000434c57 in MemoryPart<ShamirShare<gfp_<0, 2> > >::indirect_read<StackedVector<Integer> > (this=<optimised out>, inst=..., regs=..., indices=...) at ./Processor/Memory.hpp:26
  #1  Program::execute<ShamirShare<gfp_<0, 2> >, ShamirShare<gf2n_long> > (this=0x620cc0, Proc=...) at ./Processor/Instruction.hpp:1486
  #2  0x0000000000428fd1 in thread_info<ShamirShare<gfp_<0, 2> >, ShamirShare<gf2n_long> >::Sub_Main_Func (this=<optimised out>, this@entry=0x656900) at ./Processor/Online-Thread.hpp:280
  #3  0x0000000000426e45 in thread_info<ShamirShare<gfp_<0, 2> >, ShamirShare<gf2n_long> >::Main_Func_With_Purge (this=0x656900) at ./Processor/Online-Thread.hpp:431
  #4  thread_info<ShamirShare<gfp_<0, 2> >, ShamirShare<gf2n_long> >::Main_Func (ptr=0x656900) at ./Processor/Online-Thread.hpp:410
  #5  0x00007ffff6bbaac3 in start_thread (arg=<optimised out>) at ./nptl/pthread_create.c:442
  #6  0x00007ffff6c4c850 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

This information can be very useful to find the error and fix bugs, so
make sure to include it in GitHub issues etc.
