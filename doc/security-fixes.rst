Security Fixes
==============


This section explains select security fixes and credits people who
have reported them.

Malicious parties are not committed to MAC key across threads and executions
----------------------------------------------------------------------------

MP-SPDZ used to read MAC key shares from a file if available and
regenerate the relevant oblivious transfer instances or homomorphic
encryptions at every run. For oblivious transfer, it even did so for
every computation thread. Sela Navot discovered that this opens the
possibility for malicious parties to generate valid shares with MAC
under different MAC keys between different threads or runs, opening
the possibility of selective failure attacks. The remedy is to only
generate OT instances or encryptions once for a fresh MAC key and then
store them on disk for future runs. This is done in
``Player-Data/<protocol>-Secrets-<parameters>-P<player>-<n_players>``.


Insufficient checks in Rep4
---------------------------

`Brüggemann and Schneider <https://eprint.iacr.org/2026/234>`_
discovered selective failure attacks in the MP-SPDZ implementation of
Rep4, which delayed consistency checks too much.


Co-ordinate MAC checks among threads and race condition in MAC checks
---------------------------------------------------------------------

`Kyster et al. <https://eprint.iacr.org/2025/789>`_ found selective
failure attacks if the result of computation in one thread would be
used in another before checking. See also "SPDZ Multi-Threaded MAC
Check" on `mpcsec.org <https://mpcsec.org>`_. A further related race
condition has been reported by Tadas Majorovas.


Remove MAC key in case of failure
---------------------------------

If a MAC check fails, the MAC key should not be used again.


Remotely caused buffer overflows
--------------------------------

MP-SPDZ generally sends length fields before data to allow the
receiver to allocate a buffer of the correct size. However, Guopeng
Lin found `instances <https://github.com/data61/MP-SPDZ/issues/1382>`_
where and adversary could send data that causes a buffer overflow on
the receiving side.


Missing shuffling check in PS mod 2^k and Brain
-----------------------------------------------

MP-SPDZ uses a class for every type of share and static variables
within these classes to indicate a protocol provides malicious
security. This variable is then used when there is a small difference
between semi-honest and malicious protocols, such as in the generic
secure shuffling protocol. The fact that this variable was incorrect
for a few share classes lead to a necessary check being skipped.


Insufficient drowning in pairwise protocols
-------------------------------------------

MP-SPDZ generates homomorphic encryption system parameters depending
on variable parameters such as how much randomness is used noise
drowning/flooding. An accidental reset to the default meant that any
larger parameter given would be ignored.


Proper accounting for random elements
-------------------------------------

When using preprocessing from files, MP-SPDZ uses the predicted number
of items to avoid using the item several times. There was an omission
in the account of random elements used in some opening protocols,
hence the potential for reuse.


Insufficient security in non-interactive zero-knowledge proofs
--------------------------------------------------------------

Sebastian Hasler pointed out that the default statistical security
parameter does not suffice in the non-interactive setting where the
adversary can try forging a proof without involving any other party.


Security bug in SPDZ2k
----------------------

Daniel Escudero has found a bug in the original SPDZ2k where only the
"payload bits" would be checked. This would lead to a high attack
probability. Sections 3.2-3.4 of the `updated
paper <https://eprint.iacr.org/2018/482>`_ describe the issue.


Skewed random bit generation
----------------------------

There was a bug in caching random bits such that every 64-th bit was
guaranteed to be zero. This was only discovered when it caused issues
with the initialization of machine learning models.


All-zero secret keys in homomorphic encryption
----------------------------------------------

An insufficient initialization and checking of homomorphic encryption
parameters lead to the generation of keys with Hamming weight 0.


Insufficient randomness in SemiBin random bit generation
--------------------------------------------------------

The usage of an intricate inheritance structure for convenience lead
to an assignment operation that would always assign zero.


Missing MAC key initialization
------------------------------

A missing initialization would lead to all MAC key shares for binary
computation being zero.
