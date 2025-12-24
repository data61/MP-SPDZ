"""
This module contains the building blocks of the compiler such as code
blocks and registers. Most relevant is the central :py:class:`Program`
object that holds various properties of the computation.
"""

import inspect
import itertools
import math
import os
import re
import sys
import hashlib
import random
from collections import defaultdict, deque
from functools import reduce

import Compiler.instructions
import Compiler.instructions_base
import Compiler.instructions_base as inst_base
from Compiler.config import REG_MAX, USER_MEM, COST, MEM_MAX
from Compiler.exceptions import CompilerError
from Compiler.instructions_base import RegType

from . import allocator as al
from . import util
from .papers import *
from .cost import expected_communication

data_types = dict(
    triple=0,
    square=1,
    bit=2,
    inverse=3,
    dabit=4,
    mixed=5,
    random=6,
    open=7,
)

field_types = dict(
    modp=0,
    gf2n=1,
    bit=2,
)


class defaults:
    debug = False
    verbose = False
    outfile = None
    ring = 0
    field = 0
    binary = 0
    garbled = False
    prime = None
    galois = 40
    budget = 1000
    mixed = False
    edabit = False
    invperm = False
    split = None
    cisc = True
    comparison = None
    merge_opens = True
    preserve_mem_order = False
    max_parallel_open = 0
    dead_code_elimination = False
    noreallocate = False
    asmoutfile = None
    stop = False
    insecure = False
    keep_cisc = False


class Program(object):
    """A program consists of a list of tapes representing the whole
    computation.

    When compiling an :file:`.mpc` file, the single instance is
    available as :py:obj:`program`. When compiling directly
    from Python code, an instance has to be created before running any
    instructions.
    """

    def __init__(self, args, options=defaults, name=None):
        from .non_linear import KnownPrime, Prime

        self.options = options
        self.verbose = options.verbose
        self.args = args
        self.name = name
        self.init_names(args)
        self._security = 40
        self.used_security = 0
        self.prime = None
        self.tapes = []
        if sum(x != 0 for x in (options.ring, options.field, options.binary)) > 1:
            raise CompilerError("can only use one out of -B, -R, -F")
        if options.prime and (options.ring or options.binary):
            raise CompilerError("can only use one out of -B, -R, -p")
        if options.ring:
            self.set_ring_size(int(options.ring))
        else:
            self.bit_length = int(options.binary) or int(options.field)
            if options.prime:
                self.prime = int(options.prime)
                print("WARNING: --prime/-P activates code that usually isn't "
                      "the most efficient variant. Consider using --field/-F "
                      "and set the prime only during the actual computation.")
                if not self.rabbit_gap() and self.prime > 2 ** 50:
                    print("The chosen prime is particularly inefficient. "
                          "Consider using a prime that is closer to a power "
                          "of two", end='')
                    try:
                        import gmpy2
                        bad_prime = self.prime
                        self.prime = 2 ** int(
                            round(math.log(self.prime, 2))) + 1
                        while True:
                            if self.prime > 2 ** 59:
                                # LWE compatibility
                                step = 2 ** 15
                            else:
                                step = 1
                            if self.prime < bad_prime:
                                self.prime += step
                            else:
                                self.prime -= step
                            if gmpy2.is_prime(self.prime):
                                break
                        assert self.rabbit_gap()
                        print(", for example, %d." % self.prime)
                        self.prime = bad_prime
                    except (ImportError, AssertionError):
                        self.prime = bad_prime
                        print(".")
                if options.execute:
                    print("Use '-- --prime <prime>' to specify the prime for "
                          "execution only.")
                max_bit_length = int(options.prime).bit_length() - 2
                if self.bit_length > max_bit_length:
                    raise CompilerError(
                        "integer bit length can be maximal %s" % max_bit_length
                    )
                from .types import sfix
                self.bit_length = self.bit_length or max_bit_length
                k = self.bit_length // 2
                f = int(math.ceil(k / 2))
                if k < sfix.k or f < sfix.f:
                    print("Reducing fixed-point precision to (%d, %d) "
                          "to match prime %d" % (f, k, self.prime))
                    sfix.set_precision(f, k)
                self.non_linear = KnownPrime(self.prime)
            else:
                self.non_linear = Prime()
                if not self.bit_length:
                    self.bit_length = 64
        print("Default bit length for compilation:", self.bit_length)
        if not (options.binary or options.garbled):
            print("Default security parameter for compilation:", self._security)
        self.galois_length = int(options.galois)
        if self.verbose:
            print("Galois length:", self.galois_length)
        self.tape_counter = 0
        self._curr_tape = None
        self.DEBUG = options.debug
        self.allocated_mem = RegType.create_dict(lambda: USER_MEM)
        self.free_mem_blocks = defaultdict(al.BlockAllocator)
        self.later_mem_blocks = defaultdict(list)
        self.allocated_mem_blocks = {}
        self.saved = 0
        self.req_num = None
        self.tape_stack = []
        self.n_threads = 1
        self.public_input_file = None
        self.types = {}
        if self.options.budget:
            self.budget = int(self.options.budget)
        else:
            if self.options.optimize_hard:
                self.budget = 100000
            else:
                self.budget = defaults.budget
        self.to_merge = [
            Compiler.instructions.asm_open_class,
            Compiler.instructions.gasm_open_class,
            Compiler.instructions.muls_class,
            Compiler.instructions.gmuls_class,
            Compiler.instructions.mulrs_class,
            Compiler.instructions.gmulrs,
            Compiler.instructions.dotprods_class,
            Compiler.instructions.gdotprods_class,
            Compiler.instructions.asm_input_class,
            Compiler.instructions.gasm_input_class,
            Compiler.instructions.inputfix_class,
            Compiler.instructions.inputfloat_class,
            Compiler.instructions.inputmixed_class,
            Compiler.instructions.trunc_pr_class,
            Compiler.instructions_base.Mergeable,
        ]
        import Compiler.GC.instructions as gc

        self.to_merge += [
            gc.ldmsdi,
            gc.stmsdi,
            gc.ldmsd,
            gc.stmsd,
            gc.stmsdci,
            gc.andrs,
            gc.ands,
            gc.inputb,
            gc.inputbvec,
            gc.reveal,
        ]
        self.use_trunc_pr = False
        """ Setting whether to use special probabilistic truncation. """
        self.use_dabit = options.mixed
        """ Setting whether to use daBits for non-linear functionality. """
        self._edabit = options.edabit
        """ Whether to use the low-level INVPERM instruction (only implemented with the assumption of a semi-honest two-party environment)"""
        self._invperm = options.invperm
        self._split = False
        if options.split:
            self.use_split([int(x) for x in options.split.split(",")])
        self._square = False
        self._always_raw = False
        self._linear_rounds = False
        self.warn_about_mem = [True]
        self.relevant_opts = set()
        self.n_running_threads = None
        self.input_files = {}
        self.base_addresses = util.dict_by_id()
        self._protect_memory = False
        self.mem_protect_stack = []
        self._always_active = True
        self.active = True
        self.prevent_breaks = False
        self.cisc_to_function = True
        if not self.options.cisc:
            self.options.cisc = not self.options.optimize_hard
        self.use_tape_calls = not options.garbled
        self.force_cisc_tape = False
        self.use_mulm = True
        self.have_warned_trunc_pr = False
        self.use_unsplit = False
        self.recommended = set()
        if self.options.papers:
            if self.options.execute:
                protocol = self.options.execute
                print("Recommended reading for %s: %s" % (
                    protocol, reading_for_protocol(protocol)))
            else:
                print("Use '--execute <protocol>' to see recommended reading "
                      "on the basic protocol.")
        if self.options.garbled:
            if not self.options.binary:
                raise CompilerError(
                    "You have to specify a default bit length using '--binary' "
                    "for garbled circuits.")
            self.optimize_for_gc()
        self.allow_tight_parameters = True
        self.warned_about_tightness = False
        self.warned_about_a2b = False

        Program.prog = self
        from . import comparison, instructions, instructions_base, types

        instructions.program = self
        instructions_base.program = self
        types.program = self
        comparison.program = self
        comparison.set_variant(options)

    def get_args(self):
        return self.args

    def max_par_tapes(self):
        """Upper bound on number of tapes that will be run in parallel.
        (Excludes empty tapes)"""
        return self.n_threads

    def init_names(self, args):
        self.programs_dir = "Programs"
        if self.verbose:
            print("Compiling program in", self.programs_dir)

        for dirname in (self.programs_dir, "Player-Data"):
            if not os.path.exists(dirname):
                os.mkdir(dirname)

        # create extra directories if needed
        for dirname in ["Public-Input", "Bytecode", "Schedules", "Functions"]:
            if not os.path.exists(self.programs_dir + "/" + dirname):
                os.mkdir(self.programs_dir + "/" + dirname)

        if self.name is None:
            self.name = args[0].split("/")[-1]
            exts = ".mpc", ".py"
            for ext in exts:
                if self.name.endswith(ext):
                    self.name = self.name[:-len(ext)]

            infiles = [args[0]]
            for x in (self.programs_dir, sys.path[0] + "/Programs"):
                for ext in exts:
                    filename = args[0]
                    if not filename.endswith(ext):
                        filename += ext
                    filename = x + "/Source/" + filename
                    if os.path.abspath(filename) not in \
                       [os.path.abspath(f) for f in infiles]:
                        infiles += [filename]
            existing = [f for f in infiles if os.path.exists(f)]
            if len(existing) == 1:
                self.infile = existing[0]
            elif len(existing) > 1:
                raise CompilerError("ambiguous input files: " +
                                    ", ".join(existing))
            else:
                raise CompilerError(
                    "found none of the potential input files: " +
                    ", ".join("'%s'" % x for x in infiles))
        """
        self.name is input file name (minus extension) + any optional arguments.
        Used to generate output filenames
        """
        if self.options.outfile:
            self.name = self.options.outfile + "-" + self.name
        else:
            self.name = self.name
        if len(args) > 1:
            self.name += "-" + "-".join(re.sub("/", "_", arg) for arg in args[1:])

    def set_ring_size(self, ring_size):
        from .non_linear import Ring

        for tape in self.tapes:
            prev = tape.req_bit_length["p"]
            if prev and prev != ring_size:
                raise CompilerError("cannot have different ring sizes")
        self.bit_length = ring_size - 1
        self.non_linear = Ring(ring_size)
        self.options.ring = str(ring_size)

    def new_tape(self, function, args=[], name=None, single_thread=False,
                 finalize=True, **kwargs):
        """
        Create a new tape from a function. See
        :py:func:`~Compiler.library.multithread` and
        :py:func:`~Compiler.library.for_range_opt_multithread` for
        easier-to-use higher-level functionality. The following runs
        two threads defined by two different functions::

            def f():
                ...
            def g():
                ...
            tapes = [program.new_tape(x) for x in (f, g)]
            thread_numbers = program.run_tapes(tapes)
            program.join_tapes(threads_numbers)

        :param function: Python function defining the thread
        :param args: arguments to the function
        :param name: name used for files
        :param single_thread: Boolean indicating whether tape will
            never be run in parallel to itself
        :returns: tape handle

        """
        if name is None:
            name = function.__name__
        name = "%s-%s" % (self.name, name)
        # make sure there is a current tape
        self.curr_tape
        tape_index = len(self.tapes)
        self.tape_stack.append(self.curr_tape)
        self.curr_tape = Tape(name, self, **kwargs)
        self.curr_tape.singular = single_thread
        self.tapes.append(self.curr_tape)
        function(*args)
        if finalize:
            self.finalize_tape(self.curr_tape)
        if self.tape_stack:
            self.curr_tape = self.tape_stack.pop()
        return tape_index

    def run_tape(self, tape_index, arg):
        return self.run_tapes([[tape_index, arg]])[0]

    def run_tapes(self, args):
        """Run tapes in parallel. See :py:func:`new_tape` for an example.

        :param args: list of tape handles or tuples of tape handle and extra
            argument (for :py:func:`~Compiler.library.get_arg`)
        :returns: list of thread numbers
        """
        if not self.curr_tape.singular:
            raise CompilerError(
                "Compiler does not support " "recursive spawning of threads"
            )
        args = [list(util.tuplify(arg)) for arg in args]
        singular_tapes = set()
        for arg in args:
            if self.tapes[arg[0]].singular:
                if arg[0] in singular_tapes:
                    raise CompilerError("cannot run singular tape in parallel")
                singular_tapes.add(arg[0])
            assert len(arg)
            assert len(arg) <= 2
            if len(arg) == 1:
                arg += [0]
        thread_numbers = []
        while len(thread_numbers) < len(args):
            free_threads = self.curr_tape.free_threads
            self.curr_tape.ran_threads = True
            if free_threads:
                thread_numbers.append(min(free_threads))
                free_threads.remove(thread_numbers[-1])
            else:
                thread_numbers.append(self.n_threads)
                self.n_threads += 1
        self.curr_tape.start_new_basicblock(name="pre-run_tape")
        Compiler.instructions.run_tape(
            *sum(([x] + list(y) for x, y in zip(thread_numbers, args)), [])
        )
        self.curr_tape.start_new_basicblock(name="post-run_tape")
        for arg in args:
            self.curr_block.req_node.children.append(
                self.tapes[arg[0]].req_tree)
        return thread_numbers

    def join_tape(self, thread_number):
        self.join_tapes([thread_number])

    def join_tapes(self, thread_numbers):
        """Wait for completion of tapes.  See :py:func:`new_tape` for an example.

        :param thread_numbers: list of thread numbers
        """
        self.curr_tape.start_new_basicblock(name="pre-join_tape")
        for thread_number in thread_numbers:
            Compiler.instructions.join_tape(thread_number)
            self.curr_tape.free_threads.add(thread_number)
        self.curr_tape.start_new_basicblock(name="post-join_tape")

    def update_req(self, tape):
        if self.req_num is None:
            self.req_num = tape.req_num
        else:
            self.req_num += tape.req_num

    def required_bit_length(self, t):
        return max(x.req_bit_length[t] for x in self.tapes)

    def write_bytes(self):

        """Write all non-empty threads and schedule to files."""

        nonempty_tapes = [t for t in self.tapes]

        sch_filename = self.programs_dir + "/Schedules/%s.sch" % self.name
        sch_file = open(sch_filename, "w")
        print("Writing to", sch_filename)
        sch_file.write(str(self.max_par_tapes()) + "\n")
        sch_file.write(str(len(nonempty_tapes)) + "\n")
        sch_file.write(" ".join("%s:%d" % (tape.name, len(tape))
                                for tape in nonempty_tapes) + "\n")
        sch_file.write("1 0\n")
        sch_file.write("0\n")
        sch_file.write(" ".join(sys.argv) + "\n")
        req = self.required_bit_length("p")
        if self.options.ring:
            sch_file.write("R:%s" % self.options.ring)
        elif self.options.prime:
            sch_file.write("p:%s" % self.options.prime)
        else:
            sch_file.write("lgp:%s" % req)
        sch_file.write("\n")
        sch_file.write("opts: %s\n" % " ".join(self.relevant_opts))
        sch_file.write("sec:%d\n" % self.used_security)
        req2 = set(x.req_bit_length["2"] for x in self.tapes)
        req2.add(0)
        assert len(req2) <= 2
        if req2:
            sch_file.write("lg2:%s" % max(req2))
        sch_file.write("\n")
        exp = self.expected_communication()
        if exp:
            sch_file.write(
                "online:%d offline:%d n_parties:%d\n" % (
                    exp.sanitize() + (exp.n_parties,)))
        else:
            sch_file.write('no expections\n')
        sch_file.close()
        h = hashlib.sha256()
        for tape in self.tapes:
            tape.write_bytes()
            h.update(tape.hash)
        print('Hash:', h.hexdigest())

    def finalize_tape(self, tape):
        if not tape.purged:
            curr_tape = self.curr_tape
            self.curr_tape = tape
            tape.optimize(self.options)
            self.curr_tape = curr_tape
            tape.write_bytes()
            if self.options.asmoutfile:
                tape.write_str(self.options.asmoutfile + "-" + tape.name)
            tape.purge()

    @property
    def curr_tape(self):
        """The tape that is currently running."""
        if self._curr_tape is None:
            assert not self.tapes
            self._curr_tape = Tape(self.name, self)
            self.tapes.append(self._curr_tape)
        return self._curr_tape

    @curr_tape.setter
    def curr_tape(self, value):
        self._curr_tape = value

    @property
    def curr_block(self):
        """The basic block that is currently being created."""
        return self.curr_tape.active_basicblock

    def malloc(self, size, mem_type, reg_type=None, creator_tape=None, use_freed=True):
        """Allocate memory from the top"""
        if not isinstance(size, int):
            raise CompilerError("size must be known at compile time")
        if size == 0:
            return
        if isinstance(mem_type, type):
            try:
                size *= math.ceil(mem_type.n / mem_type.unit)
            except AttributeError:
                pass
            self.types[mem_type.reg_type] = mem_type
            mem_type = mem_type.reg_type
        elif reg_type is not None:
            self.types[mem_type] = reg_type
        single_size = None
        if not (creator_tape or self.curr_tape).singular:
            if self.n_running_threads:
                single_size = size
                size *= self.n_running_threads
            else:
                raise CompilerError("cannot allocate memory " "outside main thread")
        blocks = self.free_mem_blocks[mem_type]
        addr = blocks.pop(size) if use_freed else None
        if addr is not None:
            self.saved += size
        else:
            addr = self.allocated_mem[mem_type]
            self.allocated_mem[mem_type] += size
            if len(str(addr)) != len(str(addr + size)) and self.verbose:
                print("Memory of type '%s' now of size %d" % (mem_type, addr + size))
            if addr + size >= MEM_MAX:
                raise CompilerError(
                    "allocation exceeded for type '%s' after adding %d" % \
                    (mem_type, size))
        self.allocated_mem_blocks[addr, mem_type] = size, self.curr_block.alloc_pool
        if single_size:
            from .library import get_arg, runtime_error_if
            bak = self.curr_tape.active_basicblock
            self.curr_tape.active_basicblock = self.curr_tape.basicblocks[0]
            arg = get_arg()
            runtime_error_if(arg >= self.n_running_threads, "malloc")
            res = addr + single_size * arg
            self.curr_tape.active_basicblock = bak
            self.base_addresses[res] = addr
            return res
        else:
            return addr

    def free(self, addr, mem_type):
        """Free memory"""
        now = True
        if not util.is_constant(addr):
            addr = self.base_addresses[addr]
            now = self.curr_tape == self.tapes[0]
        size, pool = self.allocated_mem_blocks[addr, mem_type]
        if self.curr_block.alloc_pool is not pool:
            raise CompilerError("Cannot free memory across function blocks")
        self.allocated_mem_blocks.pop((addr, mem_type))
        if now:
            self.free_mem_blocks[mem_type].push(addr, size)
        else:
            self.later_mem_blocks[mem_type].append((addr, size))

    def free_later(self):
        for mem_type in self.later_mem_blocks:
            for block in self.later_mem_blocks[mem_type]:
                self.free_mem_blocks[mem_type].push(*block)
        self.later_mem_blocks.clear()

    def finalize(self):
        # optimize the tapes
        for tape in self.tapes:
            tape.optimize(self.options)

        if self.tapes:
            self.update_req(self.curr_tape)

        # finalize the memory
        self.finalize_memory()

        # communicate protocol compability
        Compiler.instructions.active(self._always_active)

        # communicate mulm usage to VM
        if self.use_mulm != 1:
            self.relevant_opts.add("no_mulm")

        self.write_bytes()

        if self.options.asmoutfile:
            for tape in self.tapes:
                tape.write_str(self.options.asmoutfile + "-" + tape.name)

        # Making sure that the public_input_file has been properly closed
        if self.public_input_file is not None:
            self.public_input_file.close()

    def finalize_memory(self):
        self.curr_tape.start_new_basicblock(None, "memory-usage",
                                            req_node=self.curr_tape.req_tree)
        # reset register counter to 0
        if not self.options.noreallocate:
            self.curr_tape.init_registers()
        for mem_type, size in sorted(self.allocated_mem.items()):
            if size and (not self.options.garbled or \
                         mem_type not in ('s', 'sg', 'c', 'cg')):
                # print "Memory of type '%s' of size %d" % (mem_type, size)
                if mem_type in self.types:
                    self.types[mem_type].load_mem(size - 1, mem_type)
                else:
                    from Compiler.types import _get_type

                    _get_type(mem_type).load_mem(size - 1, mem_type)
        if self.verbose:
            if self.saved:
                print("Saved %s memory units through reallocation" % self.saved)

    def public_input(self, x):
        """Append a value to the public input file."""
        if self.public_input_file is None:
            self.public_input_file = open(
                self.programs_dir + "/Public-Input/%s" % self.name, "w"
            )
        self.public_input_file.write("%s\n" % str(x))

    def get_binary_input_file(self, player):
        key = player, 'bin'
        if key not in self.input_files:
            filename = 'Player-Data/Input-Binary-P%d-0' % player
            print('Writing binary data to', filename)
            self.input_files[key] = open(filename, 'wb')
        return self.input_files[key]

    def set_bit_length(self, bit_length):
        """Change the integer bit length for non-linear functions."""
        self.bit_length = bit_length
        print("Changed bit length for comparisons etc. to", bit_length)

    def set_security(self, security):
        changed = self._security != security
        self._security = security
        if changed:
            print("Changed statistical security for comparison etc. to",
                  security)

    @property
    def security(self):
        """The statistical security parameter for non-linear
        functions."""
        self.used_security = max(self.used_security, self._security)
        return self._security

    @security.setter
    def security(self, security):
        self.set_security(security)

    def optimize_for_gc(self):
        import Compiler.GC.instructions as gc
        self.to_merge += [gc.xors]

    def get_tape_counter(self):
        res = self.tape_counter
        self.tape_counter += 1
        return res

    @property
    def use_trunc_pr(self):
        if not self._use_trunc_pr:
            self.relevant_opts.add("trunc_pr")
        return self._use_trunc_pr

    @use_trunc_pr.setter
    def use_trunc_pr(self, change):
        self._use_trunc_pr = change

    def trunc_pr_warning(self):
        if not self.have_warned_trunc_pr:
            print("WARNING: Probabilistic truncation leaks some information, "
                  "see https://eprint.iacr.org/2024/1127 for discussion. "
                  "Use 'sfix.round_nearest = True' to deactivate this for "
                  "fixed-point operations.")
        self.have_warned_trunc_pr = True

    def use_edabit(self, change=None):
        """Setting whether to use edaBits for non-linear
        functionality (default: false).

        :param change: change setting if not :py:obj:`None`
        :returns: setting if :py:obj:`change` is :py:obj:`None`
        """
        if change is None:
            if not self._edabit:
                self.relevant_opts.add("edabit")
            return self._edabit
        else:
            self._edabit = change

    def use_invperm(self, change=None):
        """ Set whether to use the low-level INVPERM instruction to inverse a permutation (see sint.inverse_permutation). The INVPERM instruction assumes a semi-honest two-party environment. If false, a general protocol implemented in the high-level language is used.

        :param change: change setting if not :py:obj:`None`
        :returns: setting if :py:obj:`change` is :py:obj:`None`
        """
        if change is None:
            if not self._invperm:
                self.relevant_opts.add("invperm")
            return self._invperm
        else:
            self._invperm = change


    def use_edabit_for(self, *args):
        return True

    def use_split(self, change=None):
        """Setting whether to use local arithmetic-binary share
        conversion for non-linear functionality (default: false).

        :param change: change setting if not :py:obj:`None`
        :returns: setting if :py:obj:`change` is :py:obj:`None`
        """
        if change is None:
            if self._split:
                return self._split[0]
            else:
                self.relevant_opts.add("split")
                return False
        else:
            if change and not self.options.ring:
                raise CompilerError("splitting only supported for rings")
            if change:
                self._split = util.tuplify(change)
                for x in self._split:
                    assert x > 1
            else:
                self._split = ()

    def used_splits(self):
        return self._split

    def have_a2b(self):
        if self.use_split() or self.use_edabit() or self.use_dabit:
            return True
        if not self.warned_about_a2b:
            print(
                'WARNING: No option selected for A2B conversion, defaulting '
                'to edaBits. Use -X/-Y/-Z to get rid of this warning.')
            self.warned_about_a2b = True

    def use_square(self, change=None):
        """Setting whether to use preprocessed square tuples
        (default: false).

        :param change: change setting if not :py:obj:`None`
        :returns: setting if :py:obj:`change` is :py:obj:`None`
        """
        if change is None:
            return self._square
        else:
            self._square = change

    def always_raw(self, change=None):
        if change is None:
            return self._always_raw
        else:
            self._always_raw = change

    def linear_rounds(self, change=None):
        if change is None:
            return self._linear_rounds
        else:
            self._linear_rounds = change

    def options_from_args(self):
        """Set a number of options from the command-line arguments."""
        if "trunc_pr" in self.args:
            self.use_trunc_pr = True
        if "signed_trunc_pr" in self.args:
            self.use_trunc_pr = -1
        if "trunc_pr20" in self.args:
            self.use_trunc_pr = 20
        if "split" in self.args or "split3" in self.args:
            self.use_split(3)
        for arg in self.args:
            m = re.match("split([0-9]+)", arg)
            if m:
                self.use_split(int(m.group(1)))
            m = re.match("unsplit([0-9]+)", arg)
            if m:
                self.use_unsplit = int(m.group(1))
        if "raw" in self.args:
            self.always_raw(True)
        if "edabit" in self.args:
            self.use_edabit(True)
        if "invperm" in self.args:
            self.use_invperm(True)
        if "linear_rounds" in self.args:
            self.linear_rounds(True)
        if "back_mulm" in self.args:
            self.use_mulm = -1

    def disable_memory_warnings(self):
        self.warn_about_mem.append(False)
        self.curr_block.warn_about_mem = False

    def protect_memory(self, status):
        """ Enable or disable memory protection. """
        self._protect_memory = status

    def open_memory_scope(self, key=None):
        self.mem_protect_stack.append(self._protect_memory)
        self.protect_memory(key or object())

    def close_memory_scope(self):
        self.protect_memory(self.mem_protect_stack.pop())

    def use_cisc(self):
        return self.options.cisc and (not self.prime or self.rabbit_gap()) \
            and not self.options.max_parallel_open

    def rabbit_gap(self):
        assert self.prime
        p = self.prime
        logp = int(round(math.log(p, 2)))
        return abs(p - 2 ** logp) / p < 2 ** -self.security

    @property
    def active(self):
        """ Whether to use actively secure protocols. """
        return self._active

    @active.setter
    def active(self, change):
        self._always_active &= change
        self._active = change

    def semi_honest(self):
        self._always_active = False

    @staticmethod
    def read_schedule(schedule):
        m = re.search(r"([^/]*)\.mpc", schedule)
        if m:
            schedule = m.group(1)
        if not os.path.exists(schedule):
            schedule = "Programs/Schedules/%s.sch" % schedule

        try:
            return open(schedule).readlines()
        except FileNotFoundError:
            print(
                "%s not found, have you compiled the program?" % schedule,
                file=sys.stderr,
            )
            sys.exit(1)

    @classmethod
    def read_tapes(cls, schedule):
        lines = cls.read_schedule(schedule)
        for tapename in lines[2].split(" "):
            yield tapename.strip().split(":")[0]

    @classmethod
    def read_n_threads(cls, schedule):
        return int(cls.read_schedule(schedule)[0])

    @classmethod
    def read_domain_size(cls, schedule):
        from Compiler.instructions import reqbl_class
        tapename = cls.read_schedule(schedule)[2].strip().split(":")[0]
        for inst in Tape.read_instructions(tapename):
            if inst.code == reqbl_class.code:
                bl = inst.args[0]
                return (abs(bl.i) + 63) // 64 * 8

    def reading(self, concept, reference, part=None):
        key = concept, reference, part
        if self.options.papers and key not in self.recommended:
            if isinstance(reference, tuple):
                assert part is None
                reference = ', '.join(papers.get(x) or x for x in reference)
            suffix = ' (%s)' % part or ''
            print('Recommended reading on %s: %s%s' % (
                concept, papers.get(reference) or reference, suffix))
            self.recommended.add(key)

    def expected_communication(self):
        if self.options.ring:
            bit_length = int(self.options.ring)
        elif self.options.prime:
            bit_length = self.prime.bit_length()
        else:
            # check against OnlineOptions.cpp
            bit_length = max(self.required_bit_length("p"), 128)
            bit_length = int(math.ceil(bit_length / 64) * 64)
        length = int(math.ceil(bit_length / 8))
        return expected_communication(
            self.options.execute, self.req_num or Tape.ReqNum(), length)

class Tape:
    """A tape contains a list of basic blocks, onto which instructions are added."""

    def __init__(self, name, program, thread_pool=None):
        """Set prime p and the initial instructions and registers."""
        self.program = program
        name += "-%d" % program.get_tape_counter()
        self.init_names(name)
        self.init_registers()
        self.req_tree = self.ReqNode(name)
        self.basicblocks = []
        self.purged = False
        self.block_counter = 0
        self.active_basicblock = None
        self.old_allocated_mem = program.allocated_mem.copy()
        self.start_new_basicblock(req_node=self.req_tree)
        self._is_empty = False
        self.merge_opens = True
        self.if_states = []
        self.req_bit_length = defaultdict(lambda: 0)
        self.bit_length_reason = None
        self.function_basicblocks = {}
        self.functions = []
        self.singular = True
        self.free_threads = set() if thread_pool is None else thread_pool
        self.loop_breaks = []
        self.warned_about_mem = False
        self.return_values = []
        self.ran_threads = False
        self.unused_decorators = {}

    class BasicBlock(object):
        def __init__(self, parent, name, scope, exit_condition=None,
                     req_node=None):
            self.parent = parent
            self.instructions = []
            self.name = name
            self.open_queue = []
            self.exit_condition = exit_condition
            self.exit_block = None
            self.previous_block = None
            self.scope = scope
            self.children = []
            if scope is not None:
                scope.children.append(self)
                self.alloc_pool = scope.alloc_pool
            else:
                self.alloc_pool = al.AllocPool()
            self.purged = False
            self.n_rounds = 0
            self.n_to_merge = 0
            self.rounds = Tape.ReqNum()
            self.warn_about_mem = parent.program.warn_about_mem[-1]
            self.req_node = req_node
            self.used_from_scope = set()

        def __len__(self):
            return len(self.instructions)

        def new_reg(self, reg_type, size=None):
            return self.parent.new_reg(reg_type, size=size)

        def set_return(self, previous_block, sub_block):
            self.previous_block = previous_block
            self.sub_block = sub_block

        def adjust_return(self):
            offset = self.sub_block.get_offset(self)
            self.previous_block.return_address_store.args[1] = offset

        def set_exit(self, condition, exit_true=None):
            """Sets the block which we start from next, depending on the condition.

            (Default is to go to next block in the list)
            """
            self.exit_condition = condition
            self.exit_block = exit_true
            for reg in condition.get_used():
                reg.can_eliminate = False

        def add_jump(self):
            """Add the jump for this block's exit condition to list of
            instructions (must be done after merging)"""
            self.instructions.append(self.exit_condition)

        def get_offset(self, next_block):
            return next_block.offset - (self.offset + len(self.instructions))

        def adjust_jump(self):
            """Set the correct relative jump offset"""
            offset = self.get_offset(self.exit_block)
            self.exit_condition.set_relative_jump(offset)

        def purge(self, retain_usage=True):
            def relevant(inst):
                req_node = Tape.ReqNode("")
                req_node.num = Tape.ReqNum()
                inst.add_usage(req_node)
                return req_node.num != {}

            if retain_usage:
                self.usage_instructions = list(filter(relevant, self.instructions))
            else:
                self.usage_instructions = []
            if len(self.usage_instructions) > 1000 and \
               self.parent.program.verbose:
                print("Retaining %d instructions" % len(self.usage_instructions))
            del self.instructions
            self.purged = True

        def add_usage(self, req_node):
            if self.purged:
                instructions = self.usage_instructions
            else:
                instructions = self.instructions
            for inst in instructions:
                inst.add_usage(req_node)
            req_node.num["all", "round"] += self.n_rounds
            req_node.num["all", "inv"] += self.n_to_merge
            req_node.num += self.rounds

        def expand_cisc(self):
            if self.parent.program.options.keep_cisc is not None:
                skip = ["LTZ", "Trunc", "EQZ"]
                skip += self.parent.program.options.keep_cisc.split(",")
            else:
                skip = []
            tape = self.parent
            tape.start_new_basicblock(scope=self.scope, req_node=self.req_node,
                                      name="cisc")
            start_block = tape.basicblocks[-1]
            start_block.alloc_pool = self.alloc_pool
            for inst in self.instructions:
                inst.expand_merged(skip)
            self.instructions = tape.active_basicblock.instructions
            if start_block == tape.basicblocks[-1]:
                res = self
            else:
                res = start_block
            tape.basicblocks[-1] = self
            return res

        def replace_last_reg(self, new_reg, last_reg):
            args = self.instructions[-1].args
            if args[0] is last_reg:
                args[0] = new_reg
            else:
                new_reg.mov(new_reg, new_reg.conv(last_reg))

        def __str__(self):
            return self.name

    def is_empty(self):
        """Returns True if the list of basic blocks is empty.

        Note: False is returned even when tape only contains basic
        blocks with no instructions. However, these are removed when
        optimize is called."""
        if not self.purged:
            self._is_empty = len(self.basicblocks) == 0
        return self._is_empty

    def start_new_basicblock(self, scope=False, name="", req_node=None):
        assert not self.program.prevent_breaks
        if self.program.verbose and self.active_basicblock and \
           self.program.allocated_mem != self.old_allocated_mem:
            print("New allocated memory in %s " % self.active_basicblock.name,
                  end="")
            for t, n in self.program.allocated_mem.items():
                if n != self.old_allocated_mem[t]:
                    print("%s:%d " % (t, n - self.old_allocated_mem[t]), end="")
            print()
            self.old_allocated_mem = self.program.allocated_mem.copy()
        # use False because None means no scope
        if scope is False:
            scope = self.active_basicblock
        suffix = "%s-%d" % (name, self.block_counter)
        self.block_counter += 1
        if req_node is None:
            req_node = self.active_basicblock.req_node
        sub = self.BasicBlock(self, self.name + "-" + suffix, scope,
                              req_node=req_node)
        self.basicblocks.append(sub)
        self.active_basicblock = sub
        # print 'Compiling basic block', sub.name

    def init_registers(self):
        self.reg_counter = RegType.create_dict(lambda: 0)

    def init_names(self, name):
        self.name = name
        self.outfile = self.program.programs_dir + "/Bytecode/" + self.name + ".bc"

    def __len__(self):
        if self.purged:
            return self.size
        else:
            return sum(len(block) for block in self.basicblocks)

    def purge(self):
        self.size = len(self)
        for block in self.basicblocks:
            block.purge()
        self._is_empty = len(self.basicblocks) == 0
        del self.basicblocks
        del self.active_basicblock
        self.purged = True

    def unpurged(function):
        def wrapper(self, *args, **kwargs):
            if self.purged:
                return
            return function(self, *args, **kwargs)

        return wrapper

    @unpurged
    def optimize(self, options):
        if len(self.basicblocks) == 0:
            print("Tape %s is empty" % self.name)
            return

        if self.if_states:
            print("Tracebacks for open blocks:")
            for state in self.if_states:
                try:
                    print(util.format_trace(state.caller))
                except AttributeError:
                    pass
            print()
            raise CompilerError("Unclosed if/else blocks, see tracebacks above")

        if self.unused_decorators:
            raise CompilerError("Unused branching decorators, make sure to write " + ",".join(
                "'@%s' instead of '%s'" % (x, x) for x in set(self.unused_decorators.values())))

        if self.program.verbose:
            print(
                "Processing tape", self.name, "with %d blocks" % len(self.basicblocks)
            )

        for block in self.basicblocks:
            al.determine_scope(block, options)

        # merge open instructions
        # need to do this if there are several blocks
        if (options.merge_opens and self.merge_opens) or options.dead_code_elimination:
            for i, block in enumerate(self.basicblocks):
                if len(block.instructions) > 0 and self.program.verbose:
                    print(
                        "Processing basic block %s, %d/%d, %d instructions"
                        % (
                            block.name,
                            i,
                            len(self.basicblocks),
                            len(block.instructions),
                        )
                    )
                # the next call is necessary for allocation later even without merging
                merger = al.Merger(block, options, tuple(self.program.to_merge))
                if options.dead_code_elimination:
                    if len(block.instructions) > 1000000:
                        print("Eliminate dead code...")
                    merger.eliminate_dead_code()
                else:
                    merger.eliminate_dead_code(only_ldint=True)
                if options.merge_opens and self.merge_opens:
                    if len(block.instructions) == 0:
                        block.used_from_scope = util.set_by_id()
                        continue
                    if len(block.instructions) > 1000000:
                        print("Merging instructions...")
                    numrounds = merger.longest_paths_merge()
                    block.n_rounds = numrounds
                    block.n_to_merge = len(merger.open_nodes)
                    if options.verbose:
                        block.rounds = merger.req_num
                    if merger.counter and self.program.verbose:
                        print(
                            "Block requires",
                            ", ".join(
                                "%d %s" % (y, x.__name__)
                                for x, y in list(merger.counter.items())
                            ),
                        )
                    if merger.counter and self.program.verbose:
                        print(
                            "Block requires %s rounds"
                            % ", ".join(
                                "%d %s" % (y, x.__name__)
                                for x, y in list(merger.rounds.items())
                            )
                        )
                # free memory
                merger = None
                block.instructions = [
                    x for x in block.instructions if x is not None
                ]
        if not (options.merge_opens and self.merge_opens):
            print("Not merging instructions in tape %s" % self.name)

        if options.cisc:
            self.expand_cisc()

        # add jumps
        offset = 0
        for block in self.basicblocks:
            if block.exit_condition is not None:
                block.add_jump()
            block.offset = offset
            offset += len(block.instructions)
        for block in self.basicblocks:
            if block.exit_block is not None:
                block.adjust_jump()
            if block.previous_block is not None:
                block.adjust_return()

        # now remove any empty blocks (must be done after setting jumps)
        self.basicblocks = [x for x in self.basicblocks if len(x.instructions) != 0]

        # allocate registers
        reg_counts = self.count_regs()
        if options.noreallocate:
            if self.program.verbose:
                print("Tape register usage:", dict(reg_counts))
        else:
            if self.program.verbose:
                print("Tape register usage before re-allocation:", dict(reg_counts))
                print(
                    "modp: %d clear, %d secret"
                    % (reg_counts[RegType.ClearModp], reg_counts[RegType.SecretModp])
                )
                print(
                    "GF2N: %d clear, %d secret"
                    % (reg_counts[RegType.ClearGF2N], reg_counts[RegType.SecretGF2N])
                )
                print("Re-allocating...")
            allocator = al.StraightlineAllocator(REG_MAX, self.program)

            # make addresses available in functions
            for addr in self.program.base_addresses:
                if addr.program == self and self.basicblocks:
                    allocator.alloc_reg(addr, self.basicblocks[-1].alloc_pool)

            for reg in self.return_values:
                allocator.alloc_reg(reg, self.basicblocks[-1].alloc_pool)

            seen = set()

            def alloc(block):
                allocator.update_usage(block.alloc_pool)
                for reg in sorted(
                    block.used_from_scope, key=lambda x: (x.reg_type, x.i)
                ):
                    allocator.alloc_reg(reg, block.alloc_pool)
                seen.add(block)

            def alloc_loop(block):
                left = deque([block])
                while left:
                    block = left.popleft()
                    alloc(block)
                    for child in block.children:
                        if child not in seen:
                            left.append(child)

            allocator.old_pool = None
            for i, block in enumerate(reversed(self.basicblocks)):
                if len(block.instructions) > 1000000:
                    print(
                        "Allocating %s, %d/%d" % (block.name, i, len(self.basicblocks))
                    )
                if block.exit_condition is not None:
                    jump = block.exit_condition.get_relative_jump()
                    if (
                        isinstance(jump, int)
                        and jump < 0
                        and block.exit_block.scope is not None
                    ):
                        alloc_loop(block.exit_block.scope)
                usage = allocator.max_usage.copy()
                allocator.process(block.instructions, block.alloc_pool)
                if self.program.verbose and usage != allocator.max_usage:
                    print("Allocated registers in %s " % block.name, end="")
                    for t, n in allocator.max_usage.items():
                        if n > usage[t]:
                            print("%s:%d " % (t, n - usage[t]), end="")
                    print()
            allocator.finalize(options)
            if self.program.verbose:
                print("Tape register usage:", dict(allocator.max_usage))
                scopes = set(block.alloc_pool for block in self.basicblocks)
                n_fragments = sum(scope.n_fragments() for scope in scopes)
                print("%d register fragments in %d scopes" % (n_fragments, len(scopes)))

        # offline data requirements
        if self.program.verbose:
            print("Compile offline data requirements...")
        for block in self.basicblocks:
            block.req_node.add_block(block)
        self.req_num = self.req_tree.aggregate()
        if self.program.verbose:
            print("Tape requires", self.req_num)
        for req, num in sorted(self.req_num.items()):
            if num == float("inf") or num >= 2**64:
                num = -1
            if req[1] in data_types:
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use(
                        field_types[req[0]], data_types[req[1]], num, add_to_prog=False
                    )
                )
            elif req[1] == "input":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use_inp(
                        field_types[req[0]], req[2], num, add_to_prog=False
                    )
                )
            elif req[0] == "modp" and req[1] == "prep":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use_prep(req[2], num, add_to_prog=False)
                )
            elif req[0] == "gf2n" and req[1] == "prep":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.guse_prep(req[2], num, add_to_prog=False)
                )
            elif req[0] == "edabit":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use_edabit(
                        False, req[1], num, add_to_prog=False
                    )
                )
            elif req[0] == "sedabit":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use_edabit(
                        True, req[1], num, add_to_prog=False
                    )
                )
            elif req[0] == "matmul":
                self.basicblocks[-1].instructions.append(
                    Compiler.instructions.use_matmul(*req[1], num, add_to_prog=False)
                )

        if not self.is_empty():
            # bit length requirement
            from Compiler.instructions import reqbl, greqbl
            for x, inst in (("p", reqbl), ("2", greqbl)):
                if self.req_bit_length[x]:
                    bl = self.req_bit_length[x]
                    if self.program.options.ring:
                        bl = -int(self.program.options.ring)
                    self.basicblocks[-1].instructions.append(
                        inst(bl, add_to_prog=False)
                    )
            if self.program.verbose:
                print("Tape requires prime bit length",
                      self.req_bit_length["p"],
                      ('for %s' % self.bit_length_reason
                       if self.bit_length_reason else ''))
                print("Tape requires galois bit length", self.req_bit_length["2"])

    @unpurged
    def expand_cisc(self):
        mapping = {None: None}
        blocks = self.basicblocks[:]
        self.basicblocks = []
        for block in blocks:
            expanded = block.expand_cisc()
            mapping[block] = expanded
        for block in self.basicblocks:
            if block not in mapping:
                mapping[block] = block
        for block in self.basicblocks:
            block.exit_block = mapping[block.exit_block]
            if block.exit_block is not None:
                assert block.exit_block in self.basicblocks
            if block.previous_block and mapping[block] != block:
                mapping[block].previous_block = block.previous_block
                mapping[block].sub_block = block.sub_block
                block.previous_block = None
                del block.sub_block

    @unpurged
    def _get_instructions(self):
        return itertools.chain.from_iterable(b.instructions for b in self.basicblocks)

    @unpurged
    def get_encoding(self):
        """Get the encoding of the program, in human-readable format."""
        return [i.get_encoding() for i in self._get_instructions() if i is not None]

    @unpurged
    def get_bytes(self):
        """Get the byte encoding of the program as an actual string of bytes."""
        return b"".join(
            i.get_bytes() for i in self._get_instructions() if i is not None
        )

    @unpurged
    def write_encoding(self, filename):
        """Write the readable encoding to a file."""
        print("Writing to", filename)
        f = open(filename, "w")
        for line in self.get_encoding():
            f.write(str(line) + "\n")
        f.close()

    @unpurged
    def write_str(self, filename):
        """Write the sequence of instructions to a file."""
        print("Writing to", filename)
        f = open(filename, "w")
        n = 0
        for block in self.basicblocks:
            if block.instructions:
                f.write("# %s\n" % block.name)
                for line in block.instructions:
                    f.write("%s # %d\n" % (line, n))
                    n += 1
        f.close()

    @unpurged
    def write_bytes(self, filename=None):
        """Write the program's byte encoding to a file."""
        if filename is None:
            filename = self.outfile
        if not filename.endswith(".bc"):
            filename += ".bc"
        if "Bytecode" not in filename:
            filename = self.program.programs_dir + "/Bytecode/" + filename
        print("Writing to", filename)
        sys.stdout.flush()
        f = open(filename, "wb")
        h = hashlib.sha256()
        for i in self._get_instructions():
            if i is not None:
                b = i.get_bytes()
                f.write(b)
                h.update(b)
        f.close()
        self.hash = h.digest()

    def new_reg(self, reg_type, size=None):
        return self.Register(reg_type, self, size=size)

    def count_regs(self, reg_type=None):
        if reg_type is None:
            return self.reg_counter
        else:
            return self.reg_counter[reg_type]

    def __str__(self):
        return self.name

    class ReqNum(defaultdict):
        def __init__(self, init={}):
            super(Tape.ReqNum, self).__init__(lambda: 0, init)

        def __add__(self, other):
            res = Tape.ReqNum()
            for i, count in list(self.items()):
                res[i] += count
            for i, count in list(other.items()):
                res[i] += count
            return res

        def __mul__(self, other):
            res = Tape.ReqNum()
            for i in self:
                res[i] = other * self[i]
            return res

        __rmul__ = __mul__

        def __neg__(self):
            res = Tape.ReqNum()
            for i, count in list(self.items()):
                res[i] = -count
            return res

        def set_all(self, value):
            if Program.prog.options.verbose and \
               value == float("inf") and self["all", "inv"] > 0:
                print("Going to unknown from %s" % self)
            res = Tape.ReqNum()
            for i in self:
                res[i] = value
            return res

        def max(self, other):
            res = Tape.ReqNum()
            for i in self:
                res[i] = max(self[i], other[i])
            for i in other:
                res[i] = max(self[i], other[i])
            return res

        def cost(self):
            return sum(
                num * COST[req[0]][req[1]]
                for req, num in list(self.items())
                if req[1] != "input" and req[0] != "edabit"
            )

        def pretty(self):
            def t(x):
                return "integer" if x == "modp" else x

            def f(num):
                try:
                    return "%12.0f" % num
                except:
                    return str(num)

            res = []
            for req, num in self.items():
                domain = t(req[0])
                if num < 0:
                    num = float('inf')
                n = f(num)
                if req[1] == "input":
                    res += ["%s %s inputs from player %d" % (n, domain, req[2])]
                elif domain.endswith("edabit"):
                    if domain == "sedabit":
                        eda = "strict edabits"
                    else:
                        eda = "loose edabits"
                    res += ["%s %s of length %d" % (n, eda, req[1])]
                elif domain == "matmul":
                    res += [
                        "%s matrix multiplications (%dx%d * %dx%d)"
                        % (n, req[1][0], req[1][1], req[1][1], req[1][2])
                    ]
                elif req[0] != "all":
                    res += ["%s %s %ss" % (n, domain, req[1])]
            if self["all", "round"]:
                res += ["%s virtual machine rounds" % f(self["all", "round"])]
            return res

        def __str__(self):
            return ", ".join(self.pretty())

        def __repr__(self):
            return repr(dict(self))

    class ReqNode(object):
        def __init__(self, name):
            self._children = []
            self.name = name
            self.blocks = []
            self.aggregated = None
            self.num = None

        @property
        def children(self):
            self.aggregated = None
            return self._children

        def aggregate(self, *args):
            if self.aggregated is not None:
                return self.aggregated
            self.recursion = self.num is not None
            if self.recursion:
                return Tape.ReqNum()
            self.num = Tape.ReqNum()
            for block in self.blocks:
                block.add_usage(self)
            res = reduce(
                lambda x, y: x + y.aggregate(self.name), self.children, self.num
            )
            if self.recursion:
                res *= float('inf')
            self.aggregated = res
            return res

        def increment(self, data_type, num=1):
            self.num[data_type] += num
            self.aggregated = None

        def add_block(self, block):
            self.blocks.append(block)
            self.aggregated = None

    class ReqChild(object):
        __slots__ = ["aggregator", "nodes", "parent"]

        def __init__(self, aggregator, parent):
            self.aggregator = aggregator
            self.nodes = []
            self.parent = parent

        def aggregate(self, name):
            res = self.aggregator([node.aggregate() for node in self.nodes])
            try:
                n_reps = self.aggregator([1])
                n_rounds = res["all", "round"]
                n_invs = res["all", "inv"]
                if (n_invs / n_rounds) * 1000 < n_reps and Program.prog.verbose:
                    print(
                        self.nodes[0].blocks[0].name,
                        "blowing up rounds: ",
                        "(%d / %d) ** 3 < %d" % (n_rounds, n_reps, n_invs),
                    )
            except Exception:
                pass
            return res

        def add_node(self, tape, name):
            new_node = Tape.ReqNode(name)
            self.nodes.append(new_node)
            return new_node

    def open_scope(self, aggregator, scope=False, name=""):
        req_node = self.active_basicblock.req_node
        child = self.ReqChild(aggregator, req_node)
        req_node.children.append(child)
        node = child.add_node(self, "%s-%d" % (name, len(self.basicblocks)))
        self.start_new_basicblock(name=name, req_node=node)
        return child

    def close_scope(self, outer_scope, parent_req_node, name):
        self.start_new_basicblock(outer_scope, name, req_node=parent_req_node)

    def require_bit_length(self, bit_length, t="p", reason=None):
        if t == "p":
            if self.program.prime:
                if bit_length >= self.program.prime.bit_length() - 1:
                    raise CompilerError(
                        "required bit length %d too much for %d"
                        % (bit_length, self.program.prime)
                        + (" (for %s)" % reason if reason else '')
                    )
            bit_length += 1
            if bit_length > self.req_bit_length[t]:
                self.req_bit_length[t] = bit_length
                self.bit_length_reason = reason
        else:
            if self.req_bit_length[t] and bit_length != self.req_bit_length[t]:
                raise CompilerError('cannot change bit length')
            self.req_bit_length[t] = bit_length

    @staticmethod
    def read_instructions(tapename):
        tape = open("Programs/Bytecode/%s.bc" % tapename, "rb")
        while tape.peek():
            yield inst_base.ParsedInstruction(tape)

    class _no_truth(object):
        __slots__ = []

        def __bool__(self):
            raise CompilerError(
                "Cannot derive truth value (bool) from %s. "
                "See https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#cannot-derive-truth-value-from-register. " % \
                type(self).__name__
            )

        def __int__(self):
            raise CompilerError(
                "It is impossible to convert run-time types to compile-time "
                "Python types like int or float. The reason for this is that "
                "%s objects are only a placeholder during the execution in "
                "Python, the actual value of which is only defined in the "
                "virtual machine at a later time. See "
                "https://mp-spdz.readthedocs.io/en/latest/journey.html "
                "to get an understanding of the overall design. "
                "In rare cases, you can fix this by using 'compile.py -l'." % \
                type(self).__name__
            )

        __float__ = __int__

        def __eq__(self, other):
            raise CompilerError("equality testing not implemented")

        __ne__ = __eq__

    class _no_secret_truth(_no_truth):
        def __bool__(self):
            raise CompilerError(
                "Cannot branch on secret values like %s. "
                "See https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#cannot-branch-on-secret-values. " % \
                type(self).__name__
            )

    class Register(_no_truth):
        """
        Class for creating new registers. The register's index is automatically assigned
        based on the block's  reg_counter dictionary.
        """

        __slots__ = [
            "reg_type",
            "program",
            "absolute_i",
            "relative_i",
            "size",
            "vector",
            "vectorbase",
            "caller",
            "can_eliminate",
            "duplicates",
            "dup_count",
            "block",
        ]
        maximum_size = 2 ** (64 - inst_base.Instruction.code_length) - 1

        def __init__(self, reg_type, program, size=None, i=None):
            """Creates a new register.
            reg_type must be one of those defined in RegType."""
            if Compiler.instructions_base.get_global_instruction_type() == "gf2n":
                if reg_type == RegType.ClearModp:
                    reg_type = RegType.ClearGF2N
                elif reg_type == RegType.SecretModp:
                    reg_type = RegType.SecretGF2N
            self.reg_type = reg_type
            self.program = program
            self.block = program.active_basicblock
            if size is None:
                size = Compiler.instructions_base.get_global_vector_size()
            if size is not None and size > self.maximum_size:
                raise CompilerError("vector too large: %d" % size)
            self.size = size
            self.vectorbase = self
            self.relative_i = 0
            if i is not None:
                self.i = i
            elif size is not None:
                self.i = program.reg_counter[reg_type]
                program.reg_counter[reg_type] += size
            else:
                self.i = float("inf")
            self.vector = []
            self.can_eliminate = True
            self.duplicates = util.set_by_id([self])
            self.dup_count = None
            if Program.prog.DEBUG:
                self.caller = [frame[1:] for frame in inspect.stack()[1:]]
            else:
                self.caller = None

        @property
        def i(self):
            return self.vectorbase.absolute_i + self.relative_i

        @i.setter
        def i(self, value):
            self.vectorbase.absolute_i = value - self.relative_i

        def set_size(self, size):
            if self.size == size:
                return
            else:
                raise CompilerError(
                    "Mismatch of instruction and register size:"
                    " %s != %s" % (self.size, size)
                )

        def set_vectorbase(self, vectorbase):
            if self.vectorbase is not self:
                raise CompilerError("Cannot assign one register" "to several vectors")
            self.relative_i = self.i - vectorbase.i
            self.vectorbase = vectorbase

        def _new_by_number(self, i, size=1):
            return Tape.Register(self.reg_type, self.program, size=size, i=i)

        def get_vector(self, base=0, size=None):
            if size is None:
                size = self.size
            if base == 0 and size == self.size:
                return self
            if size == 1:
                return self[base]
            res = self._new_by_number(self.i + base, size=size)
            res.set_vectorbase(self)
            self.create_vector_elements()
            res.vector = self.vector[base : base + size]
            return res

        def create_vector_elements(self):
            if self.vector:
                return
            elif self.size == 1:
                self.vector = [self]
                return
            self.vector = []
            for i in range(self.size):
                reg = self._new_by_number(self.i + i)
                reg.set_vectorbase(self)
                self.vector.append(reg)

        def get_all(self):
            return self.vector or [self]

        def __getitem__(self, index):
            try:
                if isinstance(index, slice):
                    for x in index.start, index.stop, index.step:
                        if x is not None:
                            int(x)
                else:
                    int(index)
            except:
                raise CompilerError(
                    'cannot address vectors with run-time indices, '
                    'use (Multi)Array instead')
            if self.size == 1 and index == 0:
                return self
            if not self.vector:
                self.create_vector_elements()
            return self.vector[index]

        def __len__(self):
            return self.size

        def copy(self):
            return Tape.Register(self.reg_type, Program.prog.curr_tape)

        def same_type(self):
            return type(self)(size=self.size)

        def link(self, other):
            if Program.prog.options.noreallocate:
                raise CompilerError("reallocation necessary for linking, "
                                    "remove option -u")
            assert self.reg_type == other.reg_type
            self.duplicates |= other.duplicates
            for dup in self.duplicates:
                dup.duplicates = self.duplicates

        def update(self, other):
            """
            Update register. Useful in loops like
            :py:func:`~Compiler.library.for_range`.

            :param other: any convertible type

            """
            other = type(self)(other)
            same_block = other.block == self.block
            if same_block or self.reg_type[0] != "s":
                self.program.start_new_basicblock(name="update")
            if self.program != other.program:
                raise CompilerError(
                    'cannot update register with one from another thread')
            self.link(other)

        @property
        def is_gf2n(self):
            return (
                self.reg_type == RegType.ClearGF2N
                or self.reg_type == RegType.SecretGF2N
            )

        @property
        def is_clear(self):
            return (
                self.reg_type == RegType.ClearModp
                or self.reg_type == RegType.ClearGF2N
                or self.reg_type == RegType.ClearInt
            )

        def __str__(self):
            return self.reg_type + str(self.i) + \
                ("(%d)" % self.size if self.size is not None and self.size > 1
                 else "")

        __repr__ = __str__
