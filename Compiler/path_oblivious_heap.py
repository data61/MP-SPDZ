"""This module contains a basic implementation of the Path Oblivious Heap'
oblivious priority queue as proposed by 
`Shi <https://eprint.iacr.org/2019/274.pdf>`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Generic, List, Tuple, Type, TypeVar

from Compiler import library as lib, oram, util
from Compiler.circuit_oram import CircuitORAM
from Compiler.dijkstra import HeapEntry
from Compiler.path_oram import Counter, PathORAM
from Compiler.types import (
    _arithmetic_register,
    _clear,
    _secret,
    Array,
    cint,
    MemValue,
    regint,
    sint,
)

# TODO:
# - Optimize "home-made" algorithms (update_min)
#   - look at what evict does
# - Benchmark
# - Type hiding security (maybe)

### SETTINGS ###

# If enabled, compile-time debugging info is printed.
COMPILE_DEBUG = True

# If enabled, high-level debugging messages are printed at runtime.
# Warning: Reveals operation types.
DEBUG = True

# If enabled, low-level trace is printed at runtime
# Warning: Reveals secret information.
TRACE = False

# DEBUG is enabled if TRACE is enabled
DEBUG = DEBUG or TRACE


def noop(*args, **kwargs):
    pass


cprint = print if COMPILE_DEBUG else noop

### IMPLEMENTATION ###

# Types
T = TypeVar("T", _arithmetic_register, int)
_Secret = Type[_secret]


class AbstractMinPriorityQueue(ABC, Generic[T]):
    """An abstract class defining the basic behavior
    of a min priority queue.
    """

    @abstractmethod
    def insert(self, value: T, priority: T) -> None:
        """Insert a value with a priority into the queue."""
        pass

    @abstractmethod
    def extract_min(self) -> T:
        """Remove the minimal element in the queue and return it."""
        pass


class EmptyIndexStructure:
    """Since Path Oblivious Heap does not need to
    maintain a position map, we use an empty index structure
    for compatibility.
    """

    def __init__(*args, **kwargs):
        pass

    def noop(*args, **kwargs):
        return None

    def __getattr__(self, _):
        return self.noop


class NoIndexORAM:
    index_structure = EmptyIndexStructure


class SubtreeMinEntry(HeapEntry):
    fields = ["empty", "leaf", "prio", "value"]

    empty: _secret | MemValue
    leaf: _secret | MemValue
    prio: _secret | MemValue
    value: _secret | MemValue

    def __init__(
        self,
        value_type: _Secret,
        empty: _secret | int,
        leaf: _secret | int,
        prio: _secret | int,
        value: _secret | int,
        mem: bool = False,
    ):
        empty = value_type.hard_conv(empty)
        leaf = value_type.hard_conv(leaf)
        prio = value_type.hard_conv(prio)
        value = value_type.hard_conv(value)
        if mem:
            empty = MemValue(empty)
            leaf = MemValue(leaf)
            prio = MemValue(prio)
            value = MemValue(value)
        super().__init__(value_type, empty, leaf, prio, value)
        self.value_type = value_type

    def __eq__(self, other: SubtreeMinEntry) -> _secret:
        # Leaf label is only set on subtree-min elements so we don't use it for equality check
        return (self.empty * other.empty).max(
            (self.empty == other.empty)
            * (self.prio == other.prio)
            * (self.value == other.value)
        )

    def __lt__(self, other: SubtreeMinEntry) -> _secret:
        """Entries are always equal if they are empty.
        Otherwise, compare on emptiness,
        then on priority, and finally tie break on value.
        Returns 1 if first has strictly higher priority (smaller value),
        and 0 otherwise.
        """
        # TODO: Tie break is probably not secure if there are duplicates.
        # Can be fixed with unique ids
        prio_lt = self.prio < other.prio
        prio_eq = self.prio == other.prio
        value_lt = self.value < other.value
        return (1 - self.empty) * other.empty.max(prio_lt + prio_eq * (value_lt))

    def __gt__(self, other: SubtreeMinEntry) -> _secret:
        return other < self

    def __le__(self, other: SubtreeMinEntry) -> _secret:
        return (self == other).max(self < other)

    def __ge__(self, other: SubtreeMinEntry) -> _secret:
        return (self == other).max(self > other)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    @staticmethod
    def get_empty(value_type: _Secret, mem: bool = False) -> SubtreeMinEntry:
        return SubtreeMinEntry(
            value_type,
            value_type(1),
            value_type(0),
            value_type(0),
            value_type(0),
            mem=mem,
        )

    @staticmethod
    def from_entry(entry: oram.Entry, mem: bool = False) -> SubtreeMinEntry:
        """Convert a RAM entry containing the fields
        [empty, index, prio, value, leaf] into a SubtreeMinEntry.
        """
        entry = iter(entry)
        empty = next(entry)
        next(entry)  # disregard index
        leaf = next(entry)
        prio = next(entry)
        value = next(entry)
        return SubtreeMinEntry(value.basic_type, empty, leaf, prio, value, mem=mem)

    def to_entry(self) -> oram.Entry:
        return oram.Entry(
            0,
            (self.leaf, self.prio, self.value),
            empty=self.empty,
            value_type=self.value_type,
        )

    def write_if(self, cond, new) -> None:
        for field in self.fields:
            self[field] = cond * new[field] + (1 - cond) * self[field]

    def dump(self, str=""):
        """Reveal contents of entry (insecure)."""
        if TRACE:
            lib.print_ln(
                str + "empty %s, leaf %s, prio %s, value %s",
                *(x.reveal() for x in self),
            )


class BasicMinTree(NoIndexORAM):
    """Basic Min tree data structure behavior."""

    def __init__(self, init_rounds=-1):
        # Maintain subtree-mins in a separate RAM
        # (some of the attributes we access are defined in the ORAM classes,
        # so no meta information is available when accessed in this constructor.)
        empty_min_entry = self._get_empty_entry()
        self.subtree_mins = oram.RAM(
            2 ** (self.D + 1) + 1,  # +1 to make space for stash min (index -1)
            empty_min_entry.types(),
            self.get_array,
        )
        if init_rounds != -1:
            lib.stop_timer()
            lib.start_timer(1)
        self.subtree_mins.init_mem(empty_min_entry)
        if init_rounds != -1:
            lib.stop_timer(1)
            lib.start_timer()

        @lib.function_block
        def evict(leaf: self.value_type.clear_type):
            """Eviction reused from PathORAM, but this version accepts a leaf as input"""

            if DEBUG:
                lib.print_ln("[POH] evict: along path with label %s", leaf.reveal())

            self.use_shuffle_evict = True

            self.state.write(self.value_type(leaf))

            # load the path
            for i, ram_indices in enumerate(self.bucket_indices_on_path_to(leaf)):
                for j, ram_index in enumerate(ram_indices):
                    self.temp_storage[i * self.bucket_size + j] = self.buckets[
                        ram_index
                    ]
                    self.temp_levels[i * self.bucket_size + j] = i
                    self.buckets[ram_index] = self._get_empty_entry()

            # load the stash
            for i in range(len(self.stash.ram)):
                self.temp_levels[i + self.bucket_size * (self.D + 1)] = 0
            # for i, entry in enumerate(self.stash.ram):
            @lib.for_range(len(self.stash.ram))
            def f(i):
                entry = self.stash.ram[i]
                self.temp_storage[i + self.bucket_size * (self.D + 1)] = entry

                self.stash.ram[i] = self._get_empty_entry()

            self.path_regs = [None] * self.bucket_size * (self.D + 1)
            self.stash_regs = [None] * len(self.stash.ram)

            for i, ram_indices in enumerate(self.bucket_indices_on_path_to(leaf)):
                for j, ram_index in enumerate(ram_indices):
                    self.path_regs[j + i * self.bucket_size] = self.buckets[ram_index]
            for i in range(len(self.stash.ram)):
                self.stash_regs[i] = self.stash.ram[i]

            # self.sizes = [Counter(0, max_val=4) for i in range(self.D + 1)]
            if self.use_shuffle_evict:
                if self.bucket_size == 4:
                    self.size_bits = [
                        [self.value_type.bit_type(i) for i in (0, 0, 0, 1)]
                        for j in range(self.D + 1)
                    ]
                elif self.bucket_size == 2 or self.bucket_size == 3:
                    self.size_bits = [
                        [self.value_type.bit_type(i) for i in (0, 0)]
                        for j in range(self.D + 1)
                    ]
            else:
                self.size_bits = [
                    [self.value_type.bit_type(0) for i in range(self.bucket_size)]
                    for j in range(self.D + 1)
                ]
            self.stash_size = Counter(0, max_val=len(self.stash.ram))

            leaf = self.state.read().reveal()

            if self.use_shuffle_evict:
                # more efficient eviction using permutation networks
                self.shuffle_evict(leaf)
            else:
                # naive eviction method
                for i, (entry, depth) in enumerate(
                    zip(self.temp_storage, self.temp_levels)
                ):
                    self.evict_block(entry, depth, leaf)

                for i, entry in enumerate(self.stash_regs):
                    self.stash.ram[i] = entry
                for i, ram_indices in enumerate(self.bucket_indices_on_path_to(leaf)):
                    for j, ram_index in enumerate(ram_indices):
                        self.buckets[ram_index] = self.path_regs[
                            i * self.bucket_size + j
                        ]

        self.evict_along_path = evict

    @lib.method_block
    def update_min(self, leaf_label: _clear = None) -> None:
        """Update subtree_min entries on the path from the specified leaf
        to the root bucket (and stash) by finding the current min entry
        of every bucket on the path and comparing it to the subtree-mins
        of the bucket's two children.
        """
        if leaf_label is None:
            leaf_label = self.state.read().reveal()
        if DEBUG:
            lib.print_ln("[POH] update_min: along path with label %s", leaf_label)
        indices = self._get_reversed_min_indices_and_children_on_path_to(leaf_label)

        # Degenerate case (leaf): no children to consider if we are at a leaf.
        # However, we must remember to set the leaf label of the entry.
        leaf_ram_index = indices[0][0]
        leaf_min = self._get_bucket_min(leaf_ram_index)
        self._set_subtree_min(leaf_min, leaf_ram_index)
        if TRACE:
            leaf_min.dump("[POH] update_min: leaf min: ")

        # Iterate through internal path nodes and root
        for c, l, r in indices[1:]:
            if TRACE:
                lib.print_ln("[POH] update_min: bucket %s", c)
            current = self._get_bucket_min(c)
            left, right = map(self.get_subtree_min, [l, r])
            if TRACE:
                current.dump("[POH] update_min: current: ")
                left.dump("[POH] update_min: left: ")
                right.dump("[POH] update_min: right: ")

            # TODO: Is the following oblivious?

            # Compare pairs
            cmp_c_l = current < left
            cmp_c_r = current < right
            cmp_l_r = left < right

            # Only one of the three has the highest priority
            c_min = cmp_c_l * cmp_c_r
            l_min = (1 - cmp_c_l) * cmp_l_r
            r_min = (1 - cmp_c_r) * (1 - cmp_l_r)

            # entry = min(current, left, right)
            fields = [
                c_min * current[key] + l_min * left[key] + r_min * right[key]
                for key in current.fields
            ]
            entry = SubtreeMinEntry(self.value_type, *fields)
            if TRACE:
                entry.dump("[POH] update_min: updating min to: ")
            self._set_subtree_min(SubtreeMinEntry(self.value_type, *fields), c)

        # Degenerate case (stash): the only child of stash is the root
        # so only compare those two
        if TRACE:
            lib.print_ln("[POH] update_min: stash")
        stash_min = self._get_stash_min()
        root_min = self.get_subtree_min(0)
        if TRACE:
            stash_min.dump("[POH] update_min: stash min: ")
            root_min.dump("[POH] update_min: root min: ")

        s_min = stash_min < root_min

        # entry = min(stash_min, root_min)
        fields = [
            s_min * stash_min[key] + (1 - s_min) * root_min[key]
            for key in stash_min.fields
        ]
        self._set_subtree_min(SubtreeMinEntry(self.value_type, *fields))

    @lib.method_block
    def insert(
        self, value: _secret, priority: _secret, fake: _secret, empty: _secret = None
    ) -> None:
        """Insert an entry in the stash, assigning it a random leaf label,
        evict along two random, non-overlapping (except in the root) paths,
        and update_min along the two same paths.
        """
        # O(log n)

        if empty is None:
            empty = self.value_type(0)

        # Insert entry into stash with random leaf
        leaf_label = oram.random_block(self.D, self.value_type)
        if TRACE:
            lib.print_ln(
                "[POH] insert: sampled random leaf label %s", leaf_label.reveal()
            )
        self.add(
            oram.Entry(
                MemValue(sint(0)),
                [MemValue(v) for v in ((1 - fake) * priority, (1 - fake) * value)],
                empty=empty.max(fake),
                value_type=self.value_type,
            ),
            state=MemValue((1 - fake) * leaf_label),
            evict=False,
        )
        if TRACE:
            lib.print_ln("[POH] insert: stash:")
            self.dump_stash()

        # Get two random, non-overlapping leaf paths (except in the root)
        # Due to Path ORAM using the leaf index bits for indexing in reversed
        # order, we need to get a random even and uneven label
        leaf_label_even = oram.random_block(self.D - 1, self.value_type).reveal() * 2
        leaf_label_odd = oram.random_block(self.D - 1, self.value_type).reveal() * 2 + 1

        # Evict along two random non-overlapping paths
        self.evict_along_path(leaf_label_even)
        self.evict_along_path(leaf_label_odd)

        if TRACE:
            lib.print_ln("[POH] insert: stash:")
            self.dump_stash()
            lib.print_ln("[POH] insert: ram:")
            self.dump_ram()

        # UpdateMin along same paths
        self.update_min(leaf_label_even)
        self.update_min(leaf_label_odd)

    @lib.method_block
    def extract_min(self, fake: _secret) -> _secret:
        """Look up subtree-min of stash and extract it by linear scanning the structure.
        Then, evict along the extracted path, and finally, update_min along the path.
        """
        # O(log n)

        # Get min entry from stash
        min_entry = self.get_subtree_min()
        if DEBUG:
            min_entry.dump("[POH] extract_min")
        if TRACE:
            lib.crash(min_entry.empty.reveal())
        leaf_label = min_entry.leaf.reveal()
        empty_entry = SubtreeMinEntry.get_empty(self.value_type)

        # Scan path and remove element
        for i, _, _ in self._get_reversed_min_indices_and_children_on_path_to(
            leaf_label
        ):
            start = i * self.bucket_size
            stop = start + self.bucket_size

            # TODO: Debug for_range (use MemValues?)
            @lib.for_range(start, stop=stop)
            def _(j):
                current_entry = SubtreeMinEntry.from_entry(self.buckets[j])
                if TRACE:
                    lib.print_str("[POH] extract_min: current element (bucket %s): ", i)
                    current_entry.dump()
                found = min_entry == current_entry
                current_entry.write_if((1 - fake) * found, empty_entry)
                self.buckets[j] = current_entry.to_entry()

        @lib.for_range(0, self.stash.ram.size)
        def _(i):
            current_entry = SubtreeMinEntry.from_entry(self.stash.ram[i])
            if TRACE:
                current_entry.dump(f"[POH] extract_min: current element (stash): ")
            found = min_entry == current_entry
            current_entry.write_if(found, empty_entry)
            self.stash.ram[i] = current_entry.to_entry()

        # Evict along path to leaf
        self.evict_along_path(leaf_label)

        # UpdateMin along path
        self.update_min(leaf_label)
        return min_entry.value

    def _get_empty_entry(self) -> oram.Entry:
        return oram.Entry.get_empty(*self.internal_entry_size())

    def get_subtree_min(self, index: int = -1) -> SubtreeMinEntry:
        """Returns a SubtreeMinEntry representing the subtree-min
        of the bucket with the specified index. If index is not specified,
        it returns the subtree-min of the stash (index -1),
        which is the subtree-min of the complete tree.
        """
        return SubtreeMinEntry.from_entry(self.subtree_mins[index])

    def _set_subtree_min(self, entry: SubtreeMinEntry, index: int = -1) -> None:
        """Sets the subtree-min of the bucket with the specified index
        to the specified entry.
        """
        self.subtree_mins[index] = entry.to_entry()

    def _get_bucket_min(self, index: _clear) -> SubtreeMinEntry:
        """Get the min entry of a bucket by linear scan."""
        start = index * self.bucket_size
        stop = start + self.bucket_size
        return self._get_ram_min(self.buckets, start, stop)

    def _get_stash_min(self) -> SubtreeMinEntry:
        """Get the min entry of the stash by linear scan."""
        # TODO: Is this secure? We touch every entry so probably.
        return self._get_ram_min(self.stash.ram, 0, self.stash.size)

    def _get_ram_min(self, ram: oram.RAM, start: int, stop: int) -> SubtreeMinEntry:
        """Scan through RAM indices, finding the entry with highest priority."""
        # TODO: Write cleaner. Need to use memvalues due to for_range.

        min_empty = MemValue(self.value_type(1))
        min_leaf = MemValue(self.value_type(0))
        min_prio = MemValue(self.value_type(0))
        min_value = MemValue(self.value_type(0))

        @lib.for_range(start, stop=stop)
        def _(i):
            res = SubtreeMinEntry(
                self.value_type,
                min_empty.read(),
                min_leaf.read(),
                min_prio.read(),
                min_value.read(),
            )
            entry = SubtreeMinEntry.from_entry(ram[i])
            entry_min = entry < res
            min_empty.write(entry_min * entry.empty + (1 - entry_min) * res.empty)
            min_leaf.write(entry_min * entry.leaf + (1 - entry_min) * res.leaf)
            min_prio.write(entry_min * entry.prio + (1 - entry_min) * res.prio)
            min_value.write(entry_min * entry.value + (1 - entry_min) * res.value)
            if TRACE:
                res.dump("[POH] _get_ram_min: res: ")
                entry.dump("[POH] _get_ram_min: entry: ")
                lib.print_ln("[POH] _get_ram_min: entry_min: %s", entry_min.reveal())

        return SubtreeMinEntry(
            self.value_type,
            min_empty.read(),
            min_leaf.read(),
            min_prio.read(),
            min_value.read(),
        )

    def _get_reversed_min_indices_and_children_on_path_to(
        self, leaf_label: _clear
    ) -> List[Tuple[int, int, int]]:
        """Returns a list from leaf to root of tuples of (index, left_child, right_child).
        Used for update_min.
        Note that leaf label bits are used from least to most significant bit,
        so even leaves are indexed first, then odd, e.g. (for 8 leaves):

            leaf_label    leaf_index (left to right)
            000           000 (0)
            001           100 (4)
            010           010 (2)
            011           110 (6)
            100           001 (1)
            101           101 (5)
            110           011 (3)
            111           111 (7)

        In other words, leaf indices are reversed.
        """
        leaf_label = regint(leaf_label)
        indices = [(0, 1, 2)]
        index = 0
        for _ in range(self.D):
            index = 2 * index + 1 + (cint(leaf_label) & 1)
            leaf_label >>= 1
            indices += [(index,) + self._get_child_indices(index)]
        # if TRACE:
        #     [lib.print_ln("%s", i) for i in indices]
        return list(reversed(indices))

    def _get_child_indices(self, i) -> Tuple[int, int]:
        """This is how a binary tree works."""
        return 2 * i + 1, 2 * i + 2

    def dump_stash(self):
        for i in range(len(self.stash.ram)):
            SubtreeMinEntry.from_entry(self.stash.ram[i]).dump()

    def dump_ram(self):
        for i in range(len(self.ram)):
            if i % self.bucket_size == 0:
                lib.print_ln("bucket %s", i // self.bucket_size)
            SubtreeMinEntry.from_entry(self.ram[i]).dump()


class CircuitMinTree(CircuitORAM, BasicMinTree):
    """Binary Bucket Tree data structure
    using Circuit ORAM as underlying data structure.
    """

    def __init__(
        self,
        capacity: int,
        int_type: _Secret = sint,
        entry_size: Tuple[int] | None = None,
        bucket_size: int = 3,
        stash_size: int | None = None,
        init_rounds: int = -1,
    ):
        CircuitORAM.__init__(
            self,
            capacity,
            value_type=int_type,
            entry_size=entry_size,
            bucket_size=bucket_size,
            stash_size=stash_size,
            init_rounds=init_rounds,
        )
        BasicMinTree.__init__(self)


class PathMinTree(PathORAM, BasicMinTree):
    """Binary Bucket Tree data structure
    using Path ORAM as underlying data structure.
    """

    def __init__(
        self,
        capacity: int,
        int_type: _Secret = sint,
        entry_size: Tuple[int] | None = None,
        bucket_oram: oram.AbstractORAM = oram.TrivialORAM,
        bucket_size: int = 2,
        stash_size: int | None = None,
        init_rounds: int = -1,
    ):
        PathORAM.__init__(
            self,
            capacity,
            value_type=int_type,
            entry_size=entry_size,
            bucket_oram=bucket_oram,
            bucket_size=bucket_size,
            stash_size=stash_size,
            init_rounds=init_rounds,
        )
        # For compatibility with inherited __repr__
        self.ram = self.buckets
        self.root = oram.RefBucket(1, self)

        BasicMinTree.__init__(self, init_rounds)


class POHVariant(Enum):
    """Constants representing Path and Circuit variants
    and utility functions to map the variants to defaults.
    """

    PATH = 0
    CIRCUIT = 1

    def get_tree_class(self):
        return PathMinTree if self == self.PATH else CircuitMinTree

    def get_default_bucket_size(self):
        return 2 if self == self.PATH else 3

    def __repr__(self):
        return "Path" if self == self.PATH else "Circuit"


class PathObliviousHeap(AbstractMinPriorityQueue[_secret]):
    """A basic Path Oblivious Heap implementation supporting
    insert, extract_min, and find_min.

    :ivar type_hiding_security: A boolean indicating whether
        type hiding security is enabled. Enabling this
        makes the cost of every operation equal to the
        sum of the costs of all operations. This is initially
        set by passing an argument to the class constructor.
    :ivar int_type: the secret integer type of entry members.
    """

    def __init__(
        self,
        capacity: int,
        security: int | None = None,
        type_hiding_security: bool = False,
        int_type: _Secret = sint,
        entry_size: Tuple[int] | None = None,
        variant: POHVariant = POHVariant.PATH,
        bucket_oram: oram.AbstractORAM = oram.TrivialORAM,
        bucket_size: int | None = None,
        stash_size: int | None = None,
        init_rounds: int = -1,
    ):
        """
        Initializes a Path Oblivious Heap priority queue.
        The queue supports non-negative priorities only.

        :param capacity: The max capacity of the queue.
        :param security: A security parameter, used for determining the stash size
            in order to make the error probability negligible in this parameter.
            Defaults to be equal to the capacity.
        :param type_hiding_security: (Currently not supported) True if the types of
            executed operations should be oblivious, False otherwise. Defaults to False.
        :param int_type: The data type of the queue, used for both key and value.
            Defaults to `sint`.
        :param entry_size: A tuple containing an integer per entry value that specifies
            the bit length of that value. Defaults to `(32, util.log2(capacity))`.
        :param variant: A `POHVariant` enum class member specifying the variant (either
            `PATH` or `CIRCUIT`). Defaults to `PATH`.
        :param bucket_oram: The ORAM used in every bucket. Defaults to `oram.TrivialORAM`.
        :param bucket_size: The size of every bucket. Defaults to
            `variant.get_default_bucket_size()`.
        :param stash_size: The size of the stash. Defaults to the squared base 2 logarithm
            of the security parameter.
        :param init_rounds: If not equal to -1, initialization is timed in isolation.
            Defaults to -1.
        """
        # Check inputs
        if int_type != sint:
            raise lib.CompilerError(
                "[POH] __init__: Only sint is supported as int_type."
            )

        if variant is not POHVariant.PATH:
            raise lib.CompilerError(
                "[POH] __init__: Only the PATH variant is supported."
            )

        # Initialize basic class fields
        self.int_type = int_type
        self.type_hiding_security = type_hiding_security

        # TODO: Figure out what default should be (capacity = poly(security))
        if security is None:
            security = capacity

        # Use default entry size (for Dijkstra) if not specified (distance, node)
        if entry_size is None:
            entry_size = (32, util.log2(capacity))  # TODO: Why 32?

        # Use default bucket size if not specified
        if bucket_size is None:
            bucket_size = variant.get_default_bucket_size()

        # TODO: How to do superlogarithmic?
        # TODO: Experiment with constant stash size as in Path ORAM
        if stash_size is None:
            stash_size = util.log2(security) ** 2

        # Print debug messages
        cprint(
            "[POH] __init__: Initializing a queue with a capacity of %s and security parameter %s",
            capacity,
            security,
        )
        cprint(
            f"[POH] __init__: Type hiding security is {'en' if self.type_hiding_security else 'dis'}abled",
        )
        cprint("[POH] __init__: Variant is %s", variant)

        # Initialize data structure with dummy elements
        self.tree = variant.get_tree_class()(
            capacity,
            int_type=int_type,
            entry_size=entry_size,
            bucket_oram=bucket_oram,
            bucket_size=bucket_size,
            stash_size=stash_size,
            init_rounds=init_rounds,
        )

    def insert(self, value, priority, fake: bool = False) -> None:
        """Insert an element with a priority into the queue."""
        value = self.int_type.hard_conv(value)
        priority = self.int_type.hard_conv(priority)
        fake = self.int_type.hard_conv(fake)
        self._insert(value, priority, fake)

    def extract_min(self, fake: bool = False) -> _secret | None:
        """Extract the element with the smallest (ie. highest)
        priority from the queue.
        """
        fake = self.int_type.hard_conv(fake)
        return self._extract_min(fake)

    def find_min(self, fake: bool = False) -> _secret | None:
        """Find the element with the smallest (ie. highest)
        priority in the queue and return its value and priority.
        Returns -1 if empty.
        """
        fake = self.int_type.hard_conv(fake)  # Not supported
        return self._find_min()

    def _insert(self, value: _secret, priority: _secret, fake: _secret) -> None:
        if TRACE:
            lib.print_ln(
                "[POH] insert: {value: %s, prio: %s}",
                value.reveal(),
                priority.reveal(),
            )
        elif DEBUG:
            lib.print_ln("[POH] insert")
        self.tree.insert(value, priority, fake)

    def _extract_min(self, fake: _secret) -> _secret:
        if DEBUG:
            lib.print_ln("[POH] extract_min")
        value = self.tree.extract_min(fake)
        if TRACE:
            lib.print_ln("[POH] extract_min: extracted value %s", value.reveal())
        return value

    def _find_min(self) -> _secret:
        entry = self.tree.get_subtree_min()
        if TRACE:
            entry.dump("[POH] find_min: ")
            lib.print_ln_if(
                entry["empty"].reveal(), "[POH] Found empty entry during find_min!"
            )
        elif DEBUG:
            lib.print_ln("[POH] find_min")
        return entry["empty"].if_else(self.int_type(-1), entry["value"])


class POHToHeapQAdapter(PathObliviousHeap):
    """
    Adapts Path Oblivious Heap to the HeapQ interface,
    allowing plug-and-play replacement in the Dijkstra
    implementation.
    """

    def __init__(self, max_size, *args, **kwargs):
        """Initialize a POH with the required capacity
        and disregard all other parameters.
        """
        super().__init__(max_size)  # TODO: Check parameters

    def update(self, value, priority, for_real=True):
        """Call insert instead of update.
        Warning: When using this adapter, duplicate values are
        allowed to be inserted, and no values are ever updated.
        """
        self.insert(value, priority, fake=(1 - for_real))

    def pop(self, for_real=True):
        """Renaming of pop to extract_min."""
        return self.extract_min(fake=(1 - for_real))


def path_oblivious_sort(keys: Array, values: Array):
    """Sort values in place according to keys using Path Oblivious Heap
    by calling insert followed by extract min.
    """
    assert len(keys) == len(values)
    n = len(keys)
    q = PathObliviousHeap(n, entry_size=(64, util.log2(n)))

    @lib.for_range(n)
    def _(i):
        q.insert(values[i], keys[i])

    @lib.for_range(n)
    def _(i):
        values[i] = q.extract_min()


def test_SubtreeMinEntry_cmp():
    a = SubtreeMinEntry(sint, 0, 42, 6, 14)
    b = SubtreeMinEntry(sint, 0, 42, 6, 13)
    c = SubtreeMinEntry(sint, 0, 42, 5, 13)
    d = SubtreeMinEntry(sint, 1, 10, 0, 0)
    e = SubtreeMinEntry(sint, 0, 17, 0, 7, mem=True)
    f = SubtreeMinEntry(sint, 0, 17, 0, 6, mem=True)

    lib.print_ln("a < a: %s", (a < a).reveal())  # 0
    lib.print_ln("a > a: %s", (a > a).reveal())  # 0
    lib.print_ln("a == a: %s", (a == a).reveal())  # 1
    lib.print_ln("a <= a: %s", (a <= a).reveal())  # 1
    lib.print_ln("a >= a: %s", (a >= a).reveal())  # 1
    lib.print_ln("a < b: %s", (a < b).reveal())  # 0
    lib.print_ln("a == b: %s", (a == b).reveal())  # 0
    lib.print_ln("b < a: %s", (b < a).reveal())  # 1
    lib.print_ln("b > a: %s", (b > a).reveal())  # 0
    lib.print_ln("a < c: %s", (a < c).reveal())  # 0
    lib.print_ln("a == c: %s", (a == c).reveal())  # 0
    lib.print_ln("a > c: %s", (a > c).reveal())  # 1
    lib.print_ln("c > a: %s", (c > a).reveal())  # 0
    lib.print_ln("a < d: %s", (a < d).reveal())  # 1
    lib.print_ln("d > a: %s", (d > a).reveal())  # 1
    lib.print_ln("d == a: %s", (d == a).reveal())  # 0
    lib.print_ln("c < b: %s", (c < b).reveal())  # 1
    lib.print_ln("b < c: %s", (b < c).reveal())  # 0
    lib.print_ln("b > c: %s", (b > c).reveal())  # 1
    lib.print_ln("b == c: %s", (b == c).reveal())  # 0

    # MemValues
    lib.print_ln("e < f: %s", (e < f).reveal())  # 0
    lib.print_ln("f < e: %s", (f < e).reveal())  # 1
    lib.print_ln("e == f: %s", (e == f).reveal())  # 0

    # MemValues and basic types
    lib.print_ln("e < a: %s", (e < a).reveal())  # 1