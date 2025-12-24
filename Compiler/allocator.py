import itertools, time
from collections import defaultdict, deque
from Compiler.exceptions import *
from Compiler.config import *
from Compiler.instructions import *
from Compiler.instructions_base import *
from Compiler.util import *
import Compiler.graph
import Compiler.program
import heapq, itertools
import operator
import sys
from functools import reduce

class BlockAllocator:
    """ Manages freed memory blocks. """
    def __init__(self):
        self.by_logsize = [defaultdict(set) for i in range(64)]
        self.by_address = {}

    def by_size(self, size):
        if size >= 2 ** 64:
            raise CompilerError('size exceeds addressing capability')
        return self.by_logsize[int(math.log(size, 2))][size]

    def push(self, address, size):
        end = address + size
        if end in self.by_address:
            next_size = self.by_address.pop(end)
            self.by_size(next_size).remove(end)
            size += next_size
        self.by_size(size).add(address)
        self.by_address[address] = size

    def pop(self, size):
        if len(self.by_size(size)) > 0:
            block_size = size
        else:
            logsize = int(math.log(size, 2))
            for block_size, addresses in self.by_logsize[logsize].items():
                if block_size >= size and len(addresses) > 0:
                    break
            else:
                done = False
                for x in self.by_logsize[logsize + 1:]:
                    for block_size, addresses in sorted(x.items()):
                        if len(addresses) > 0:
                            done = True
                            break
                    if done:
                        break
                else:
                    block_size = 0
        if block_size >= size:
            addr = self.by_size(block_size).pop()
            del self.by_address[addr]
            diff = block_size - size
            if diff:
                self.by_size(diff).add(addr + size)
                self.by_address[addr + size] = diff
            return addr

class AllocRange:
    def __init__(self, base=0):
        self.base = base
        self.top = base
        self.limit = base
        self.grow = True
        self.pool = defaultdict(set)

    def alloc(self, size):
        if self.pool[size]:
            return self.pool[size].pop()
        elif self.grow or self.top + size <= self.limit:
            res = self.top
            self.top += size
            self.limit = max(self.limit, self.top)
            if res >= REG_MAX:
                raise RegisterOverflowError(size)
            return res

    def free(self, base, size):
        assert self.base <= base < self.top
        self.pool[size].add(base)

    def stop_growing(self):
        self.grow = False

    def consolidate(self):
        regs = []
        for size, pool in self.pool.items():
            for base in pool:
                regs.append((base, size))
        for base, size in reversed(sorted(regs)):
            if base + size == self.top:
                self.top -= size
                self.pool[size].remove(base)
                regs.pop()
            else:
                if program.Program.prog.verbose:
                    print('cannot free %d register blocks '
                          'by a gap of %d at %d' %
                          (len(regs), self.top - size - base, base))
                break

class AllocPool:
    def __init__(self, parent=None):
        self.ranges = defaultdict(lambda: [AllocRange()])
        self.by_base = {}
        self.parent = parent

    def alloc(self, reg_type, size):
        for r in self.ranges[reg_type]:
            res = r.alloc(size)
            if res is not None:
                self.by_base[reg_type, res] = r
                return res

    def free(self, reg):
        try:
            r = self.by_base.pop((reg.reg_type, reg.i))
            r.free(reg.i, reg.size)
        except KeyError:
            try:
                self.parent.free(reg)
            except:
                if program.Program.prog.options.debug:
                    print('Error with freeing register with trace:')
                    print(util.format_trace(reg.caller))
                    print()

    def new_ranges(self, min_usage):
        for t, n in min_usage.items():
            r = self.ranges[t][-1]
            assert (n >= r.limit)
            if r.limit < n:
                r.stop_growing()
                self.ranges[t].append(AllocRange(n))

    def consolidate(self):
        for r in self.ranges.values():
            for rr in r:
                rr.consolidate()

    def n_fragments(self):
        if self.ranges:
            return max(len(r) for r in self.ranges)
        else:
            return 0

class StraightlineAllocator:
    """Allocate variables in a straightline program using n registers.
    It is based on the precondition that every register is only defined once."""
    def __init__(self, n, program):
        self.alloc = dict_by_id()
        self.max_usage = defaultdict(lambda: 0)
        self.defined = dict_by_id()
        self.dealloc = set_by_id()
        assert(n == REG_MAX)
        self.program = program
        self.old_pool = None
        self.unused = defaultdict(lambda: 0)

    def alloc_reg(self, reg, free):
        base = reg.vectorbase
        if base in self.alloc:
            # already allocated
            return

        reg_type = reg.reg_type
        size = base.size
        res = free.alloc(reg_type, size)
        self.alloc[base] = res

        base.i = self.alloc[base]

        for dup in base.duplicates:
            dup = dup.vectorbase
            self.alloc[dup] = self.alloc[base]
            dup.i = self.alloc[base]
            if not dup.dup_count:
                dup.dup_count = len(base.duplicates)

    def dealloc_reg(self, reg, inst, free):
        if reg.vector:
            self.dealloc |= reg.vector
        else:
            self.dealloc.add(reg)
        reg.duplicates.remove(reg)
        base = reg.vectorbase

        seen = set_by_id()
        to_check = set_by_id()
        to_check.add(base)
        while to_check:
            dup = to_check.pop()
            if dup not in seen:
                seen.add(dup)
                base = dup.vectorbase
                if base.vector:
                    for i in base.vector:
                        if i not in self.dealloc:
                            # not all vector elements ready for deallocation
                            return
                        if len(i.duplicates) > 1:
                            for x in i.duplicates:
                                to_check.add(x)
                else:
                    if base not in self.dealloc:
                        return
                for x in itertools.chain(dup.duplicates, base.duplicates):
                    to_check.add(x)

        if reg not in self.program.base_addresses \
           and not isinstance(inst, call_arg):
            free.free(base)
        if inst.is_vec() and base.vector:
            self.defined[base] = inst
            for i in base.vector:
                self.defined[i] = inst
        else:
            self.defined[reg] = inst

    def process(self, program, alloc_pool):
        self.update_usage(alloc_pool)
        for k,i in enumerate(reversed(program)):
            unused_regs = []
            for j in i.get_def():
                if j.vectorbase in self.alloc:
                    if j in self.defined:
                        raise CompilerError("Double write on register %s " \
                                            "assigned by '%s' in %s" % \
                                                (j,i,format_trace(i.caller)))
                else:
                    # unused register
                    self.alloc_reg(j, alloc_pool)
                    unused_regs.append(j)
            if unused_regs and len(unused_regs) == len(list(i.get_def())) and \
               self.program.verbose:
                # only report if all assigned registers are unused
                self.unused[type(i).__name__] += 1
                if self.program.verbose > 1:
                    print(
                        "Register(s) %s never used, assigned by '%s' in %s" % \
                        (unused_regs,i,format_trace(i.caller)))

            for j in i.get_used():
                self.alloc_reg(j, alloc_pool)
            for j in i.get_def():
                self.dealloc_reg(j, i, alloc_pool)

            if k % 1000000 == 0 and k > 0:
                print("Allocated registers for %d instructions at" % k, time.asctime())

        self.update_max_usage(alloc_pool)
        alloc_pool.consolidate()

        # print "Successfully allocated registers"
        # print "modp usage: %d clear, %d secret" % \
        #     (self.usage[Compiler.program.RegType.ClearModp], self.usage[Compiler.program.RegType.SecretModp])
        # print "GF2N usage: %d clear, %d secret" % \
        #     (self.usage[Compiler.program.RegType.ClearGF2N], self.usage[Compiler.program.RegType.SecretGF2N])
        return self.max_usage

    def update_max_usage(self, alloc_pool):
        for t, r in alloc_pool.ranges.items():
            self.max_usage[t] = max(self.max_usage[t], r[-1].limit)

    def update_usage(self, alloc_pool):
        if self.old_pool:
            self.update_max_usage(self.old_pool)
        if id(self.old_pool) != id(alloc_pool):
            alloc_pool.new_ranges(self.max_usage)
            self.old_pool = alloc_pool

    def finalize(self, options):
        for reg in self.alloc:
            for x in reg.get_all():
                if x not in self.dealloc and reg not in self.dealloc \
                   and len(x.duplicates) == x.dup_count:
                    print('Warning: read before write at register %s/%x' % 
                          (x, id(x)))
                    print('\tregister trace: %s' % format_trace(x.caller,
                                                                '\t\t'))
                    if options.stop:
                        sys.exit(1)
        if self.program.verbose:
            def p(sizes):
                total = defaultdict(lambda: 0)
                for (t, size) in sorted(sizes):
                    n = sizes[t, size]
                    total[t] += size * n
                    print('%s:%d*%d' % (t, size, n), end=' ')
                print()
                print('Total:', dict(total))

            sizes = defaultdict(lambda: 0)
            for reg in self.alloc:
                x = reg.reg_type, reg.size
            print('Used registers: ', end='')
            p(sizes)
            print('Unused instructions:', dict(self.unused))

def determine_scope(block, options):
    last_def = defaultdict_by_id(lambda: -1)
    used_from_scope = set_by_id()

    def read(reg, n):
        for dup in reg.duplicates:
            if last_def[dup] == -1:
                dup.can_eliminate = False
                used_from_scope.add(dup)

    def write(reg, n):
        if last_def[reg] != -1:
            print('Warning: double write at register', reg)
            print('\tline %d: %s' % (n, instr))
            print('\ttrace: %s' % format_trace(instr.caller, '\t\t'))
            if options.stop:
                sys.exit(1)
        last_def[reg] = n

    for n,instr in enumerate(block.instructions):
        outputs,inputs = instr.get_def(), instr.get_used()
        for reg in inputs:
            if reg.vector and instr.is_vec():
                for i in reg.vector:
                    read(i, n)
            else:
                read(reg, n)
        for reg in outputs:
            if reg.vector and instr.is_vec():
                for i in reg.vector:
                    write(i, n)
            else:
                write(reg, n)

    block.used_from_scope = used_from_scope

class Merger:
    def __init__(self, block, options, merge_classes):
        self.block = block
        self.instructions = block.instructions
        self.options = options
        if options.max_parallel_open:
            self.max_parallel_open = int(options.max_parallel_open)
        else:
            self.max_parallel_open = float('inf')
        self.counter = defaultdict(lambda: 0)
        self.rounds = defaultdict(lambda: 0)
        self.dependency_graph(merge_classes)

    def do_merge(self, merges_iter):
        """ Merge an iterable of nodes in G, returning the number of merged
        instructions and the index of the merged instruction. """
        # sort merges, necessary for inputb
        merge = list(merges_iter)
        merge.sort()
        merges_iter = iter(merge)
        instructions = self.instructions
        mergecount = 0
        try:
            n = next(merges_iter)
        except StopIteration:
            return mergecount, None

        for i in merges_iter:
            instructions[n].merge(instructions[i])
            instructions[i] = None
            self.merge_nodes(n, i)
            mergecount += 1

        return mergecount, n

    def longest_paths_merge(self):
        """ Attempt to merge instructions of type instruction_type (which are given in
        merge_nodes) using longest paths algorithm.

        Returns the no. of rounds of communication required after merging (assuming 1 round/instruction).

        Doesn't use networkx.
        """
        G = self.G
        instructions = self.instructions
        merge_nodes = self.open_nodes
        depths = self.depths
        self.req_num = defaultdict(lambda: 0)
        if not merge_nodes:
            return 0

        # merge opens at same depth
        merges = defaultdict(list)
        for node in merge_nodes:
            merges[depths[node]].append(node)

        # after merging, the first element in merges[i] remains for each depth i,
        # all others are removed from instructions and G
        last_nodes = [None, None]
        for i in sorted(merges):
            merge = merges[i]
            t = type(self.instructions[merge[0]])
            self.counter[t] += len(merge)
            self.rounds[t] += 1
            if len(merge) > 10000:
                print('Merging %d %s in round %d/%d' % \
                    (len(merge), t.__name__, i, len(merges)))
            self.do_merge(merge)
            self.req_num[t.__name__, 'round'] += 1

        preorder = None

        if len(instructions) > 1000000:
            print("Topological sort ...")
        order = Compiler.graph.topological_sort(G, preorder)
        instructions[:] = [instructions[i] for i in order if instructions[i] is not None]
        if len(instructions) > 1000000:
            print("Done at", time.asctime())

        return len(merges)

    def dependency_graph(self, merge_classes):
        """ Create the program dependency graph. """
        block = self.block
        options = self.options
        open_nodes = set()
        self.open_nodes = open_nodes
        colordict = defaultdict(lambda: 'gray', asm_open='red',\
                                ldi='lightblue', ldm='lightblue', stm='blue',\
                                mov='yellow', mulm='orange', mulc='orange',\
                                triple='green', square='green', bit='green',\
                                asm_input='lightgreen')

        G = Compiler.graph.SparseDiGraph(len(block.instructions))
        self.G = G

        reg_nodes = {}
        last_def = defaultdict_by_id(lambda: -1)
        last_read = defaultdict_by_id(list)
        last_mem_write = []
        last_mem_read = []
        last_mem_write_of = defaultdict(list)
        last_mem_read_of = defaultdict(list)
        last_print_str = None
        last = defaultdict(lambda: defaultdict(lambda: None))
        last_open = deque()
        last_input = defaultdict(lambda: [None, None])
        mem_scopes = defaultdict_by_id(lambda: MemScope())

        depths = [0] * len(block.instructions)
        self.depths = depths
        parallel_open = defaultdict(lambda: 0)
        next_available_depth = {}
        self.sources = []
        self.real_depths = [0] * len(block.instructions)
        round_type = {}
        shuffles = defaultdict_by_id(set)

        class MemScope:
            def __init__(self):
                self.read = []
                self.write = []

        def add_edge(i, j):
            if i in (-1, j):
                return
            G.add_edge(i, j)
            for d in (self.depths, self.real_depths):
                if d[j] < d[i]:
                    d[j] = d[i]

        def read(reg, n):
            for dup in reg.duplicates:
                if last_def[dup] not in (-1, n):
                    add_edge(last_def[dup], n)
            last_read[reg].append(n)

        def write(reg, n):
            for dup in reg.duplicates:
                add_edge(last_def[dup], n)
                for m in last_read[dup]:
                    add_edge(m, n)
            last_def[reg] = n

        def handle_mem_access(addr, reg_type, last_access_this_kind,
                              last_access_other_kind):
            this = last_access_this_kind[str(addr),reg_type]
            other = last_access_other_kind[str(addr),reg_type]
            if this and other:
                if this[-1] < other[0]:
                    del this[:]
            this.append(n)
            if id(last_access_this_kind) == id(last_mem_write_of):
                insts = itertools.chain(other, this)
            else:
                insts = other
            for inst in insts:
                add_edge(inst, n)

        def mem_access(n, instr, last_access_this_kind, last_access_other_kind):
            addr = instr.args[1]
            reg_type = instr.args[0].reg_type
            budget = block.parent.program.budget
            if isinstance(addr, int):
                for i in range(min(instr.get_size(), budget)):
                    addr_i = addr + i
                    handle_mem_access(addr_i, reg_type, last_access_this_kind,
                                      last_access_other_kind)
                if block.warn_about_mem and \
                   not block.parent.warned_about_mem and \
                   (instr.get_size() > budget) and not instr._protect:
                    print('WARNING: Order of memory instructions ' \
                        'not preserved due to long vector, errors possible')
                    block.parent.warned_about_mem = True
            else:
                handle_mem_access(addr, reg_type, last_access_this_kind,
                                  last_access_other_kind)
            if block.warn_about_mem and \
               not block.parent.warned_about_mem and \
               not isinstance(instr, DirectMemoryInstruction) and \
               not instr._protect:
                print('WARNING: Order of memory instructions ' \
                    'not preserved, errors possible')
                block.parent.warned_about_mem = True

        def strict_mem_access(n, last_this_kind, last_other_kind):
            if last_other_kind and last_this_kind and \
               last_other_kind[-1] > last_this_kind[-1]:
                last_this_kind[:] = []
            last_this_kind.append(n)
            if last_this_kind == last_mem_write:
                insts = itertools.chain(last_other_kind, last_this_kind)
            else:
                insts = last_other_kind
            for i in insts:
                add_edge(i, n)

        def keep_order(instr, n, t, arg_index=None):
            if arg_index is None:
                player = None
            else:
                player = instr.args[arg_index]
            if last[t][player] is not None:
                add_edge(last[t][player], n)
            last[t][player] = n

        def keep_merged_order(instr, n, t):
            if last_input[t][0] is not None:
                if instr.merge_id() != \
                   block.instructions[last_input[t][0]].merge_id():
                    add_edge(last_input[t][0], n)
                    last_input[t][1] = last_input[t][0]
                elif last_input[t][1] is not None:
                    add_edge(last_input[t][1], n)
            last_input[t][0] = n

        def keep_text_order(inst, n):
            if inst.get_players() is None:
                # switch
                for x in list(last_input.keys()):
                    if isinstance(x, int):
                        add_edge(last_input[x][0], n)
                        del last_input[x]
                keep_merged_order(instr, n, None)
            elif last_input[None][0] is not None:
                keep_merged_order(instr, n, None)
            else:
                for player in inst.get_players():
                    keep_merged_order(instr, n, player)

        for n,instr in enumerate(block.instructions):
            outputs,inputs = instr.get_def(), instr.get_used()

            G.add_node(n)

            # if options.debug:
            #     col = colordict[instr.__class__.__name__]
            #     G.add_node(n, color=col, label=str(instr))
            for reg in outputs:
                if reg.vector and instr.is_vec():
                    for i in reg.vector:
                        write(i, n)
                else:
                    write(reg, n)

            for reg in inputs:
                if reg.vector and instr.is_vec():
                    for i in reg.vector:
                        read(i, n)
                else:
                    read(reg, n)

            # will be merged
            if isinstance(instr, TextInputInstruction):
                keep_text_order(instr, n)
            elif isinstance(instr, RawInputInstruction):
                keep_merged_order(instr, n, RawInputInstruction)
            elif isinstance(instr, matmulsm_class):
                if options.preserve_mem_order:
                    strict_mem_access(n, last_mem_read, last_mem_write)
                else:
                    if instr.indices_values is not None and instr.first_factor_base_addresses is not None and instr.second_factor_base_addresses is not None:
                        # Determine which values get accessed by the MATMULSM instruction and only add the according dependencies.
                        for matmul_idx in range(len(instr.first_factor_base_addresses)):
                            start_time = time.time()
                            first_base = instr.first_factor_base_addresses[matmul_idx]
                            second_base = instr.second_factor_base_addresses[matmul_idx]

                            first_factor_row_indices = instr.indices_values[4 * matmul_idx]
                            first_factor_column_indices = instr.indices_values[4 * matmul_idx + 1]
                            second_factor_row_indices = instr.indices_values[4 * matmul_idx + 2]
                            second_factor_column_indices = instr.indices_values[4 * matmul_idx + 3]

                            first_factor_row_length = instr.args[12 * matmul_idx + 10]
                            second_factor_row_length = instr.args[12 * matmul_idx + 11]

                            # Due to the potentially very large number of inputs on large matrices, adding dependencies to
                            # all inputs may take a long time. Therefore, we only partially build the dependencies on
                            # large matrices and output a warning.
                            # The threshold of 2_250_000 values per matrix is equivalent to multiplying two 1500x1500
                            # matrices. Experiments showed that multiplying two 1700x1700 matrices requires roughly 10 seconds on an i7-1370P,
                            # so this threshold should lead to acceptable compile times even on slower processors.
                            first_factor_total_number_of_values = instr.args[12 * matmul_idx + 3] * instr.args[12 * matmul_idx + 4]
                            second_factor_total_number_of_values = instr.args[12 * matmul_idx + 4] * instr.args[12 * matmul_idx + 5]
                            max_dependencies_per_matrix = \
                                self.block.parent.program.budget
                            if first_factor_total_number_of_values > max_dependencies_per_matrix or second_factor_total_number_of_values > max_dependencies_per_matrix:
                                if block.warn_about_mem and not block.parent.warned_about_mem:
                                    print('WARNING: Order of memory instructions not preserved due to long vector, errors possible')
                                    block.parent.warned_about_mem = True

                            # Add dependencies to the first factor.
                            # If the size of the matrix exceeds the max_dependencies_per_matrix, only a limited number
                            # of rows will be processed.
                            for i in range(min(instr.args[12 * matmul_idx + 3], max_dependencies_per_matrix // instr.args[12 * matmul_idx + 4] + 1)):
                                for k in range(instr.args[12 * matmul_idx + 4]):
                                    first_factor_addr = first_base + \
                                                        first_factor_row_length * first_factor_row_indices[i] + \
                                                        first_factor_column_indices[k]
                                    handle_mem_access(first_factor_addr, 's', last_mem_read_of, last_mem_write_of)

                            # Add dependencies to the second factor.
                            # If the size of the matrix exceeds the max_dependencies_per_matrix, only a limited number
                            # of rows will be processed.
                            for k in range(min(instr.args[12 * matmul_idx + 4], max_dependencies_per_matrix // instr.args[12 * matmul_idx + 5] + 1)):
                                if (time.time() - start_time) > 10:
                                    # Abort building the dependencies if that takes too much time.
                                    if block.warn_about_mem and not block.parent.warned_about_mem:
                                        print('WARNING: Order of memory instructions not preserved due to long vector, errors possible')
                                        block.parent.warned_about_mem = True
                                    break

                                for j in range(instr.args[12 * matmul_idx + 5]):
                                    second_factor_addr = second_base + \
                                                         second_factor_row_length * second_factor_row_indices[k] + \
                                                         second_factor_column_indices[j]
                                    handle_mem_access(second_factor_addr, 's', last_mem_read_of, last_mem_write_of)
                    else:
                        # If the accessed values cannot be determined, be cautious I guess.
                        for i in last_mem_write_of.values():
                            for j in i:
                                add_edge(j, n)

            if isinstance(instr, merge_classes):
                open_nodes.add(n)
                G.add_node(n, merges=[])
                # the following must happen after adding the edge
                self.real_depths[n] += 1
                depth = depths[n] + 1

                # find first depth that has the right type and isn't full
                skipped_depths = set()
                while (depth in round_type and \
                       round_type[depth] != instr.merge_id()) or \
                      (int(options.max_parallel_open) > 0 and \
                      parallel_open[depth] >= int(options.max_parallel_open)):
                    skipped_depths.add(depth)
                    depth = next_available_depth.get((type(instr), depth), \
                                                     depth + 1)
                for d in skipped_depths:
                    next_available_depth[type(instr), d] = depth

                round_type[depth] = instr.merge_id()
                if int(options.max_parallel_open) > 0:
                    parallel_open[depth] += len(instr.args) * instr.get_size()
                depths[n] = depth

            if isinstance(instr, ReadMemoryInstruction):
                if options.preserve_mem_order:
                    strict_mem_access(n, last_mem_read, last_mem_write)
                elif instr._protect:
                    scope = mem_scopes[instr._protect]
                    strict_mem_access(n, scope.read, scope.write)
                if not options.preserve_mem_order:
                    mem_access(n, instr, last_mem_read_of, last_mem_write_of)
            elif isinstance(instr, WriteMemoryInstruction):
                if options.preserve_mem_order:
                    strict_mem_access(n, last_mem_write, last_mem_read)
                elif instr._protect:
                    scope = mem_scopes[instr._protect]
                    strict_mem_access(n, scope.write, scope.read)
                if not options.preserve_mem_order:
                    mem_access(n, instr, last_mem_write_of, last_mem_read_of)
            # keep I/O instructions in order
            elif isinstance(instr, IOInstruction):
                if last_print_str is not None:
                    add_edge(last_print_str, n)
                last_print_str = n
            elif isinstance(instr, PublicFileIOInstruction):
                keep_order(instr, n, PublicFileIOInstruction)
            elif isinstance(instr, prep_class):
                keep_order(instr, n, instr.args[0])
            elif isinstance(instr, StackInstruction):
                keep_order(instr, n, StackInstruction)
            elif isinstance(instr, applyshuffle):
                for handle in instr.handles():
                    shuffles[handle].add(n)
            elif isinstance(instr, delshuffle):
                for i_inst in shuffles[instr.args[0]]:
                    add_edge(i_inst, n)

            if not G.pred[n]:
                self.sources.append(n)

            if n % 1000000 == 0 and n > 0:
                print("Processed dependency of %d/%d instructions at" % \
                    (n, len(block.instructions)), time.asctime())

    def merge_nodes(self, i, j):
        """ Merge node j into i, removing node j """
        G = self.G
        if j in G[i]:
            G.remove_edge(i, j)
        if i in G[j]:
            G.remove_edge(j, i)
        G.add_edges_from(list(zip(itertools.cycle([i]), G[j], [G.weights[(j,k)] for k in G[j]])))
        G.add_edges_from(list(zip(G.pred[j], itertools.cycle([i]), [G.weights[(k,j)] for k in G.pred[j]])))
        G.get_attr(i, 'merges').append(j)
        G.remove_node(j)

    def eliminate_dead_code(self, only_ldint=False):
        instructions = self.instructions
        G = self.G
        merge_nodes = self.open_nodes
        count = 0
        open_count = 0
        stats = defaultdict(lambda: 0)
        for i,inst in zip(range(len(instructions) - 1, -1, -1), reversed(instructions)):
            if inst is None:
                continue
            if only_ldint and not isinstance(inst, ldint_class):
                continue
            can_eliminate_defs = True
            for reg in inst.get_def():
                for dup in reg.duplicates:
                    if not (dup.can_eliminate and reduce(
                            operator.and_,
                            (x.can_eliminate for x in dup.vector), True)):
                        can_eliminate_defs = False
                        break
            # remove if instruction has result that isn't used
            unused_result = not G.degree(i) and len(list(inst.get_def())) \
                and can_eliminate_defs \
                and not isinstance(inst, (DoNotEliminateInstruction))
            def eliminate(i):
                G.remove_node(i)
                merge_nodes.discard(i)
                stats[type(instructions[i]).__name__] += 1
                for reg in instructions[i].get_def():
                    self.block.parent.program.base_addresses.pop(reg)
                instructions[i] = None
            if unused_result:
                eliminate(i)
                count += 1
        if count > 0 and self.block.parent.program.verbose:
            print('Eliminated %d dead instructions, among which %d opens: %s' \
                % (count, open_count, dict(stats)))

    def print_graph(self, filename):
        f = open(filename, 'w')
        print('digraph G {', file=f)
        for i in range(self.G.n):
            for j in self.G[i]:
                print('"%d: %s" -> "%d: %s";' % \
                    (i, self.instructions[i], j, self.instructions[j]), file=f)
        print('}', file=f)
        f.close()

    def print_depth(self, filename):
        f = open(filename, 'w')
        for i in range(self.G.n):
            print('%d: %s' % (self.depths[i], self.instructions[i]), file=f)
        f.close()

class RegintOptimizer:
    def __init__(self):
        self.cache = util.dict_by_id()
        self.offset_cache = util.dict_by_id()
        self.rev_offset_cache = {}
        self.range_cache = util.dict_by_id()

    def add_offset(self, res, new_base, new_offset, multiplier):
        self.offset_cache[res] = new_base, new_offset, multiplier
        if (new_base.i, new_offset, multiplier) not in self.rev_offset_cache:
            self.rev_offset_cache[new_base.i, new_offset, multiplier] = res

    def run(self, instructions, program):
        changed = defaultdict(int)
        for i, inst in enumerate(instructions):
            pre = inst
            if isinstance(inst, ldint_class):
                self.cache[inst.args[0]] = inst.args[1]
            elif isinstance(inst, incint):
                if inst.args[2] == 1 and inst.args[3] == 1 and \
                   inst.args[4] == len(inst.args[0]) and \
                   inst.args[1] in self.cache:
                    self.range_cache[inst.args[0]] = \
                        len(inst.args[0]), self.cache[inst.args[1]]
            elif isinstance(inst, IntegerInstruction):
                if inst.args[1] in self.cache and inst.args[2] in self.cache:
                    res = inst.op(self.cache[inst.args[1]],
                                  self.cache[inst.args[2]])
                    if abs(res) < 2 ** 31:
                        self.cache[inst.args[0]] = res
                        instructions[i] = ldint(inst.args[0], res,
                                                add_to_prog=False)
                elif isinstance(inst, addint_class):
                    def f(base, delta_reg):
                        delta = self.cache[delta_reg]
                        if base in self.offset_cache:
                            reg, offset, mult = self.offset_cache[base]
                            new_base, new_offset = reg, offset + delta
                        else:
                            new_base, new_offset = base, delta
                            mult = 1
                        self.add_offset(inst.args[0], new_base, new_offset,
                                        mult)
                    if inst.args[1] in self.cache:
                        f(inst.args[2], inst.args[1])
                    elif inst.args[2] in self.cache:
                        f(inst.args[1], inst.args[2])
                elif isinstance(inst, subint_class):
                    def f(reg, cached, reverse):
                        delta = self.cache[cached]
                        if reg in self.offset_cache:
                            reg, offset, mult = self.offset_cache[reg]
                            new_base = reg
                            if reverse:
                                new_offset = offset - delta
                                mult *= -1
                            else:
                                new_offset = offset + delta
                        else:
                            new_base = reg
                            new_offset = delta if reverse else -delta
                            mult = 1
                        self.add_offset(inst.args[0], new_base, new_offset,
                                        -mult)
                    if inst.args[1] in self.cache:
                        f(inst.args[2], inst.args[1], False)
                    elif inst.args[2] in self.cache:
                        f(inst.args[1], inst.args[2], True)
            elif isinstance(inst, IndirectMemoryInstruction):
                if inst.args[1] in self.cache:
                    instructions[i] = inst.get_direct(self.cache[inst.args[1]])
                    instructions[i]._protect = inst._protect
                elif inst.args[1] in self.offset_cache:
                    base, offset, mult = self.offset_cache[inst.args[1]]
                    addr = self.rev_offset_cache[base.i, offset, mult]
                    inst.args[1] = addr
                elif inst.args[1] in self.range_cache:
                    size, base = self.range_cache[inst.args[1]]
                    if size == len(inst.args[0]):
                        instructions[i] = inst.get_direct(base)
            elif type(inst) == convint_class:
                if inst.args[1] in self.cache:
                    res = self.cache[inst.args[1]]
                    self.cache[inst.args[0]] = res
                    if abs(res) < 2 ** 31:
                        instructions[i] = ldi(inst.args[0], res,
                                              add_to_prog=False)
            elif isinstance(inst, mulm_class):
                if inst.args[2] in self.cache:
                    op = self.cache[inst.args[2]]
                    if op == 0:
                        instructions[i] = ldsi(inst.args[0], 0,
                                               add_to_prog=False)
            elif isinstance(inst, (crash, cond_print_str, cond_print_plain)):
                if inst.args[0] in self.cache:
                    cond = self.cache[inst.args[0]]
                    if not cond:
                        instructions[i] = None
            if pre != instructions[i]:
                changed[type(inst).__name__] += 1
        pre = len(instructions)
        instructions[:] = list(filter(lambda x: x is not None, instructions))
        post = len(instructions)
        if changed and program.options.verbose:
            print('regint optimizer changed:', dict(changed))
        if pre != post and program.options.verbose:
            print('regint optimizer removed %d instructions' % (pre - post))
