import inspect
import os
import re
import sys
import tempfile
import subprocess
from optparse import OptionParser

from Compiler.exceptions import CompilerError

from .GC import types as GC_types
from .program import Program, defaults


class Compiler:
    singleton = None

    def __init__(self, custom_args=None, usage=None, execute=False,
                 split_args=False):
        if Compiler.singleton:
            raise CompilerError(
                "Cannot have more than one compiler instance. "
                "It's not possible to run direct compilation programs with "
                "compile.py or compile-run.py.")
        else:
            Compiler.singleton = self

        if usage:
            self.usage = usage
        else:
            self.usage = "usage: %prog [options] filename [args]"
        self.execute = execute
        self.runtime_args = []

        if split_args:
            if custom_args is None:
                args = sys.argv
            else:
                args = custom_args
            try:
                split = args.index('--')
            except ValueError:
                split = len(args)

            custom_args = args[1:split]
            self.runtime_args = args[split + 1:]

        self.custom_args = custom_args
        self.build_option_parser()
        self.VARS = {}
        self.root = os.path.dirname(__file__) + '/..'

    def build_option_parser(self):
        if self.execute:
            class MyOptionParser(OptionParser):
                def error(self, err):
                    if "no such option" in err:
                        print(self.get_usage(), file=sys.stderr)
                        print("error:", err, file=sys.stderr)
                        print("Remember to put run-time arguments "
                              "after '--' as shown above", file=sys.stderr)
                        sys.exit(1)
                    else:
                        OptionParser.error(self, err)
        else:
            MyOptionParser = OptionParser
        parser = MyOptionParser(usage=self.usage)
        parser.add_option(
            "-n",
            "--nomerge",
            action="store_false",
            dest="merge_opens",
            default=defaults.merge_opens,
            help="don't attempt to merge open instructions",
        )
        parser.add_option("-o", "--output", dest="outfile", help="specify output file")
        parser.add_option(
            "-a",
            "--asm-output",
            dest="asmoutfile",
            help="asm output file for debugging",
        )
        parser.add_option(
            "-g",
            "--galoissize",
            dest="galois",
            default=defaults.galois,
            help="bit length of Galois field",
        )
        parser.add_option(
            "-d",
            "--debug",
            action="store_true",
            dest="debug",
            help="keep track of trace for debugging",
        )
        parser.add_option(
            "-c",
            "--comparison",
            dest="comparison",
            default="log",
            help="comparison variant: log|plain|inv|sinv",
        )
        parser.add_option(
            "-M",
            "--preserve-mem-order",
            action="store_true",
            dest="preserve_mem_order",
            default=defaults.preserve_mem_order,
            help="preserve order of memory instructions; possible efficiency loss",
        )
        parser.add_option(
            "-O",
            "--optimize-hard",
            action="store_true",
            dest="optimize_hard",
            help="lower number of rounds at higher compilation cost "
            "(disables -C and increases the budget to 100000)",
        )
        parser.add_option(
            "-u",
            "--noreallocate",
            action="store_true",
            dest="noreallocate",
            default=defaults.noreallocate,
            help="don't reallocate",
        )
        parser.add_option(
            "-m",
            "--max-parallel-open",
            dest="max_parallel_open",
            default=defaults.max_parallel_open,
            help="restrict number of parallel opens",
        )
        parser.add_option(
            "-D",
            "--dead-code-elimination",
            action="store_true",
            dest="dead_code_elimination",
            default=defaults.dead_code_elimination,
            help="eliminate instructions with unused result",
        )
        parser.add_option(
            "-p",
            "--profile",
            action="store_true",
            dest="profile",
            help="profile compilation",
        )
        parser.add_option(
            "-s",
            "--stop",
            action="store_true",
            dest="stop",
            help="stop on register errors",
        )
        parser.add_option(
            "-R",
            "--ring",
            dest="ring",
            default=defaults.ring,
            help="bit length of ring (default: 0 for field)",
        )
        parser.add_option(
            "-B",
            "--binary",
            dest="binary",
            default=defaults.binary,
            help="bit length of sint in binary circuit (default: 0 for arithmetic)",
        )
        parser.add_option(
            "-G",
            "--garbled-circuit",
            dest="garbled",
            action="store_true",
            help="compile for binary circuits only (default: false)",
        )
        parser.add_option(
            "-F",
            "--field",
            dest="field",
            default=defaults.field,
            help="bit length of sint modulo prime (default: 64)",
        )
        parser.add_option(
            "-P",
            "--prime",
            dest="prime",
            default=defaults.prime,
            help="use bit decomposition with a specified prime modulus "
            "for non-linear computation (default: use the masking approach). "
            "Don't use this unless you're certain that you need it.",
        )
        parser.add_option(
            "-I",
            "--insecure",
            action="store_true",
            dest="insecure",
            help="activate insecure functionality for benchmarking",
        )
        parser.add_option(
            "-b",
            "--budget",
            dest="budget",
            help="set budget for optimized loop unrolling (default: %d)" % \
            defaults.budget,
        )
        parser.add_option(
            "-X",
            "--mixed",
            action="store_true",
            dest="mixed",
            help="mixing arithmetic and binary computation",
        )
        parser.add_option(
            "-Y",
            "--edabit",
            action="store_true",
            dest="edabit",
            help="mixing arithmetic and binary computation using edaBits",
        )
        parser.add_option(
            "-Z",
            "--split",
            default=defaults.split,
            dest="split",
            help="mixing arithmetic and binary computation "
            "using direct conversion if supported "
            "(number of parties as argument)",
        )
        parser.add_option(
            "--invperm",
            action="store_true",
            dest="invperm",
            help="speedup inverse permutation (only use in two-party, "
            "semi-honest environment)"
        )
        parser.add_option(
            "-C",
            "--CISC",
            action="store_true",
            dest="cisc",
            help="faster CISC compilation mode "
            "(used by default unless -O is given)",
        )
        parser.add_option(
            "-K",
            "--keep-cisc",
            dest="keep_cisc",
            help="don't translate CISC instructions",
        )
        parser.add_option(
            "-l",
            "--flow-optimization",
            action="store_true",
            dest="flow_optimization",
            help="optimize control flow",
        )
        parser.add_option(
            "-v",
            "--verbose",
            action="store_true",
            dest="verbose",
            help="more verbose output",
        )
        parser.add_option(
            "--papers",
            action="store_true",
            dest="papers",
            help="output recommended reading",
        )
        if self.execute:
            parser.add_option(
                "-E",
                "--execute",
                dest="execute",
                help="protocol to execute with",
            )
            parser.add_option(
                "-H",
                "--hostfile",
                dest="hostfile",
                help="hosts to execute with",
            )
            parser.add_option(
                "-t",
                "--tidy_output",
                action="store_true",
                dest="tidy_output",
                help="make output prints tidy and grouped by party (note: delays the prints)",
            )
        else:
            parser.add_option(
                "-E",
                "--execute",
                dest="execute",
                help="protocol to optimize for",
            )
        self.parser = parser

    def base_protocol(self):
        if self.options.execute:
            return re.sub("-(prep|online)$", "", self.options.execute)

    def parse_args(self):
        self.options, self.args = self.parser.parse_args(self.custom_args)
        if self.options.verbose:
            self.runtime_args += ["--verbose"]
        if self.execute:
            if not self.options.execute:
                if len(self.args) > 1:
                    self.options.execute = self.args.pop(0)
                else:
                    self.parser.error("missing protocol name")
            if self.options.hostfile:
                try:
                    open(self.options.hostfile)
                except:
                    print('hostfile %s not found' % self.options.hostfile,
                          file=sys.stderr)
                    exit(1)
        if self.options.execute:
            self.options.execute = re.sub(r"-party\.x$", "",
                                          self.options.execute)
            self.options.execute = re.sub("malicious-", "mal-",
                                          self.options.execute)
            for s, l in self.match.items():
                if self.options.execute == l:
                    self.options.execute = s
                    break
        if self.options.execute:
            protocol = self.base_protocol()
            if protocol.find("ring") >= 0 or protocol.find("2k") >= 0 or \
               protocol.find("brain") >= 0 or protocol == "emulate" or \
               protocol in ("astra", "trio"):
                if not (self.options.ring or self.options.binary):
                    self.options.ring = "64"
                if self.options.field:
                    raise CompilerError(
                        "field option not compatible with %s" % protocol)
            else:
                if protocol.find("bin") >= 0 or  protocol.find("ccd") >= 0 or \
                   protocol.find("bmr") >= 0 or \
                   protocol in ("replicated", "tinier", "tiny", "yao"):
                    if not self.options.binary:
                        self.options.binary = "32"
                    if self.options.ring or self.options.field:
                        raise CompilerError(
                            "ring/field options not compatible with %s" %
                            protocol)
                if self.options.ring:
                    raise CompilerError(
                        "ring option not compatible with %s" % protocol)
            if protocol == "emulate":
                self.options.keep_cisc = ''
            if protocol.find("bmr") >= 0 or protocol == "yao":
                self.options.garbled = True

    def build_program(self, name=None):
        self.prog = Program(self.args, self.options, name=name)
        if self.options.execute:
            if self.base_protocol() in \
               ("emulate", "ring", "rep-field", "rep4-ring", "astra", "trio"):
                self.prog.use_trunc_pr = True
            if not self.prog.options.split:
                if self.base_protocol() in (
                        "ring", "ps-rep-ring", "sy-rep-ring", "astra", "trio"):
                    self.prog.use_split(3)
                if self.base_protocol() in ("ring", "astra", "trio"):
                    self.prog.use_unsplit = 1
                if self.options.execute in ("semi2k",):
                    self.prog.use_split(int(os.getenv("PLAYERS", 2)))
                if self.options.execute in ("rep4-ring",):
                    self.prog.use_split(4)
            if self.options.execute.find("dealer") >= 0:
                self.prog.use_edabit(True)
            if self.base_protocol() in ("astra", "trio"):
                self.prog.use_mulm = False

    def build_vars(self):
        from . import comparison, floatingpoint, instructions, library, types

        # add all instructions to the program VARS dictionary
        instr_classes = inspect.getmembers(instructions, inspect.isclass)

        for mod in (types, GC_types):
            instr_classes += [
                t
                for t in inspect.getmembers(mod, inspect.isclass)
                if t[1].__module__ == mod.__name__
            ]

        instr_classes += [
            t
            for t in inspect.getmembers(library, inspect.isfunction)
            if not t[0].startswith("_")
        ]

        for name, op in instr_classes:
            self.VARS[name] = op

        # backward compatibility for deprecated classes
        self.VARS["sbitint"] = GC_types.sbitintvec
        self.VARS["sbitfix"] = GC_types.sbitfixvec

        # add open and input separately due to name conflict
        self.VARS["vopen"] = instructions.vasm_open
        self.VARS["gopen"] = instructions.gasm_open
        self.VARS["vgopen"] = instructions.vgasm_open
        self.VARS["ginput"] = instructions.gasm_input

        self.VARS["comparison"] = comparison
        self.VARS["floatingpoint"] = floatingpoint

        self.VARS["program"] = self.prog
        if self.options.binary:
            self.sint = GC_types.sbitintvec.get_type(int(self.options.binary))
            self.sfix = GC_types.sbitfixvec
            for i in [
                "cint",
                "cfix",
                "cgf2n",
                "sintbit",
                "sgf2n",
                "sgf2nint",
                "sgf2nuint",
                "sgf2nuint32",
                "sgf2nfloat",
                "cfloat",
                "squant",
            ]:
                class dummy:
                    def __init__(self, *args):
                        raise CompilerError(self.error)
                dummy.error = i + " not available with binary circuits"
                if i in ("cint", "cfix"):
                    dummy.error += ". See https://mp-spdz.readthedocs.io/en/" \
                        "latest/Compiler.html#Compiler.types." + i
                self.VARS[i] = dummy
        else:
            self.sint = types.sint
            self.sfix = types.sfix

        self.VARS["sint"] = self.sint
        self.VARS["sfix"] = self.sfix

    def prep_compile(self, name=None, build=True):
        self.parse_args()
        if len(self.args) < 1 and name is None:
            self.parser.print_help()
            exit(1)
        if build:
            self.build(name=name)

    def build(self, name=None):
        self.build_program(name=name)
        self.build_vars()

    def compile_file(self):
        """Compile a file and output a Program object.

        If options.merge_opens is set to True, will attempt to merge any
        parallelisable open instructions."""
        print("Compiling file", self.prog.infile)
        self.prog.sint = self.sint
        self.prog.sfix = self.sfix

        with open(self.prog.infile, "r") as f:
            changed = False
            if self.options.flow_optimization:
                output = []
                if_stack = []
                for line in f:
                    if if_stack and not re.match(if_stack[-1][0], line):
                        if_stack.pop()
                    m = re.match(
                        r"(\s*)for +([a-zA-Z_]+) +in " r"+range\(([0-9a-zA-Z_.]+)\):",
                        line,
                    )
                    if m:
                        output.append(
                            "%s@for_range_opt(%s)\n" % (m.group(1), m.group(3))
                        )
                        output.append("%sdef _(%s):\n" % (m.group(1), m.group(2)))
                        changed = True
                        continue
                    m = re.match(r"(\s*)if(\W.*):", line)
                    if m:
                        while if_stack and if_stack[-1][0] == m.group(1):
                            if_stack.pop()
                        if_stack.append((m.group(1), len(output)))
                        output.append("%s@if_(%s)\n" % (m.group(1), m.group(2)))
                        output.append("%sdef _():\n" % (m.group(1)))
                        changed = True
                        continue
                    m = re.match(r"(\s*)elif\s+", line)
                    if m:
                        raise CompilerError("elif not supported")
                    if if_stack:
                        m = re.match("%selse:" % if_stack[-1][0], line)
                        if m:
                            start = if_stack[-1][1]
                            ws = if_stack[-1][0]
                            output[start] = re.sub(
                                r"^%s@if_\(" % ws, r"%s@if_e(" % ws, output[start]
                            )
                            output.append("%s@else_\n" % ws)
                            output.append("%sdef _():\n" % ws)
                            continue
                    output.append(line)
                if changed:
                    infile = tempfile.NamedTemporaryFile("w+", delete=False)
                    for line in output:
                        infile.write(line)
                    infile.seek(0)
                else:
                    infile = open(self.prog.infile)
            else:
                infile = open(self.prog.infile)

        # make compiler modules directly accessible
        sys.path.insert(0, "%s/Compiler" % self.root)
        # create the tapes
        try:
            exec(compile(infile.read(), infile.name, "exec"), self.VARS)
        except UnboundLocalError:
            raise CompilerError(
                "The above error might mean that you attempted to assign "
                "to a variable in a run-time loop. This is not supported "
                "by the framework, but you can use assignment operations "
                "to variables created outside the loop such as "
                "'array[:] = ...' or 'array.assign(...)' for (multi-)arrays "
                "and 'reg.update(...)' for registers.")
        except TypeError as error:
            if 'list indices must be' in str(error):
                raise CompilerError(
                    "You cannot address Python lists using run-time types "
                    "such as regint. Use Array or MultiArray instead.")
            else:
                raise

        if changed and not self.options.debug:
            os.unlink(infile.name)

        return self.finalize_compile()

    def register_function(self, name=None):
        """
        To register a function to be compiled, use this as a decorator.
        Example:

            @compiler.register_function('test-mpc')
            def test_mpc(compiler):
                ...
        """

        def inner(func):
            self.compile_name = name or func.__name__
            self.compile_function = func
            return func

        return inner

    def compile_func(self):
        if not (hasattr(self, "compile_name") and hasattr(self, "compile_func")):
            raise CompilerError(
                "No function to compile. "
                "Did you decorate a function with @register_function(name)?"
            )
        self.prep_compile(self.compile_name)
        print(
            "Compiling: {} from {}".format(self.compile_name, self.compile_func.__name__)
        )
        self.compile_function()
        self.finalize_compile()

    def finalize_compile(self):
        self.prog.finalize()

        if self.prog.req_num:
            print("Program requires at most:")
            for x in self.prog.req_num.pretty():
                print(x)

        if self.prog.verbose:
            print("Program requires:", repr(self.prog.req_num))
            print("Cost:", 0 if self.prog.req_num is None else self.prog.req_num.cost())
            print("Memory size:", dict(self.prog.allocated_mem))

        comm = self.prog.expected_communication()
        if sum(comm):
            print(
                "Expected communication is %g MB online and %g MB offline." % \
                (comm[0] / 1e6, comm[1] / 1e6))

        return self.prog

    match = {
        "ring": "replicated-ring",
        "rep-field": "replicated-field",
        "replicated": "replicated-bin"
    }

    @classmethod
    def executable_from_protocol(cls, protocol):
        match = cls.match
        if protocol in match:
            protocol = match[protocol]
        if protocol.find("bmr") == -1:
            protocol = re.sub("^mal-", "malicious-", protocol)
        protocol = re.sub("-online$", "", protocol)
        if protocol == "emulate":
            return protocol + ".x"
        else:
            return protocol + "-party.x"

    @classmethod
    def short_protocol_name(cls, protocol):
        for x in cls.match.items():
            if protocol == x[1]:
                return x[0]
        return re.sub('^malicious-', 'mal-', protocol)

    def local_execution(self, args=None):
        if args is None:
            args = self.runtime_args
        executable = self.executable_from_protocol(self.options.execute)
        if not os.path.exists("%s/%s" % (self.root, executable)):
            print("Creating binary for virtual machine...")
            try:
                subprocess.run(["make", executable], check=True, cwd=self.root)
            except:
                raise CompilerError(
                    "Cannot produce %s. " % executable + \
                    "Note that compilation requires a few GB of RAM.")
        vm = "%s/Scripts/%s.sh" % (self.root, self.options.execute)
        sys.stdout.flush()
        print("Compilation finished, running program...", file=sys.stderr)
        sys.stderr.flush()
        os.execl(vm, vm, self.prog.name, *args)

    def remote_execution(self, args=None):
        if args is None:
            args = self.runtime_args
        vm = self.executable_from_protocol(self.options.execute)
        hosts = list(x.strip()
                     for x in filter(None, open(self.options.hostfile)))
        # test availability before compilation
        from fabric import Connection
        import subprocess
        print("Creating static binary for virtual machine...")
        subprocess.run(["make", "static/%s" % vm], check=True, cwd=self.root)

        # transfer files
        import glob
        hostnames = []
        destinations = []
        for host in hosts:
            split = host.split('/', maxsplit=1)
            hostnames.append(split[0])
            if len(split) > 1:
                destinations.append(split[1])
            else:
                destinations.append('.')
        connections = [Connection(hostname) for hostname in hostnames]
        print("Setting up players...")
        lockfile = ".transfer.lock"

        def run(i):
            dest = destinations[i]
            connection = connections[i]
            connection.run(
                "mkdir -p %s/{Player-Data,Programs/{Bytecode,Schedules}} " % \
                dest)
            dest_lockfile = "%s/%s" % (dest, lockfile)
            try:
                connection.run("test -e %s && exit 1; touch %s" % (
                    (dest_lockfile,) * 2))
            except:
                raise Exception(
                    "Problem with %s on %s. You cannot use the same directory "
                    "for several instances (including the control instance). "
                    "Remove %s on %s if this has been left behind from an "
                    "aborted exection." % ((dest_lockfile, hostnames[i]) * 2))
            # executable
            connection.put("%s/static/%s" % (self.root, vm), dest)
            # program
            dest += "/"
            connection.put("Programs/Schedules/%s.sch" % self.prog.name,
                           dest + "Programs/Schedules")
            for filename in glob.glob(
                    "Programs/Bytecode/%s-*.bc" % self.prog.name):
                connection.put(filename, dest + "Programs/Bytecode")
            # inputs
            for filename in glob.glob("Player-Data/Input*-P%d-*" % i):
                connection.put(filename, dest + "Player-Data")
            # key and certificates
            for suffix in ('key', 'pem'):
                connection.put("Player-Data/P%d.%s" % (i, suffix),
                               dest + "Player-Data")
            for filename in glob.glob("Player-Data/*.0"):
                connection.put(filename, dest + "Player-Data")
            connection.run("rm %s" % dest_lockfile)

        def run_with_error(i):
            try:
                run(i)
                copied[i] = True
            except IOError:
                print('IO error when copying files, does %s have enough space?' %
                      hostnames[i])
                raise

        import threading
        import random
        import io

        def run_and_capture_outputs(outputs, fn, i):
            out = fn(i)
            outputs[i] = out

        open(lockfile, "w")
        threads = []
        copied = [False] * len(hosts)
        for i in range(len(hosts)):
            threads.append(threading.Thread(target=run_with_error, args=(i,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        os.remove(lockfile)
        if False in copied:
            print("Error in remote copying, see above")
            sys.exit(1)

        # execution
        threads = []

        # tidy up output prints
        hide_option = False
        if self.options.tidy_output:
            outputs = []
            for i in range(len(connections)):
                outputs += [""]
            hide_option = True
        # random port numbers to avoid conflict
        port = 10000 + random.randrange(40000)
        if '@' in hostnames[0]:
            party0 = hostnames[0].split('@')[1]
        else:
            party0 = hostnames[0]
        if 'rep' not in vm and 'yao' not in vm:
            N = ['-N', str(len(connections))]
        else:
            N = []
        for i in range(len(connections)):
            run = lambda i: connections[i].run(
                "cd %s; ./%s -p %d %s -h %s -pn %d %s" % \
                (destinations[i], vm, i, self.prog.name, party0, port,
                 ' '.join(args + N)), hide=hide_option)
            if self.options.tidy_output:
                threads.append(threading.Thread(target=run_and_capture_outputs, args=(outputs, run, i,)))
            else:
                threads.append(threading.Thread(target=run, args=(i,)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if self.options.tidy_output:
            for out in outputs:
                print(out)
