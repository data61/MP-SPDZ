"""
This module defines functions directly available in high-level programs,
in particularly providing flow control and output.
"""

from Compiler.types import cint,sint,cfix,sfix,sfloat,MPCThread,Array,MemValue,cgf2n,sgf2n,_number,_mem,_register,regint,Matrix,_types, cfloat, _single, localint, personal, copy_doc, _vec, SubMultiArray, _secret
from Compiler.instructions import *
from Compiler.util import tuplify,untuplify,is_zero
from Compiler.allocator import RegintOptimizer, AllocPool
from Compiler.program import Tape
from Compiler import instructions,instructions_base,comparison,util,types
import inspect,math
import random
import collections
import operator
import copy
from functools import reduce

def get_program():
    return instructions.program
def get_tape():
    return get_program().curr_tape
def get_block():
    return get_program().curr_block

def vectorize(function):
    def vectorized_function(*args, **kwargs):
        if len(args) > 0 and 'size' in dir(args[0]):
            instructions_base.set_global_vector_size(args[0].size)
            res = function(*args, **kwargs)
            instructions_base.reset_global_vector_size()
        elif 'size' in kwargs:
            instructions_base.set_global_vector_size(kwargs['size'])
            del kwargs['size']
            res = function(*args, **kwargs)
            instructions_base.reset_global_vector_size()
        else:
            res = function(*args, **kwargs)
        return res
    vectorized_function.__name__ = function.__name__
    copy_doc(vectorized_function, function)
    return vectorized_function

def set_instruction_type(function):
    def instruction_typed_function(*args, **kwargs):
        if len(args) > 0 and isinstance(args[0], Tape.Register):
            if args[0].is_gf2n:
                instructions_base.set_global_instruction_type('gf2n')
            else:
                instructions_base.set_global_instruction_type('modp')                
            res = function(*args, **kwargs)
            instructions_base.reset_global_instruction_type()
        else:
            res = function(*args, **kwargs)
        return res
    instruction_typed_function.__name__ = function.__name__
    return instruction_typed_function


def _expand_to_print(val):
    return ('[' + ', '.join('%s' for i in range(len(val))) + ']',) + tuple(val)

def print_str(s, *args, print_secrets=False):
    """ Print a string, with optional args for adding
    variables/registers with ``%s``.

    :param s: format string
    :param args: arguments (any type)
    :param print_secrets: whether to output secret shares

    """
    def print_plain_str(ss):
        """ Print a plain string (no custom formatting options) """
        ss = bytearray(ss, 'utf8')
        i = 1
        while 4*i <= len(ss):
            print_char4(ss[4*(i-1):4*i])
            i += 1
        i = 4*(i-1)
        while i < len(ss):
            print_char(ss[i])
            i += 1

    if len(args) != s.count('%s'):
        raise CompilerError('Incorrect number of arguments for string format:', s)
    substrings = s.split('%s')
    def secret_error(x):
        raise CompilerError(
            'Cannot print secret value %s, activate printing of shares with '
            "'print_secrets=True'" % args[i])
    for i,ss in enumerate(substrings):
        print_plain_str(ss)
        if i < len(args):
            if isinstance(args[i], MemValue):
                val = args[i].read()
            else:
                val = args[i]
            if isinstance(val, Tape.Register):
                from Compiler.GC.types import sbits
                if val.is_clear:
                    val.print_reg_plain()
                elif print_secrets and isinstance(val, (_secret, sbits)):
                    val.output()
                else:
                    secret_error(args[i])
            elif isinstance(val, cfix):
                val.print_plain()
            elif isinstance(val, sfix) or isinstance(val, sfloat):
                if print_secrets:
                    val.output()
                else:
                    secret_error()
            elif isinstance(val, cfloat):
                val.print_float_plain()
            elif isinstance(val, (list, tuple)):
                print_str(*_expand_to_print(val), print_secrets=print_secrets)
            elif isinstance(val, (Array, SubMultiArray)):
                val.output(print_secrets=print_secrets)
            else:
                try:
                    val.output()
                except (AttributeError, TypeError):
                    print_plain_str(str(val))

def print_ln(s='', *args, **kwargs):
    """ Print line, with optional args for adding variables/registers
    with ``%s``. By default only player 0 outputs, but the ``-I``
    command-line option changes that.

    :param s: Python string with same number of ``%s`` as length of :py:obj:`args`
    :param args: list of public values (regint/cint/int/cfix/cfloat/localint)
    :param print_secrets: whether to output secret shares

    Example:

    .. code::

        print_ln('a is %s.', a.reveal())
    """
    print_str(str(s) + '\n', *args, **kwargs)


def print_without_ln(s='', *args, **kwargs):
    """ Print line, with optional args for adding variables/registers
    with ``%s``. By default only player 0 outputs, but the ``-I``
    command-line option changes that.

    :param s: Python string with same number of ``%s`` as length of :py:obj:`args`
    :param args: list of public values (regint/cint/int/cfix/cfloat/localint)
    :param print_secrets: whether to output secret shares

    Example:

    .. code::

        print_ln('a is %s.', a.reveal())
    """
    print_str(str(s), *args, **kwargs)


def print_both(s, end='\n'):
    """ Print line during compilation and execution. """
    print(s, end=end)
    print_str(s + end)

def print_ln_if(cond, ss, *args):
    """ Print line if :py:obj:`cond` is true. The further arguments
    are treated as in :py:func:`print_str`/:py:func:`print_ln`.

    :param cond: regint/cint/int/localint
    :param ss: Python string
    :param args: list of public values

    Example:

    .. code::

        print_ln_if(get_player_id() == 0, 'Player 0 here')
    """
    print_str_if(cond, ss + '\n', *args)

def print_str_if(cond, ss, *args):
    """ Print string conditionally. See :py:func:`print_ln_if` for details. """
    if util.is_constant(cond):
        if cond:
            print_str(ss, *args)
    else:
        subs = ss.split('%s')
        assert len(subs) == len(args) + 1
        if isinstance(cond, localint):
            cond = cond._v
        for i, s in enumerate(subs):
            if i != 0:
                val = args[i - 1]
                try:
                    val.output_if(cond)
                except:
                    if isinstance(val, (list, tuple, Array)):
                        print_str_if(cond, *_expand_to_print(val))
                    else:
                        print_str_if(cond, str(val))
            s = bytearray(s, 'utf8')
            s += b'\0' * ((-len(s)) % 4)
            while s:
                cond.print_if(s[:4])
                s = s[4:]

def print_ln_to(player, ss, *args):
    """ Print line at :py:obj:`player` only. Note that printing is
    disabled by default except at player 0. Activate interactive mode
    with `-I` or use `-OF .` to enable it for all players.

    :param player: int
    :param ss: Python string
    :param args: list of values known to :py:obj:`player`

    Example::

        print_ln_to(player, 'output for %s: %s', player, x.reveal_to(player))
    """
    cond = player == get_player_id()
    new_args = []
    for arg in args:
        if isinstance(arg, personal):
            if util.is_constant(arg.player) ^ util.is_constant(player):
                match = False
            else:
                if util.is_constant(player):
                    match = arg.player == player
                else:
                    match = id(arg.player) == id(player)
            if not match:
                raise CompilerError('player mismatch in personal printing')
            new_args.append(arg._v)
        else:
            new_args.append(arg)
    print_ln_if(cond, ss, *new_args)

def print_float_precision(n):
    """ Set the precision for floating-point printing.

    :param n: number of digits (int) """
    print_float_prec(n)

def runtime_error(msg='', *args):
    """ Print an error message and abort the runtime.
    Parameters work as in :py:func:`print_ln` """
    print_str('User exception: ')
    print_ln(msg, *args)
    crash()

def runtime_error_if(condition, msg='', *args):
    """ Conditionally print an error message and abort the runtime.

    :param condition: regint/cint/int/cbit
    :param msg: message
    :param args: list of public values to fit ``%s`` in the message

    """
    print_ln_if(condition, msg, *args)
    crash(condition)

def crash(condition=None):
    """ Crash virtual machine.

    :param condition: crash if true (default: true)

    """
    if isinstance(condition, localint):
        # allow crash on local values
        condition = condition._v
    if condition is None:
        condition = regint(1)
    instructions.crash(regint.conv(condition))

def public_input():
    """ Public input read from ``Programs/Public-Input/<progname>``. """
    res = cint()
    pubinput(res)
    return res

# mostly obsolete functions
# use the equivalent from types.py

@vectorize
def store_in_mem(value, address):
    if isinstance(value, int):
        value = regint(value)
    try:
        value.store_in_mem(address)
    except AttributeError:
        if isinstance(value, (list, tuple)):
            for i, x in enumerate(value):
                store_in_mem(x, address + i)
            return
        # legacy
        if value.is_clear:
            if isinstance(address, cint):
                stmci(value, address)
            else:
                stmc(value, address)
        else:
            if isinstance(address, cint):
                stmsi(value, address)
            else:
                stms(value, address)

@set_instruction_type
@vectorize
def reveal(secret):
    try:
        return secret.reveal()
    except AttributeError:
        if secret.is_clear:
            return secret
        if secret.is_gf2n:
            res = cgf2n()
        else:
            res = cint()
        instructions.asm_open(True, res, secret)
        return res

@vectorize
def get_thread_number():
    """ Returns the thread number. """
    res = regint()
    ldtn(res)
    return res

@vectorize
def get_arg():
    """ Returns the thread argument. """
    res = regint()
    ldarg(res)
    return res

def get_cmdline_arg(idx):
    """ Return run-time command-line argument. """
    res = regint()
    cmdlinearg(res, regint.conv(idx))
    return localint(res)

def make_array(l, t=None):
    if isinstance(l, types._structure):
        res = Array(len(l), t or type(l))
        res[:] = l
    else:
        l = list(l)
        res = Array(len(l), t or type(l[0]) if l else cint)
        res.assign(l)
    return res


class FunctionTapeCall:
    def __init__(self, thread, base, bases):
        self.thread = thread
        self.base = base
        self.bases = bases
    def start(self):
        self.thread.start(self.base)
        return self
    def join(self):
        self.thread.join()
        if self.base is not None:
            instructions.program.free(self.base, 'ci')

class Function:
    def __init__(self, function, name=None, compile_args=[]):
        self.last_key = None
        self.function = function
        self.name = name
        if name is None:
            self.name = self.function.__name__
        self.compile_args = compile_args
    def __call__(self, *args):
        args = tuple(arg.read() if isinstance(arg, MemValue) else arg for arg in args)
        runtime_args = []
        reg_args = []
        key = self.base_key(),
        for i,arg in enumerate(args):
            if isinstance(arg, types._vectorizable):
                key += (arg.shape, arg.value_type)
            else:
                arg = MemValue(arg)
                reg_args.append(arg)
                t = arg.value_type
                key += (arg.size, t)
            runtime_args.append(arg)
        if key != self.last_key:
            # first call
            outer_runtime_args = runtime_args
            def wrapped_function(*compile_args):
                addresses = regint.Array(len(outer_runtime_args),
                                         address=get_arg())
                runtime_args = []
                for i, arg in enumerate(outer_runtime_args):
                    if isinstance(arg, MemValue):
                        arg = arg.value_type.load_mem(
                            address=addresses[i], size=arg.size)
                    runtime_args.append(arg)
                self.result = self.function(
                    *(list(compile_args) + runtime_args))
                return self.result
            self.on_first_call(wrapped_function)
            self.last_key = key
        addresses = regint.Array(len(runtime_args))
        for i, arg in enumerate(reg_args):
            addresses[i] = arg.address
        return self.on_call(addresses._address,
                            [(arg.value_type, arg.address) for arg in reg_args])

class FunctionTape(Function):
    # not thread-safe
    def __init__(self, function, name=None, compile_args=[],
                 single_thread=False):
        Function.__init__(self, function, name, compile_args)
        self.single_thread = single_thread
    def on_first_call(self, wrapped_function):
        self.thread = MPCThread(wrapped_function, self.name,
                                args=self.compile_args,
                                single_thread=self.single_thread)
    def on_call(self, base, bases):
        return FunctionTapeCall(self.thread, base, bases)
    @staticmethod
    def base_key():
        pass

class FunctionCallTape(FunctionTape):
    def __init__(self, *args, **kwargs):
        super(FunctionTape, self).__init__(*args, **kwargs)
        self.instances = {}
    @staticmethod
    def get_key(args, kwargs):
        key = (get_program(),)
        def process_for_key(arg):
            nonlocal key
            if isinstance(arg, types._vectorizable):
                key += (arg.value_type, tuple(arg.shape))
            elif isinstance(arg, Tape.Register):
                key += (type(arg), arg.size)
            elif isinstance(arg, list):
                key += (tuple(arg), 'l')
            else:
                key += (arg,)
        for arg in args:
            process_for_key(arg)
        for name, arg in sorted(kwargs.items()):
            key += (name, 'kw')
            process_for_key(arg)
        return key
    def __call__(self, *args, **kwargs):
        key = self.get_key(args, kwargs)
        if key not in self.instances:
            my_args = []
            def wrapped_function():
                actual_call_args = []
                def process_for_call(arg):
                    if isinstance(arg, Tape.Register):
                        my_arg = arg.same_type()
                        call_arg(my_arg, base.vm_types[my_arg.reg_type])
                        my_args.append(my_arg)
                        return my_arg
                    elif isinstance(arg, types._vectorizable):
                        my_arg = arg.same_shape(address=regint())
                        my_arg.alloc_address = arg.address
                        call_arg(my_arg.address, base.vm_types['ci'])
                        my_args.append(my_arg)
                        my_arg = arg.same_shape(
                            address=MemValue(my_arg.address))
                        return my_arg
                        actual_call_args.append(my_arg)
                    else:
                        my_args.append(arg)
                        return arg
                for arg in args:
                    actual_call_args.append(process_for_call(arg))
                actual_call_kwargs = {}
                for name, arg in sorted(kwargs.items()):
                    actual_call_kwargs[name] = process_for_call(arg)
                self.result = self.function(*actual_call_args,
                                            **actual_call_kwargs)
                if self.result is not None:
                    self.result = list(tuplify(self.result))
                    for i, res in enumerate(self.result):
                        if util.is_constant(res):
                            self.result[i] = regint(res)
            self.on_first_call(wrapped_function, key, my_args)
        for name, arg in sorted(kwargs.items()):
            args += arg,
        return self.on_call(*self.instances[key], args)
    def on_first_call(self, wrapped_function, key, inside_args):
        program = get_program()
        program.curr_tape
        tape_handle = len(program.tapes)
        # entry for recursion
        self.instances[key] = tape_handle, None, inside_args
        assert tape_handle == program.new_tape(
            wrapped_function, name=self.name, args=self.compile_args,
            single_thread=get_tape().singular, finalize=False,
            thread_pool=get_tape().free_threads)
        tape = program.tapes[tape_handle]
        if self.result is not None:
            self.result = list(tuplify(self.result))
            for reg in self.result:
                reg.can_eliminate = False
                tape.return_values.append(reg)
        assert not tape.purged
        get_program().finalize_tape(tape)
        self.instances[key] = tape_handle, self.result, inside_args
    def on_call(self, tape_handle, result, inside_args, args):
        tape = get_program().tapes[tape_handle]
        if tape.ran_threads and tape.free_threads != get_tape().free_threads:
            raise CompilerError(
                'cannot call thread-running tape from another thread')
        assert len(inside_args) == len(args)
        out_result = []
        call_args = []
        if result is not None:
            out_result = [reg.same_type() for reg in result]
            for x, y in zip(out_result, result):
                call_args += [
                    1, instructions_base.vm_types[x.reg_type],
                    x.size, x, y]
        for x, y in zip(inside_args, args):
            if isinstance(x, Tape.Register):
                call_args += [
                    0, instructions_base.vm_types[x.reg_type],
                    x.size, x, y]
            elif isinstance(x, types._vectorizable):
                call_args += [0, base.vm_types['ci'], 1,
                              x.address, regint.conv(y.address)]
        call_tape(tape_handle, regint(0),
                  *call_args)
        break_point('call-%s' % self.name)
        return untuplify(tuple(out_result))

class ExportFunction(FunctionCallTape):
    def __init__(self, function):
        super(ExportFunction, self).__init__(function)
        self.done = set()
    def __call__(self, *args, **kwargs):
        if kwargs:
            raise CompilerError('keyword arguments not supported')
        def arg_signature(arg):
            if isinstance(arg, types._structure):
                return '%s:%d' % (arg.arg_type(), arg.size)
            elif isinstance(arg, types._vectorizable):
                from .GC.types import sbitvec
                if issubclass(arg.value_type, sbitvec):
                    return 'sbv:[%dx%d]' % (arg.total_size(),
                                            arg.value_type.n_bits)
                else:
                    return '%s:[%d]' % (arg.value_type.arg_type(),
                                        arg.total_size())
            else:
                raise CompilerError('argument not supported: %s' % arg)
        signature = []
        for arg in args:
            signature.append(arg_signature(arg))
        signature = tuple(signature)
        key = self.get_key(args, kwargs)
        if key in self.instances and signature not in self.done:
            raise CompilerError('signature conflict')
        super(ExportFunction, self).__call__(*args, **kwargs)
        if signature not in self.done:
            filename = '%s/%s/%s-%s' % (get_program().programs_dir, 'Functions',
                                        self.name, '-'.join(signature))
            print('Writing to', filename)
            out = open(filename, 'w')
            print(get_program().name, file=out)
            print(self.instances[key][0], file=out)
            result = self.instances[key][1]
            try:
                if result is not None:
                    result = untuplify(result)
                    print(arg_signature(result), result.i, file=out)
                else:
                    print('- 0', file=out)
            except CompilerError:
                raise CompilerError('return type not supported: %s' % result)
            for arg in self.instances[key][2]:
                if isinstance(arg, types._structure):
                    print(arg.i, end=' ', file=out)
                elif isinstance(arg, types._vectorizable):
                    assert util.is_constant(arg.alloc_address)
                    print(arg.alloc_address, arg.address.i, end=' ', file=out)
                else:
                    CompilerError('argument not supported: %s', arg)
            print(file=out)
            self.done.add(signature)

def function_tape(function):
    return FunctionTape(function)

def function_tape_with_compile_args(*args):
    def wrapper(function):
        return FunctionTape(function, compile_args=args)
    return wrapper

def single_thread_function_tape(function):
    return FunctionTape(function, single_thread=True)

def function_call_tape(function):
    if get_program().use_tape_calls:
        return FunctionCallTape(function)
    else:
        return function

def method_call_tape(function):
    tapes = {}
    def wrapper(self, *args, **kwargs):
        def use(name):
            x = self.__dict__[name]
            return not isinstance(x, types.MultiArray) or \
                x.array._address is not None
        key = (type(self),) + tuple(filter(use, sorted(self.__dict__)))
        member_key = key[1:]
        if key not in tapes:
            def f(*args, **kwargs):
                class Dummy(type(self)):
                    __init__ = lambda self: None
                dummy = Dummy()
                members = args[:len(member_key)]
                real_args = args[len(member_key):]
                addresses = {}
                for name, member in zip(member_key, members):
                    dummy.__dict__[name] = member
                    if isinstance(member, types._vectorizable):
                        addresses[name] = member.address
                res = function(dummy, *real_args, **kwargs)
                for name, member in zip(member_key, members):
                    new_member = dummy.__dict__[name]
                    desc = '%s in %s.%s' % (name, type(self).__name__,
                                            function.__name__)
                    if id(new_member) != id(member):
                        raise CompilerError('cannot change members '
                                            'in method tape (%s)' % desc)
                    if isinstance(member, types._vectorizable) and \
                       id(new_member.address) != id(addresses[name]):
                        raise CompilerError('cannot change memory address '
                                            'in method tape (%s)' % desc)
                    if set(member_key) != set(dummy.__dict__):
                        raise CompilerError('cannot add members '
                                            'in method tape (%s)' % desc)
                return res
            f.__name__ = '%s-%s' % (type(self).__name__, function.__name__)
            tapes[key] = function_call_tape(f)
        members = tuple(self.__dict__[x] for x in member_key)
        res = tapes[key](*(members + args), **kwargs)
        return res
    return wrapper

def function(function):
    """ Create a run-time function. The arguments can be memory or basic
    types, and return values can be basic types::

      @function
      def f(x, y, z):
          y.write(1)
          z[0] = 2
	  return x + 3

      a = MemValue(sint(0))
      b = sint.Array(10)
      c = f(sint(4), a, b)

      print_ln('%s %s %s', a.reveal(), b[0].reveal(), c.reveal())

    This should output::

      1 2 7

    You can use run-time functions recursively but without return
    values in this case.

    """
    return FunctionCallTape(function)

def export(function):
    return ExportFunction(function)

def memorize(x, write=True):
    if isinstance(x, (tuple, list)):
        return tuple(memorize(i, write=write) for i in x)
    elif x is None:
        return
    else:
        return MemValue(x, write=write)

def unmemorize(x):
    if isinstance(x, (tuple, list)):
        return tuple(unmemorize(i) for i in x)
    elif x is None:
        return
    else:
        return x.read()

def write_mem(dest, source):
    if isinstance(dest, (tuple, list)):
        assert len(dest) == len(source)
        for x, y in zip(dest, source):
            write_mem(x, y)
    elif dest is None:
        return
    else:
        dest.write(source)

class FunctionBlock(Function):
    def on_first_call(self, wrapped_function):
        p_return_address = get_tape().program.malloc(1, 'ci')
        old_block = get_tape().active_basicblock
        parent_node = old_block.req_node
        get_tape().open_scope(lambda x: x[0], None, 'begin-' + self.name)
        block = get_tape().active_basicblock
        block.alloc_pool = AllocPool(parent=block.alloc_pool)
        del parent_node.children[-1]
        self.node = block.req_node
        if get_program().verbose:
            print('Compiling function', self.name)
        result = wrapped_function(*self.compile_args)
        if result is not None:
            self.result = memorize(result)
        else:
            self.result = None
        if get_program().verbose:
            print('Done compiling function', self.name)
        get_tape().function_basicblocks[block] = p_return_address
        return_address = regint.load_mem(p_return_address)
        get_tape().active_basicblock.set_exit(instructions.jmpi(return_address, add_to_prog=False))
        self.last_sub_block = get_tape().active_basicblock
        get_tape().close_scope(old_block, parent_node, 'end-' + self.name)
        old_block.set_exit(instructions.jmp(0, add_to_prog=False), get_tape().active_basicblock)
        self.basic_block = block

    def on_call(self, base, bases):
        if base is not None:
            instructions.starg(regint(base))
        block = self.basic_block
        if block not in get_tape().function_basicblocks:
            raise CompilerError('unknown function')
        old_block = get_tape().active_basicblock
        old_block.set_exit(instructions.jmp(0, add_to_prog=False), block)
        p_return_address = get_tape().function_basicblocks[block]
        return_address = regint()
        old_block.return_address_store = instructions.ldint(return_address, 0)
        return_address.store_in_mem(p_return_address)
        get_tape().start_new_basicblock(name='call-' + self.name)
        get_tape().active_basicblock.set_return(old_block, self.last_sub_block)
        get_block().req_node.children.append(self.node)
        if self.result is not None:
            return unmemorize(self.result)

    @staticmethod
    def base_key():
        return get_tape()

def function_block(function):
    return FunctionBlock(function)

def function_block_with_compile_args(*args):
    def wrapper(function):
        return FunctionBlock(function, compile_args=args)
    return wrapper

def method_block(function):
    # If you use this, make sure to use MemValue for all member
    # variables.
    compiled_functions = {}
    def wrapper(self, *args):
        if self in compiled_functions:
            return compiled_functions[self](*args)
        else:
            name = '%s-%s' % (type(self).__name__, function.__name__)
            block = FunctionBlock(function, name=name, compile_args=(self,))
            compiled_functions[self] = block
            return block(*args)
    return wrapper

def cond_swap(x, y, key_indices=None):
    from .types import SubMultiArray
    if isinstance(x, (Array, SubMultiArray)):
        assert len(key_indices) == 1
        b = x[key_indices[0]] > y[key_indices[0]]
        return list(zip(*[b.cond_swap(xx, yy) for xx, yy in zip(x, y)]))
    b = x < y
    if isinstance(x, sfloat):
        res = ([], [])
        for i,j in enumerate(('v','p','z','s')):
            xx = x.__getattribute__(j)
            yy = y.__getattribute__(j)
            bx = b * xx
            by = b * yy
            res[0].append(bx + yy - by)
            res[1].append(xx - bx + by)
        return sfloat(*res[0]), sfloat(*res[1])
    return b.cond_swap(y, x)

def sort(a):
    print("WARNING: you're using bubble sort")

    res = a
    
    for i in range(len(a)):
        for j in reversed(list(range(i))):
            res[j], res[j+1] = cond_swap(res[j], res[j+1])

    return res

def odd_even_merge(a):
    if len(a) == 2:
        a[0], a[1] = cond_swap(a[0], a[1])
    else:
        even = a[::2]
        odd = a[1::2]
        odd_even_merge(even)
        odd_even_merge(odd)
        a[0] = even[0]
        for i in range(1, len(a) // 2):
            a[2*i-1], a[2*i] = cond_swap(odd[i-1], even[i])
        a[-1] = odd[-1]

def odd_even_merge_sort(a):
    if len(a) == 1:
        return
    elif len(a) % 2 == 0:
        aa = a
        a = list(a)
        lower = a[:len(a)//2]
        upper = a[len(a)//2:]
        odd_even_merge_sort(lower)
        odd_even_merge_sort(upper)
        a[:] = lower + upper
        odd_even_merge(a)
        aa[:] = a
    else:
        raise CompilerError('Length of list must be power of two')

def chunky_odd_even_merge_sort(a):
    raise CompilerError(
        'This function has been removed, use loopy_odd_even_merge_sort instead')

def chunkier_odd_even_merge_sort(a, n=None, max_chunk_size=512, n_threads=7, use_chunk_wraps=False):
    raise CompilerError(
        'This function has been removed, use loopy_odd_even_merge_sort instead')

def loopy_chunkier_odd_even_merge_sort(a, n=None, max_chunk_size=512, n_threads=7):
    raise CompilerError(
        'This function has been removed, use loopy_odd_even_merge_sort instead')


def loopy_odd_even_merge_sort(a, sorted_length=1, n_parallel=32,
                              n_threads=None, key_indices=None):
    get_program().reading('sorting', 'KSS13')
    a_in = a
    if isinstance(a_in, list):
        a = Array.create_from(a)
    steps = {}
    l = sorted_length
    while l < len(a):
        l *= 2
        k = 1
        while k < l:
            k *= 2
            n_innermost = 1 if k == 2 else k // 2 - 1
            key = k
            if key not in steps:
                @function_block
                def step(l):
                    l = MemValue(l)
                    m = 2 ** int(math.ceil(math.log(len(a), 2)))
                    @for_range_opt_multithread(n_threads, m // k)
                    def _(i):
                        n_inner = l // k
                        j = i % n_inner
                        i //= n_inner
                        base = i*l + j
                        step = l//k
                        def swap(base, step):
                            if m == len(a):
                                a[base], a[base + step] = \
                                    cond_swap(a[base], a[base + step],
                                              key_indices=key_indices)
                            else:
                                # ignore values outside range
                                go = base + step < len(a)
                                x = a.maybe_get(go, base)
                                y = a.maybe_get(go, base + step)
                                tmp = cond_swap(x, y, key_indices=key_indices)
                                for i, idx in enumerate((base, base + step)):
                                    a.maybe_set(go, idx, tmp[i])
                        if k == 2:
                            swap(base, step)
                        else:
                            @for_range_opt(n_innermost)
                            def f(i):
                                m1 = step + i * 2 * step
                                m2 = m1 + base
                                swap(m2, step)
                steps[key] = step
            steps[key](l)
    if isinstance(a_in, list):
        a_in[:] = list(a)

def mergesort(A):
    if not get_program().options.insecure:
        raise CompilerError('mergesort reveals the order of elements, '
                            'use --insecure to activate it')

    B = Array(len(A), sint)

    def merge(i_left, i_right, i_end):
        i0 = MemValue(i_left)
        i1 = MemValue(i_right)
        @for_range(i_left, i_end)
        def loop(j):
            if_then(and_(lambda: i0 < i_right,
                         or_(lambda: i1 >= i_end,
                             lambda: regint(reveal(A[i0] <= A[i1])))))
            B[j] = A[i0]
            i0.iadd(1)
            else_then()
            B[j] = A[i1]
            i1.iadd(1)
            end_if()

    width = MemValue(1)
    @do_while
    def width_loop():
        @for_range(0, len(A), 2 * width)
        def merge_loop(i):
            merge(i, i + width, i + 2 * width)
        A.assign(B)
        width.imul(2)
        return width < len(A)

def _range_prep(start, stop, step):
    if stop is None:
        stop = start
        start = 0
    if step is None:
        step = 1
    if util.is_zero(step):
        raise CompilerError('step must not be zero')
    # copy to avoid update
    stop = type(stop)(stop)
    return start, stop, step

def range_loop(loop_body, start, stop=None, step=None):
    start, stop, step = _range_prep(start, stop, step)
    def loop_fn(i):
        res = loop_body(i)
        return util.if_else(res == 0, stop, i + step)
    if isinstance(step, int):
        if step > 0:
            condition = lambda x: x < stop
        elif step < 0:
            condition = lambda x: x > stop
    else:
        b = step > 0
        condition = lambda x: b * (x < stop) + (1 - b) * (x > stop)
    while_loop(loop_fn, condition, start, g=loop_body.__globals__)
    if isinstance(start, int) and isinstance(stop, int) \
            and isinstance(step, int):
        # known loop count
        if condition(start):
            get_block().req_node.children[-1].aggregator = \
                lambda x: int(ceil(((stop - start) / step))) * x[0]

def for_range(start, stop=None, step=None):
    """
    Decorator to execute loop bodies consecutively.  Arguments work as
    in Python :py:func:`range`, but they can be any public
    integer. Information has to be passed out via container types such
    as :py:class:`~Compiler.types.Array` or using :py:func:`update`.
    Note that changing Python data structures such
    as lists within the loop is not possible, but the compiler cannot
    warn about this.

    :param start/stop/step: regint/cint/int

    The following should output 10::

        n = 10
        a = sint.Array(n)
        x = sint(0)
        @for_range(n)
        def _(i):
            a[i] = i
            x.update(x + 1)
        print_ln('%s', x.reveal())

    """
    def decorator(loop_body):
        get_tape().unused_decorators.pop(decorator)
        range_loop(loop_body, start, stop, step)
        return loop_body
    get_tape().unused_decorators[decorator] = 'for_range'
    return decorator

def for_range_parallel(n_parallel, n_loops):
    """
    Decorator to execute a loop :py:obj:`n_loops` up to
    :py:obj:`n_parallel` loop bodies with optimized communication in a
    single thread.
    In most cases, it is easier to use :py:func:`for_range_opt`.
    Using any other control flow instruction inside the loop breaks
    the optimization.

    :param n_parallel: optimization parameter (int)
    :param n_loops: regint/cint/int or list of int

    Example:

    .. code::

        @for_range_parallel(n_parallel, n_loops)
        def _(i):
            a[i] = a[i] * a[i]

    Multidimensional ranges are supported as well. The following
    executes ``f(0, 0)`` to ``f(4, 2)``, two calls in parallel.

    .. code::

        @for_range_parallel(2, [5, 3])
        def f(i, j):
            ...
    """
    if isinstance(n_loops, (list, tuple)):
        return for_range_multithread(None, n_parallel, n_loops)
    return map_reduce_single(n_parallel, n_loops)

def for_range_opt(start, stop=None, step=None, budget=None):
    """ Execute loop bodies in parallel up to an optimization budget.
    This prevents excessive loop unrolling. The budget is respected
    even with nested loops. Note that the optimization is rather
    rudimentary for runtime :py:obj:`n_loops` (regint/cint). Consider
    using :py:func:`for_range_parallel` in this case.
    Using further control flow constructions inside other than
    :py:func:`for_range_opt` (e.g, :py:func:`for_range`) breaks the
    optimization.

    :param start/stop/step: int/regint/cint (used as in :py:func:`range`)
      or :py:obj:`start` only as list/tuple of int (see below).
      The optimization works best if all arguments are int or :py:obj:None.
      Otherwise, the budget has to be smaller than the number of loops for
      any optimization to take place.

    :param budget: number of instructions after which to start optimization
      (default is 1000 or as given with ``--budget``)

    Example:

    .. code::

        @for_range_opt(n)
        def _(i):
            ...

    Multidimensional ranges are supported as well. The following
    executes ``f(0, 0)`` to ``f(4, 2)`` in parallel according to
    the budget.

    .. code::

        @for_range_opt([5, 3])
        def f(i, j):
            ...
    """
    if stop is not None:
        start, stop, step = _range_prep(start, stop, step)
        def wrapper(loop_body):
            range_ = stop-start
            n_loops = ((range_% step) != 0) + range_ // step
            @for_range_opt(n_loops, budget=budget)
            def _(i):
                return loop_body(start + i * step)
        return wrapper
    n_loops = start
    if isinstance(n_loops, (list, tuple)):
        return for_range_opt_multithread(None, n_loops)
    return map_reduce_single(None, n_loops, budget=budget)

def map_reduce_single(n_parallel, n_loops, initializer=lambda *x: [],
                      reducer=lambda *x: [], mem_state=None, budget=None):
    budget = budget or get_program().budget
    if not (isinstance(n_parallel, int) or n_parallel is None):
        raise CompilerError('Number of parallel executions must be constant')
    n_parallel = 1 if is_zero(n_parallel) else n_parallel
    if mem_state is None:
        # default to list of MemValues to allow varying types
        mem_state = [MemValue(x) for x in initializer()]
        use_array = False
    else:
        # use Arrays for multithread version
        use_array = True
    if not util.is_constant(n_loops):
        budget //= 10
        n_loops = regint(n_loops)
    def decorator(loop_body):
        my_n_parallel = n_parallel
        if isinstance(n_parallel, int):
            if isinstance(n_loops, int):
                loop_rounds = n_loops // n_parallel \
                              if n_parallel < n_loops else 0
            else:
                loop_rounds = n_loops // n_parallel
        def write_state_to_memory(r):
            if use_array:
                mem_state.assign(r)
            else:
                # cannot do mem_state = [...] due to scope issue
                for j,x in enumerate(r):
                    mem_state[j].write(x)
        if n_parallel is not None:
            # will be optimized out if n_loops <= n_parallel
            @for_range(loop_rounds)
            def f(i):
                state = tuplify(initializer())
                start_block = get_block()
                j = i * n_parallel
                one = regint(1)
                for k in range(n_parallel):
                    state = reducer(tuplify(loop_body(j)), state)
                    j += one
                if n_parallel > 1 and start_block != get_block():
                    print('WARNING: parallelization broken '
                          'by control flow instruction')
                r = reducer(mem_state, state)
                write_state_to_memory(r)
        else:
            if is_zero(n_loops):
                return
            n_opt_loops_reg = regint(0)
            n_opt_loops_inst = get_block().instructions[-1]
            parent_block = get_block()
            prevent_breaks = get_program().prevent_breaks
            get_program().prevent_breaks = False
            get_program().reading('loop optimization', 'Keller24')
            @while_do(lambda x: x + n_opt_loops_reg <= n_loops, regint(0))
            def _(i):
                state = tuplify(initializer())
                k = 0
                block = get_block()
                assert not isinstance(n_loops, int) or n_loops > 0
                pre = copy.copy(loop_body.__globals__)
                while (not util.is_constant(n_loops) or k < n_loops) \
                      and (len(get_block()) < budget or k == 0) \
                      and block is get_block():
                    j = i + k
                    state = reducer(tuplify(loop_body(j)), state)
                    k += 1
                RegintOptimizer().run(block.instructions, get_program())
                _link(pre, loop_body.__globals__)
                r = reducer(mem_state, state)
                write_state_to_memory(r)
                global n_opt_loops
                n_opt_loops = k
                n_opt_loops_inst.args[1] = k
                return i + k
            my_n_parallel = n_opt_loops
            loop_rounds = n_loops // my_n_parallel
            blocks = get_tape().basicblocks
            n_to_merge = 5
            get_program().prevent_breaks = prevent_breaks
            if util.is_one(loop_rounds) and parent_block is blocks[-n_to_merge]:
                # merge blocks started by if and do_while
                def exit_elimination(block):
                    if block.exit_condition is not None:
                        for reg in block.exit_condition.get_used():
                            reg.can_eliminate = True
                exit_elimination(parent_block)
                merged = parent_block
                merged.exit_condition = blocks[-1].exit_condition
                merged.exit_block = blocks[-1].exit_block
                assert parent_block is blocks[-n_to_merge]
                assert blocks[-n_to_merge + 1].req_node is \
                    get_block().req_node.children[-1].nodes[0]
                for block in blocks[-n_to_merge + 1:]:
                    merged.instructions += block.instructions
                    exit_elimination(block)
                    block.purge(retain_usage=False)
                del blocks[-n_to_merge + 1:]
                del get_block().req_node.children[-1]
                merged.children = []
                RegintOptimizer().run(merged.instructions, get_program())
                get_tape().active_basicblock = merged
            else:
                if get_program().verbose:
                    print(n_opt_loops, 'repetitions')
                assert not get_program().prevent_breaks
                req_node = get_block().req_node.children[-1].nodes[0]
                if util.is_constant(loop_rounds):
                    req_node.children[0].aggregator = lambda x: loop_rounds * x[0]
        if isinstance(n_loops, int):
            state = mem_state
            for j in range(loop_rounds * my_n_parallel, n_loops):
                state = reducer(tuplify(loop_body(j)), state)
        else:
            done = regint(loop_rounds * my_n_parallel)
            for i in range(int(math.log(my_n_parallel, 2)), -1, -1):
                N = 2 ** i
                @if_(n_loops - done >= N)
                def _():
                    state = tuplify(initializer())
                    for j in range(N):
                        state = reducer(tuplify(loop_body(done + j)), state)
                    write_state_to_memory(reducer(mem_state, state))
                    done.iadd(N)
            state = mem_state
        if use_array and len(state) and \
           isinstance(types._register, types._vectorizable):
            mem_state[:] = state.get_vector()
        else:
            for i,x in enumerate(state):
                if use_array:
                    mem_state[i] = x
                else:
                    mem_state[i].write(x)
        def returner():
            return untuplify(tuple(state))
        return returner
    return decorator

def for_range_multithread(n_threads, n_parallel, n_loops, thread_mem_req={},
                          budget=None):
    """
    Execute :py:obj:`n_loops` loop bodies in up to :py:obj:`n_threads`
    threads, up to :py:obj:`n_parallel` in parallel per thread.

    :param n_threads/n_parallel: compile-time (int)
    :param n_loops: regint/cint/int

    """
    return map_reduce(n_threads, n_parallel, n_loops, \
                          lambda *x: [], lambda *x: [], thread_mem_req,
                      budget=budget)

def for_range_opt_multithread(n_threads, n_loops, budget=None):
    """
    Execute :py:obj:`n_loops` loop bodies in up to :py:obj:`n_threads`
    threads, in parallel up to an optimization budget per thread
    similar to :py:func:`for_range_opt`. Note that optimization is rather
    rudimentary for runtime :py:obj:`n_loops` (regint/cint). Consider
    using :py:func:`for_range_multithread` in this case.

    :param n_threads: compile-time (int)
    :param n_loops: regint/cint/int

    The following will execute loop bodies 0-9 in one thread, 10-19 in
    another etc:

    .. code::

        @for_range_opt_multithread(8, 80)
        def _(i):
            ...

    Multidimensional ranges are supported as well. The following
    executes ``f(0, 0)`` to ``f(2, 0)`` in one thread and ``f(2, 1)``
    to ``f(4, 2)`` in another.

    .. code::

        @for_range_opt_multithread(2, [5, 3])
        def f(i, j):
            ...

    Note that you cannot use registers across threads. Use
    :py:class:`~Compiler.types.MemValue` instead::

        a = MemValue(sint(0))
        @for_range_opt_multithread(8, 80)
        def _(i):
            b = a + 1

    """
    return for_range_multithread(n_threads, None, n_loops, budget=budget)

def multithread(n_threads, n_items=None, max_size=None):
    """
    Distribute the computation of :py:obj:`n_items` to
    :py:obj:`n_threads` threads, but leave the in-thread repetition up
    to the user.

    :param n_threads: compile-time (int)
    :param n_items: regint/cint/int (default: :py:obj:`n_threads`)
    :param max_size: maximum size to be processed at once (default: no limit)

    The following executes ``f(0, 8)``, ``f(8, 8)``, and
    ``f(16, 9)`` in three different threads:

    .. code::

        @multithread(3, 25)
        def f(base, size):
            ...
    """
    if n_items is None:
        n_items = n_threads
    if max_size is None or n_items <= max_size:
        return map_reduce(n_threads, None, n_items, initializer=lambda: [],
                          reducer=None, looping=False)
    else:
        max_size = max(1, max_size)
        def wrapper(function):
            @multithread(n_threads, n_items)
            def new_function(base, size):
                @for_range(size // max_size)
                def _(i):
                    function(base + i * max_size, max_size)
                rem = size % max_size
                if rem:
                    function(base + size - rem, rem)
        return wrapper

def map_reduce(n_threads, n_parallel, n_loops, initializer, reducer, \
                   thread_mem_req={}, looping=True, budget=None):
    assert(n_threads != 0)
    if isinstance(n_loops, (list, tuple)):
        split = n_loops
        n_loops = reduce(operator.mul, n_loops)
        def decorator(loop_body):
            def new_body(i):
                indices = []
                for n in reversed(split):
                    indices.insert(0, i % n)
                    i //= n
                return loop_body(*indices)
            return new_body
        new_dec = map_reduce(n_threads, n_parallel, n_loops, initializer, reducer, thread_mem_req)
        return lambda loop_body: new_dec(decorator(loop_body))
    n_loops = MemValue.if_necessary(n_loops)
    if n_threads == None or util.is_one(n_loops):
        if not looping:
            return lambda loop_body: loop_body(0, n_loops)
        dec = map_reduce_single(n_parallel, n_loops, initializer, reducer)
        if thread_mem_req:
            thread_mem = Array(thread_mem_req[regint], regint)
            return lambda loop_body: dec(lambda i: loop_body(i, thread_mem))
        else:
            return dec
    def decorator(loop_body):
        thread_rounds = MemValue.if_necessary(n_loops // n_threads)
        if util.is_constant(thread_rounds):
            remainder = n_loops % n_threads
        else:
            remainder = 0
        for t in thread_mem_req:
            if t != regint:
                raise CompilerError('Not implemented for other than regint')
        args = Matrix(n_threads, 2 + thread_mem_req.get(regint, 0), 'ci')
        state = initializer()
        if len(state) == 0:
            state_type = cint
        elif isinstance(state, (tuple, list)):
            state_type = type(state[0])
        else:
            state_type = type(state)
        prevent_breaks = get_program().prevent_breaks
        def f(inc):
            get_program().prevent_breaks = prevent_breaks
            base = args[get_arg()][0]
            get_program().base_addresses[base] = None
            if not util.is_constant(thread_rounds):
                i = base // thread_rounds
                overhang = n_loops % n_threads
                inc = i < overhang
                base += inc.if_else(i, overhang)
            if not looping:
                return loop_body(base, thread_rounds + inc)
            if thread_mem_req:
                thread_mem = Array(thread_mem_req[regint], regint, \
                                       args[get_arg()].address + 2)
            mem_state = Array(len(state), state_type, args[get_arg()][1])
            @map_reduce_single(n_parallel, thread_rounds + inc, \
                                   initializer, reducer, mem_state)
            def f(i):
                if thread_mem_req:
                    return loop_body(base + i, thread_mem)
                else:
                    return loop_body(base + i)
        prog = get_program()
        thread_args = []
        if prog.curr_tape.singular:
            prog.n_running_threads = n_threads
        if not util.is_zero(thread_rounds):
            prog.prevent_breaks = False
            tape = prog.new_tape(f, (0,), 'multithread')
            for i in range(n_threads - remainder):
                mem_state = make_array(initializer())
                args[remainder + i][0] = i * thread_rounds
                if len(mem_state):
                    args[remainder + i][1] = mem_state.address
                thread_args.append((tape, remainder + i))
        if remainder:
            prog.prevent_breaks = False
            tape1 = prog.new_tape(f, (1,), 'multithread1')
            for i in range(remainder):
                mem_state = make_array(initializer())
                args[i][0] = (n_threads - remainder + i) * thread_rounds + i
                if len(mem_state):
                    args[i][1] = mem_state.address
                thread_args.append((tape1, i))
        prog.n_running_threads = None
        prog.prevent_breaks = False
        threads = prog.run_tapes(thread_args)
        for thread in threads:
            prog.join_tape(thread)
        prog.free_later()
        prog.prevent_breaks = prevent_breaks
        if len(state):
            if not util.is_zero(thread_rounds):
                for i in range(n_threads - remainder):
                    state = reducer(Array(len(state), state_type, \
                                              args[remainder + i][1]), state)
            if remainder:
                for i in range(remainder):
                    state = reducer(Array(len(state), state_type, \
                                              args[i][1]), state)
        def returner():
            return untuplify(state)
        return returner
    return decorator

def map_sum(n_threads, n_parallel, n_loops, n_items, value_types):
    value_types = tuplify(value_types)
    if len(value_types) == 1:
        value_types *= n_items
    elif len(value_types) != n_items:
        raise CompilerError('Incorrect number of value_types.')
    initializer = lambda: [t(0) for t in value_types]
    def summer(x,y):
        return tuple(a + b for a,b in zip(x,y))
    return map_reduce(n_threads, n_parallel, n_loops, initializer, summer)

def map_sum_opt(n_threads, n_loops, types):
    """ Multi-threaded sum reduction. The following computes a sum of
    ten squares in three threads::

        @map_sum_opt(3, 10, [sint])
        def summer(i):
            return sint(i) ** 2

        result = summer()

    :param n_threads: number of threads (int)
    :param n_loops: number of loop runs (regint/cint/int)
    :param types: return type, must match the return statement
        in the loop

    """
    return map_sum(n_threads, None, n_loops, len(types), types)

def map_sum_simple(n_threads, n_loops, type, size):
    """ Vectorized multi-threaded sum reduction. The following computes a
    100 sums of ten squares in three threads::

        @map_sum_simple(3, 10, sint, 100)
        def summer(i):
            return sint(regint.inc(100, i, 0)) ** 2

        result = summer()

    :param n_threads: number of threads (int)
    :param n_loops: number of loop runs (regint/cint/int)
    :param type: return type, must match the return statement
        in the loop
    :param size: vector size, must match the return statement
        in the loop

    """
    initializer = lambda: type(0, size=size)
    def summer(*args):
        assert len(args) == 2
        args = list(args)
        for i in (0, 1):
            if isinstance(args[i], tuple):
                assert len(args[i]) == 1
                args[i] = args[i][0]
        for i in (0, 1):
            assert len(args[i]) == size
            if isinstance(args[i], Array):
                args[i] = args[i][:]
        return args[0] + args[1]
    return map_reduce(n_threads, 1, n_loops, initializer, summer)

def tree_reduce_multithread(n_threads, function, vector):
    """ Round-efficient reduction in several threads. The following code
    computes the maximum of an array in 10 threads::

      tree_reduce_multithread(10, lambda x, y: x.max(y), a)

    :param n_threads: number of threads (int)
    :param function: reduction function taking exactly two arguments
    :param vector: register vector or array

    """
    inputs = vector.Array(len(vector))
    inputs.assign_vector(vector)
    outputs = vector.Array(len(vector) // 2)
    left = len(vector)
    while left > 1:
        @multithread(n_threads, left // 2)
        def _(base, size):
            outputs.assign_vector(
                function(inputs.get_vector(2 * base, size),
                         inputs.get_vector(2 * base + size, size)), base)
        inputs.assign_vector(outputs.get_vector(0, left // 2))
        if left % 2 == 1:
            inputs[left // 2] = inputs[left - 1]
        left = (left + 1) // 2
    return inputs[0]

def tree_reduce(function, sequence):
    """ Round-efficient reduction. The following computes the maximum
    of the list :py:obj:`l`::

      m = tree_reduce(lambda x, y: x.max(y), l)

    :param function: reduction function taking two arguments
    :param sequence: list, vector, or array

    """
    return util.tree_reduce(function, sequence)

def foreach_enumerate(a):
    """ Run-time loop over public data. This uses
    ``Player-Data/Public-Input/<progname>``. Example:

    .. code::

        @foreach_enumerate([2, 8, 3])
        def _(i, j):
            print_ln('%s: %s', i, j)

    This will output:

    .. code::

        0: 2
        1: 8
        2: 3
    """
    for x in a:
        get_program().public_input(' '.join(str(y) for y in tuplify(x)))
    def decorator(loop_body):
        @for_range(len(a))
        def f(i):
            loop_body(i, *(public_input() for j in range(len(tuplify(a[0])))))
        return f
    return decorator

def while_loop(loop_body, condition, arg=None, g=None):
    if not callable(condition):
        raise CompilerError('Condition must be callable')
    if arg is None:
        pre_condition = condition()
        def loop_fn():
            loop_body()
            return condition()
    else:
        pre_condition = condition(arg)
        arg = regint(arg)
        def loop_fn():
            result = loop_body(arg)
            if isinstance(result, MemValue):
                result = result.read()
            arg.link(type(arg)(result))
            return condition(result)
    if not isinstance(pre_condition, (bool,int)) or pre_condition:
        if_statement(pre_condition, lambda: do_while(loop_fn, g=g))

def while_do(condition, *args):
    """ While-do loop.

    :param condition: function returning public integer (regint/cint/int)

    The following executes an ten-fold loop:

    .. code::

        i = regint(0)
        @while_do(lambda: i < 10)
        def f():
            ...
            i.update(i + 1)
            ...

    """
    def decorator(loop_body):
        while_loop(loop_body, condition, *args)
        return loop_body
    return decorator

def _run_and_link(function, g=None, lock_lists=True, allow_return=False):
    if g is None:
        g = function.__globals__
        if lock_lists:
            class A(list):
                def __init_(self, l):
                    self[:] = l
                def __setitem__(*args):
                    raise Exception('you cannot change lists in branches, '
                                    'use Array or MultiArray instead')
                __delitem__ = append = clear = extend = insert = __setitem__
                pop = remove = reverse = sort = __setitem__
            for x in g:
                if isinstance(g[x], list):
                    g[x] = A(g[x])
    pre = copy.copy(g)
    res = function()
    if res is not None and not allow_return:
        raise CompilerError('Conditional blocks cannot return values. '
                            'Use if_else instead: https://mp-spdz.readthedocs.io/en/latest/Compiler.html#Compiler.types.regint.if_else')
    _link(pre, g)
    return res

def _link(pre, g):
    if g:
        from .types import _single
        for name, var in pre.items():
            if isinstance(var, (Tape.Register, _single, _vec)):
                new_var = g[name]
                if util.is_constant_float(new_var):
                    raise CompilerError('cannot reassign constants in blocks')
                if id(new_var) != id(var):
                    new_var.link(new_var.conv(var))

def do_while(loop_fn, g=None):
    """ Do-while loop. The loop is stopped if the return value is zero.
    It must be public. The following executes exactly once:

    .. code::

        @do_while
        def _():
            ...
            return regint(0)
    """
    scope = instructions.program.curr_block
    parent_node = get_block().req_node
    # possibly unknown loop count
    get_tape().open_scope(lambda x: x[0].set_all(float('Inf')), \
                              name='begin-loop')
    get_tape().loop_breaks.append([])
    loop_block = instructions.program.curr_block
    condition = _run_and_link(loop_fn, g, allow_return=True)
    if callable(condition):
        condition = condition()
    branch = instructions.jmpnz(regint.conv(condition), 0, add_to_prog=False)
    instructions.program.curr_block.set_exit(branch, loop_block)
    get_tape().close_scope(scope, parent_node, 'end-loop')
    for loop_break in get_tape().loop_breaks.pop():
        loop_break.set_exit(jmp(0, add_to_prog=False), get_block())
    return loop_fn

def break_loop():
    """ Break out of loop. """
    get_tape().loop_breaks[-1].append(get_block())
    break_point('break')

def if_then(condition):
    class State: pass
    state = State()
    if callable(condition):
        condition = condition()
    try:
        if not condition.is_clear:
            raise CompilerError(
                'cannot branch on secret values, use if_else instead: '
                'https://mp-spdz.readthedocs.io/en/latest/Compiler.html#Compiler.types.sint.if_else')
    except AttributeError:
        pass
    state.condition = regint.conv(condition)
    state.start_block = instructions.program.curr_block
    state.req_child = get_tape().open_scope(lambda x: x[0].max(x[1]), \
                                                   name='if-block')
    state.has_else = False
    state.closed_if = False
    state.caller = [frame[1:] for frame in inspect.stack()[1:]]
    instructions.program.curr_tape.if_states.append(state)

def else_then():
    try:
        state = instructions.program.curr_tape.if_states[-1]
    except IndexError:
        raise CompilerError('No open if block')
    if state.has_else:
        raise CompilerError('else block already defined')
    # run the else block
    state.if_exit_block = instructions.program.curr_block
    req_node = state.req_child.add_node(get_tape(), 'else-block')
    instructions.program.curr_tape.start_new_basicblock(state.start_block, \
                                                        name='else-block',
                                                        req_node=req_node)
    state.else_block = instructions.program.curr_block
    state.has_else = True

def end_if():
    try:
        state = instructions.program.curr_tape.if_states.pop()
    except IndexError:
        raise CompilerError('No open if/else block')
    branch = instructions.jmpeqz(regint.conv(state.condition), 0, \
                                     add_to_prog=False)
    # start next block
    get_tape().close_scope(state.start_block, state.req_child.parent, 'end-if')
    if state.has_else:
        # jump to else block if condition == 0
        state.start_block.set_exit(branch, state.else_block)
        # set if block to skip else
        jump = instructions.jmp(0, add_to_prog=False)
        state.if_exit_block.set_exit(jump, instructions.program.curr_block)
    else:
        # set start block's conditional jump to next block
        state.start_block.set_exit(branch, instructions.program.curr_block)
        # nothing to compute without else
        state.req_child.aggregator = lambda x: x[0]

def if_statement(condition, if_fn, else_fn=None):
    if condition is True or condition is False:
        # condition known at compile time
        if condition:
            if_fn()
        elif else_fn is not None:
            else_fn()
    else:
        state = if_then(condition)
        if_fn()
        if else_fn is not None:
            else_then()
            else_fn()
        end_if()

def if_(condition):
    """
    Conditional execution without else block. Note that this does not
    work compile-time (Python) data structures, so if you change
    lists, dictionaries, or objects, you might not get the desired
    result. You can avoid problems by creating container types like
    :py:class:`~Compiler.types.Array` and
    :py:class:`~Compiler.types.MemValue` *before* the condition and
    only using assignment operations inside.

    :param condition: regint/cint/int

    Usage:

    .. code::

        @if_(x > 0)
        def _():
            ...

    """
    try:
        condition = bool(condition)
    except:
        pass
    def decorator(body):
        if isinstance(condition, bool):
            if condition:
                _run_and_link(body)
        else:
            if_then(condition)
            _run_and_link(body)
            end_if()
    return decorator

def if_e(condition):
    """
    Conditional execution with else block.
    Use :py:class:`~Compiler.types.MemValue` to assign values that
    live beyond.

    :param condition: regint/cint/int

    Usage:

    .. code::

        y = MemValue(0)
        @if_e(x > 0)
        def _():
            y.write(1)
        @else_
        def _():
            y.write(0)
    """
    try:
        condition = bool(condition)
    except:
        pass
    def decorator(body):
        if isinstance(condition, bool):
            get_tape().if_states.append(condition)
            if condition:
                _run_and_link(body)
        else:
            if_then(condition)
            _run_and_link(body)
            get_tape().if_states[-1].closed_if = True
    return decorator

def else_(body):
    if_states = get_tape().if_states
    if isinstance(if_states[-1], bool):
        if not if_states[-1]:
            _run_and_link(body)
        if_states.pop()
    else:
        if not if_states[-1].closed_if:
            raise CompilerError('@if_e not closed before else block')
        else_then()
        _run_and_link(body)
        end_if()

def and_(*terms):
    def load_result():
        res = regint(0)
        for term in terms:
            if_then(term())
        old_res = res
        res = regint(1)
        res.link(old_res)
        for term in terms:
            else_then()
            end_if()
        return res
    return load_result

def or_(*terms):
    def load_result():
        res = regint(1)
        for term in terms:
            if_then(term())
            else_then()
        old_res = res
        res = regint(0)
        res.link(old_res)
        for term in terms:
            end_if()
        return res
    return load_result

def not_(term):
    return lambda: 1 - term()

def start_timer(timer_id=0):
    """ Start timer. Timer 0 runs from the start of the program. The
    total time of all used timers is output at the end. Fails if
    already running.

    :param timer_id: compile-time (int) """
    get_tape().start_new_basicblock(name='pre-start-timer')
    start(timer_id)
    get_tape().start_new_basicblock(name='post-start-timer')

def stop_timer(timer_id=0):
    """ Stop timer. Fails if not running.

    :param timer_id: compile-time (int) """
    get_tape().start_new_basicblock(name='pre-stop-timer')
    stop(timer_id)
    get_tape().start_new_basicblock(name='post-stop-timer')

def get_number_of_players():
    """
    :return: the number of players
    :rtype: regint
    """
    res = regint()
    nplayers(res)
    return res

def get_threshold():
    """ The threshold is the maximal number of corrupted
    players.

    :rtype: regint
    """
    res = regint()
    threshold(res)
    return res

def get_player_id():
    """
    :return: player number
    :rtype: localint (cannot be used for computation) """
    res = localint()
    playerid(res._v)
    return res

def listen_for_clients(port):
    """ Listen for clients on specific port base.

    :param port: port base (int/regint/cint)
    """
    instructions.listen(regint.conv(port))

def accept_client_connection(port, players=None):
    """ Accept client connection on specific port base.

    :param port: port base (int/regint/cint)
    :param players: subset of players (default: all)
    :returns: client id

    """
    res = regint()
    if players is None:
        instructions.acceptclientconnection(res, regint.conv(port))
    else:
        @if_e(sum(regint(players) ==
                 get_player_id()._v.expand_to_vector(len(players))))
        def _():
            res.update(accept_client_connection(port))
        @else_
        def _():
            res.update(-1)
    return res

def init_client_connection(host, port, my_id, relative_port=True):
    """ Initiate connection to another party as client.

    :param host: hostname
    :param port: port base (int/regint/cint)
    :param my_id: client id to use
    :param relative_port: whether to add party number to port number
    :returns: connection id

    """
    if relative_port:
        port = (port + get_player_id())._v
    res = regint()
    instructions.initclientconnection(
        res, regint.conv(port), regint.conv(my_id), host)
    return res

def break_point(name=''):
    """
    Insert break point. This makes sure that all following code
    will be executed after preceding code.

    :param name: Name for identification (optional)
    """
    get_tape().start_new_basicblock(name=name)

def check_point():
    """
    Force MAC checks in current thread and all idle threads if the
    current thread is the main thread. This implies a break point.
    """
    break_point('pre-check')
    check()
    break_point('post-check')

# Fixed point ops

from math import ceil, log
from .floatingpoint import PreOR, TruncPr, two_power

def approximate_reciprocal(divisor, k, f, theta):
    """
        returns aproximation of 1/divisor
        where type(divisor) = cint
    """
    def twos_complement(x):
        bits = x.bit_decompose(k)[::-1]

        twos_result = cint(0)
        for i in range(k):
            val = twos_result
            val <<= 1
            val += 1 - bits[i]
            twos_result = val

        return twos_result + 1

    bits = divisor.bit_decompose(k)[::-1]

    flag = regint(0)
    cnt_leading_zeros = regint(0)
    normalized_divisor = divisor

    for i in range(k):
        flag = flag | bits[i]
        flag_zero = flag.bit_not()
        cnt_leading_zeros += flag_zero
        normalized_divisor <<= flag_zero

    q = two_power(k)
    e = twos_complement(normalized_divisor)

    for i in range(theta):
        q += (q * e) >> k
        e = (e * e) >> k

    res = q >> cint(2*k - 2*f - cnt_leading_zeros)

    return res


def cint_cint_division(a, b, k, f):
    """
        Goldschmidt method implemented with
        SE aproximation:
        http://stackoverflow.com/questions/2661541/picking-good-first-estimates-for-goldschmidt-division
    """
    # theta can be replaced with something smaller
    # for safety we assume that is the same theta from previous GS method

    if get_program().options.ring:
        assert 2 * f < int(get_program().options.ring)

    theta = int(ceil(log(k/3.5) / log(2)))
    two = cint(2) * two_power(f)

    sign_b = cint(1) - 2 * cint(b.less_than(0, k, sync=False))
    sign_a = cint(1) - 2 * cint(a.less_than(0, k, sync=False))
    absolute_b = b * sign_b
    absolute_a = a * sign_a
    w0 = approximate_reciprocal(absolute_b, k, f, theta)

    A = absolute_a
    B = absolute_b
    W = w0

    corr = cint(1) << (f - 1)

    for i in range(theta):
        A = (A * W + corr) >> f
        B = (B * W + corr) >> f
        W = two - B
    return (sign_a * sign_b) * A

from Compiler.program import Program

@instructions_base.ret_cisc
def sint_cint_division(a, b, k, f, nearest=False):
    """
        type(a) = sint, type(b) = cint
    """
    theta = int(ceil(log(k/3.5) / log(2)))
    two = cint(2) * two_power(f)
    sign_b = cint(1) - 2 * cint(b.less_than(0, k))
    sign_a = sint(1) - 2 * comparison.LessThanZero(a, k)
    absolute_b = b * sign_b
    absolute_a = a * sign_a
    w0 = approximate_reciprocal(absolute_b, k, f, theta)

    A = absolute_a
    B = absolute_b
    W = w0

    for i in range(1, theta):
        A = (A * W).round(2 * k, f, nearest=nearest, signed=True)
        temp = (B * W + 2 * (f - 1)) >> f
        W = two - temp
        B = temp
    return (sign_a * sign_b) * A

def IntDiv(a, b, k):
    l = 2 * k + 1
    b = a.conv(b)
    return FPDiv(a.extend(l) << k, b.extend(l) << k, l, k,
                 nearest=True)

@instructions_base.ret_cisc
def FPDiv(a, b, k, f, simplex_flag=False, nearest=False):
    """
        Goldschmidt method as presented in Catrina10,
    """
    get_program().reading('fixed-point division', 'CdH10-fixed')
    prime = get_program().prime
    if 2 * k == int(get_program().options.ring) or \
       (prime and 2 * k <= (prime.bit_length() - 1)):
        # not fitting otherwise
        nearest = True
    if get_program().options.binary:
        # no probabilistic truncation in binary circuits
        nearest = True
    res_f = f
    min_f = (k - nearest) // 2 + 1
    max_length = lambda f: k + 3 * f - res_f

    if get_program().options.ring:
        max_f = (int(get_program().options.ring) - k + res_f) // 3
        if max_f < res_f:
            min_ring = int(math.ceil(max_length(res_f) / 64) * 64)
            print('WARNING: Reducing precision of fixed-point division. '
                  'Increase ring size for full precision, '
                  "maybe using '-R %d'." % min_ring)
        else:
            max_f = res_f
    else:
        max_f = res_f

    f = max(min_f, max_f)
    assert 2 * f > k - nearest
    theta = int(ceil(log(k/3.5) / log(2)))
    l_y = max_length(f)

    comparison.require_ring_size(
        l_y, 'division',
        suffix=" or consider reducing k in 'sfix.precision(f, k)'")

    base.set_global_vector_size(b.size)
    alpha = b.get_type(2 * k).two_power(2*f, size=b.size)
    w = AppRcr(b, k, f, simplex_flag, nearest).extend(2 * k)
    x = alpha - b.extend(2 * k) * w
    base.reset_global_vector_size()

    y = a.extend(l_y) * w
    y = y.round(l_y, f, nearest, signed=True)

    for i in range(theta - 1):
        x = x.extend(2 * k)
        y = y.extend(l_y) * (alpha + x).extend(l_y)
        x = x * x
        y = y.round(l_y, 2*f, nearest, signed=True)
        x = x.round(2*k, 2*f, nearest, signed=True)

    x = x.extend(2 * k)
    y = y.extend(l_y) * (alpha + x).extend(l_y)
    y = y.round(l_y, 3 * f - res_f, nearest, signed=True)
    return y

@instructions_base.ret_cisc
def AppRcr(b, k, f, simplex_flag=False, nearest=False):
    """
        Approximate reciprocal of [b]:
        Given [b], compute [1/b]
    """
    alpha = b.get_type(2 * k)(int(2.9142 * 2**k))
    c, v = b.Norm(k, f, simplex_flag)
    #v should be 2**{k - m} where m is the length of the bitwise repr of [b]
    d = alpha - 2 * c
    w = d * v
    w = w.round(2 * k + 1, 2 * (k - f), nearest, signed=True)
    # now w * 2 ^ {-f} should be an initial approximation of 1/b
    return w

def Norm(b, k, f, simplex_flag=False):
    """
        Computes secret integer values [c] and [v_prime] st.
        2^{k-1} <= c < 2^k and c = b*v_prime
    """
    # For simplex, we can get rid of computing abs(b)
    temp = None
    if simplex_flag == False:
        temp = b.less_than(0, k, sync=False)
    elif simplex_flag == True:
        temp = cint(0)

    sign = 1 - 2 * temp # 1 - 2 * [b < 0]
    absolute_val = sign * b

    #next 2 lines actually compute the SufOR for little indian encoding
    bits = absolute_val.bit_decompose(k, maybe_mixed=True)[::-1]
    suffixes = PreOR(bits)[::-1]

    z = [0] * k
    for i in range(k - 1):
        z[i] = suffixes[i] - suffixes[i+1]
    z[k - 1] = suffixes[k-1]

    acc = b.bit_compose(reversed(z))

    part_reciprocal = absolute_val * acc
    signed_acc = sign * acc

    return part_reciprocal, signed_acc
