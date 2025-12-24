"""
This module contains machine learning functionality. It is work in
progress, so you must expect things to change. The only tested
functionality for training is using consecutive layers.
This includes logistic regression. It can be run as
follows::

    sgd = ml.SGD([ml.Dense(n_examples, n_features, 1),
                  ml.Output(n_examples, approx=True)], n_epochs,
                 report_loss=True)
    sgd.layers[0].X.input_from(0)
    sgd.layers[1].Y.input_from(1)
    sgd.reset()
    sgd.run()

This loads measurements from party 0 and labels (0/1) from party
1. After running, the model is stored in :py:obj:`sgd.layers[0].W` and
:py:obj:`sgd.layers[0].b`. The :py:obj:`approx` parameter determines
whether to use an approximate sigmoid function. Setting it to 5 uses
a five-piece approximation instead of a three-piece one.

A simple network for MNIST using two dense layers can be trained as
follows::

    sgd = ml.SGD([ml.Dense(60000, 784, 128, activation='relu'),
                  ml.Dense(60000, 128, 10),
                  ml.MultiOutput(60000, 10)], n_epochs,
                 report_loss=True)
    sgd.layers[0].X.input_from(0)
    sgd.layers[1].Y.input_from(1)
    sgd.reset()
    sgd.run()

See `this repository <https://github.com/csiro-mlai/mnist-mpc>`_
for scripts importing MNIST training data and further examples.

Inference can be run as follows::

    data = sfix.Matrix(n_test, n_features)
    data.input_from(0)
    res = sgd.eval(data)
    print_ln('Results: %s', [x.reveal() for x in res])

For inference/classification, this module offers the layers necessary
for neural networks such as DenseNet, ResNet, and SqueezeNet. A
minimal example using input from player 0 and model from player 1
looks as follows::

    graph = Optimizer()
    graph.layers = layers
    layers[0].X.input_from(0)
    for layer in layers:
        layer.input_from(1)
    graph.forward(1)
    res = layers[-1].Y

See the `readme <https://github.com/data61/MP-SPDZ/#tensorflow-inference>`_ for
an example of how to run MP-SPDZ on TensorFlow graphs.
"""

import math
import re

from Compiler import mpc_math, util
from Compiler.types import *
from Compiler.types import _unreduced_squant, _single
from Compiler.library import *
from Compiler.util import is_zero, tree_reduce
from Compiler.comparison import CarryOutRawLE
from Compiler.GC.types import sbitint
from functools import reduce

def log_e(x):
    return mpc_math.log_fx(x, math.e)

use_mux = False

def exp(x):
    if use_mux:
        return mpc_math.mux_exp(math.e, x)
    else:
        return mpc_math.pow_fx(math.e, x)

def get_limit(x):
    exp_limit = 2 ** (x.k - x.f - 1)
    return math.log(exp_limit)

def sanitize(x, raw, lower, upper):
    limit = get_limit(x)
    res = (x > limit).if_else(upper, raw)
    return (x < -limit).if_else(lower, res)

def sigmoid(x):
    """ Sigmoid function.

    :param x: sfix """
    return sigmoid_from_e_x(x, exp(-x))

def sigmoid_from_e_x(x, e_x):
    return sanitize(x, 1 / (1 + e_x), 0, 1)

def sigmoid_prime(x):
    """ Sigmoid derivative.

    :param x: sfix """
    sx = sigmoid(x)
    return sx * (1 - sx)

@vectorize
def approx_sigmoid(x, n=3):
    """ Piece-wise approximate sigmoid as in
    `Hong et al. <https://arxiv.org/abs/2002.04344>`_

    :param x: input
    :param n: number of pieces, 3 (default) or 5
    """
    if n == 5:
        cuts = [-5, -2.5, 2.5, 5]
        le = [0] + [x <= cut for cut in cuts] + [1]
        select = [le[i + 1] - le[i] for i in range(5)]
        outputs = [cfix(10 ** -4),
                   0.02776 * x + 0.145,
                   0.17 * x + 0.5,
                   0.02776 * x + 0.85498,
                   cfix(1 - 10 ** -4)]
        return sum(a * b for a, b in zip(select, outputs))
    else:
        a = x < -0.5
        b = x > 0.5
        return a.if_else(0, b.if_else(1, 0.5 + x))

def lse_0_from_e_x(x, e_x):
    return sanitize(-x, log_e(1 + e_x), x + 2 ** -x.f, 0)

def lse_0(x):
    return lse_0_from_e_x(x, exp(x))

def approx_lse_0(x, n=3):
    assert n != 5
    a = x < -0.5
    b = x > 0.5
    return a.if_else(0, b.if_else(x, 0.5 * (x + 0.5) ** 2)) - x

def relu_prime(x):
    """ ReLU derivative. """
    return (0 <= x)

def relu(x):
    """ ReLU function (maximum of input and zero). """
    return (0 < x).if_else(x, 0)

def argmax(x):
    """ Compute index of maximum element.

    :param x: iterable
    :returns: sint or 0 if :py:obj:`x` has length 1
    """
    def op(a, b):
        comp = b[1].less_than(a[1], sync=False)
        return comp.if_else(a[0], b[0]), comp.if_else(a[1], b[1])
    res = tree_reduce(op, enumerate(x))[0]
    if isinstance(res, regint):
        res = cint(res)
    return res

def softmax(x):
    """ Softmax.

    :param x: vector or list of sfix
    :returns: sfix vector
    """
    return softmax_from_exp(exp_for_softmax(x)[0])

def exp_for_softmax(x):
    m = util.max(x) - get_limit(x[0]) + math.log(len(x))
    mv = m.expand_to_vector(len(x))
    try:
        x = x.get_vector()
    except AttributeError:
        x = sfix(x)
    if use_mux:
        return exp(x - mv), m
    else:
        return (x - mv > -get_limit(x)).if_else(exp(x - mv), 0), m

def softmax_from_exp(x):
    return x / sum(x)

report_progress = False

def progress(x):
    if report_progress:
        print_ln(x)
        time()

def set_n_threads(n_threads):
    Layer.n_threads = n_threads
    Optimizer.n_threads = n_threads

def _no_mem_warnings(function):
    def wrapper(*args, **kwargs):
        get_program().warn_about_mem.append(False)
        res = function(*args, **kwargs)
        get_program().warn_about_mem.pop()
        return res
    copy_doc(wrapper, function)
    return wrapper

def _layer_method_call_tape(function):
    function = method_call_tape(function)
    def wrapper(self, *args, **kwargs):
        self._Y.alloc()
        if self.inputs and len(self.inputs) == 1:
            backup = self.inputs
            del self.inputs
            res = function(self, *args, **kwargs)
            self.inputs = backup
            return res
        else:
            return function(self, *args, **kwargs)
    return wrapper

class Tensor(MultiArray):
    def __init__(self, *args, **kwargs):
        kwargs['alloc'] = False
        super(Tensor, self).__init__(*args, **kwargs)

    def input_from(self, *args, **kwargs):
        self.alloc()
        super(Tensor, self).input_from(*args, **kwargs)

    def __getitem__(self, *args):
        self.alloc()
        return super(Tensor, self).__getitem__(*args)

    def assign_all(self, *args):
        self.alloc()
        return super(Tensor, self).assign_all(*args)

    def assign_vector(self, *args, **kwargs):
        self.alloc()
        return super(Tensor, self).assign_vector(*args, **kwargs)

    def assign_vector_by_indices(self, *args):
        self.alloc()
        return super(Tensor, self).assign_vector_by_indices(*args)

    def randomize(self, *args, **kwargs):
        self.alloc()
        return super(Tensor, self).randomize(*args, **kwargs)

class Layer:
    n_threads = 1
    inputs = []
    input_bias = True
    thetas = lambda self: ()
    debug_output = False
    back_batch_size = 128
    print_random_update = False

    @property
    def shape(self):
        return list(self._Y.sizes)

    @property
    def X(self):
        self._X.alloc()
        return self._X

    @X.setter
    def X(self, value):
        self._X = value

    @property
    def Y(self):
        self._Y.alloc()
        return self._Y

    @Y.setter
    def Y(self, value):
        self._Y = value

    @_layer_method_call_tape
    def forward(self, batch=None, training=None):
        if batch is None:
            batch = Array.create_from(regint(0))
        self._forward(batch)

    def __str__(self):
        return type(self).__name__ + str(self._Y.shape)

    def __repr__(self):
        return '%s(%s)' % (type(self).__name__, self._Y.shape)

class NoVariableLayer(Layer):
    input_from = lambda *args, **kwargs: None
    output_weights = lambda *args: None
    reveal_parameters_to_binary = lambda *args, **kwargs: None

    nablas = lambda self: ()
    reset = lambda self: None

class OutputBase(NoVariableLayer):
    sample_mask = None

    def set_sample_mask(self, sample_mask):
        self.sample_mask = sample_mask and Array.create_from(sample_mask)

class Output(OutputBase):
    """ Fixed-point logistic regression output layer.

    :param N: number of examples
    :param approx: :py:obj:`False` (default) or parameter for :py:obj:`approx_sigmoid`
    """
    n_outputs = 2

    @classmethod
    def from_args(cls, N, program):
        res = cls(N, approx='approx' in program.args)
        res.compute_loss = not 'no_loss' in program.args
        return res

    def __init__(self, N, debug=False, approx=False):
        self.N = N
        self.X = sfix.Array(N)
        self.Y = sfix.Array(N)
        self.nabla_X = sfix.Array(N)
        self.l = MemValue(sfix(-1))
        self.e_x = sfix.Array(N)
        self.debug = debug
        self.weights = None
        self.approx = approx
        self.compute_loss = True
        self.d_out = 1

    @staticmethod
    def divisor(divisor, size=1):
        return cfix(1.0 / divisor, size=size)

    def _forward(self, batch):
        if self.approx == 5:
            self.l.write(999)
            return
        N = len(batch)
        lse = sfix.Array(N)
        @multithread(self.n_threads, N)
        def _(base, size):
            x = self.X.get_vector(base, size)
            y = self.Y.get(batch.get_vector(base, size))
            if self.approx:
                if self.compute_loss:
                    lse.assign(approx_lse_0(x, self.approx) + x * (1 - y), base)
                return
            e_x = exp(-x)
            self.e_x.assign(e_x, base)
            if self.compute_loss:
                lse.assign(lse_0_from_e_x(-x, e_x) + x * (1 - y), base)
        if self.compute_loss and self.sample_mask:
            mask = self.sample_mask.get_slice_vector(batch)
            self.l.write(lse[:].dot(mask)) / sum(mask)
        else:
            self.l.write(sum(lse) * self.divisor(N, 1))

    def eval(self, size, base=0, top=False):
        if top:
            return self.X.get_vector(base, size) > 0
        if self.approx:
            return approx_sigmoid(self.X.get_vector(base, size), self.approx)
        else:
            return sigmoid(self.X.get_vector(base, size))

    def backward(self, batch):
        N = len(batch)
        @multithread(self.n_threads, N)
        def _(base, size):
            diff = self.eval(size, base) - \
                   self.Y.get(batch.get_vector(base, size))
            if self.weights is not None:
                assert N == len(self.weights)
                diff *= self.weights.get_vector(base, size)
                assert self.weight_total == N
            if self.sample_mask is not None:
                diff *= self.sample_mask.get(batch.get_vector(base, size))
            self.nabla_X.assign(diff, base)
        # @for_range_opt(len(diff))
        # def _(i):
        #     self.nabla_X[i] = self.nabla_X[i] * self.weights[i]
        if self.debug_output:
            print_ln('sigmoid X %s', self.X.reveal_nested())
            print_ln('sigmoid nabla %s', self.nabla_X.reveal_nested())
            print_ln('batch %s', batch.reveal_nested())

    def set_weights(self, weights):
        assert sfix.f == cfix.f
        self.weights = cfix.Array(len(weights))
        self.weights.assign(weights)
        self.weight_total = sum(weights)

    def average_loss(self, N):
        return self.l.reveal()

    def reveal_correctness(self, n=None, Y=None, debug=False):
        if n is None:
            n = self.X.sizes[0]
        if Y is None:
            Y = self.Y
        assert isinstance(Y, Array)
        n_correct = MemValue(0)
        n_printed = MemValue(0)
        @for_range_opt(n)
        def _(i):
            truth = Y[i].reveal()
            b = self.X[i].reveal()
            if debug:
                nabla = self.nabla_X[i].reveal()
            guess = b > 0
            correct = truth == guess
            n_correct.iadd(correct)
            if debug:
                to_print = (1 - correct) * (n_printed < 10)
                n_printed.iadd(to_print)
                print_ln_if(to_print, '%s: %s %s %s %s',
	                    i, truth, guess, b, nabla)
        return n_correct

class LinearOutput(OutputBase):
    n_outputs = -1

    def __init__(self, N, n_targets=1):
        if n_targets == 1:
            shape = N,
        else:
            shape = N, n_targets
        self.X = sfix.Tensor(shape)
        self.Y = sfix.Tensor(shape)
        self.nabla_X = sfix.Tensor(shape)
        self.l = MemValue(sfix(0))
        self.d_out = n_targets

    def _forward(self, batch):
        assert len(self.X.shape) == 1
        N = len(batch)
        guess = self.X.get_vector(0, N)
        truth = self.Y.get(batch.get_vector(0, N))
        diff = guess - truth
        if self.sample_mask:
            sample_mask = self.sample_mask.get(batch.get_vector(0, N))
            diff = diff * sample_mask
            self.l.write(sum((diff) ** 2) / sum(sample_mask))
        else:
            self.l.write(sum((diff) ** 2) * Output.divisor(N))
        self.nabla_X.assign_vector(diff)
        #print_ln('%s %s %s', diff.reveal(), truth.reveal(), guess.reveal())

    def backward(self, batch):
        pass

    def reveal_correctness(*args):
        return 0

    def average_loss(self, N):
        return self.l.reveal()

    def eval(self, size, base=0, top=False):
        return self.X.get_part(base, size)

class MultiOutputBase(NoVariableLayer):
    def __init__(self, N, d_out, approx=False, debug=False):
        self.X = sfix.Matrix(N, d_out)
        self.Y = sint.Matrix(N, d_out)
        self.nabla_X = sfix.Matrix(N, d_out)
        self.l = MemValue(sfix(-1))
        self.losses = sfix.Array(N)
        self.approx = None
        self.N = N
        self.d_out = d_out
        self.compute_loss = True

    def eval(self, N):
        d_out = self.X.sizes[1]
        res = sfix.Matrix(N, d_out)
        res.assign_vector(self.X.get_part_vector(0, N))
        return res

    def average_loss(self, N):
        return sum(self.losses.get_vector(0, N)).reveal() / N

    def reveal_correctness(self, n=None, Y=None, debug=False):
        if n is None:
            n = self.X.sizes[0]
        if Y is None:
            Y = self.Y
        n_printed = MemValue(0)
        assert n <= len(self.X)
        assert n <= len(Y)
        Y.address = MemValue.if_necessary(Y.address)
        @map_sum(None if debug else self.n_threads, None, n, 1, regint)
        def _(i):
            a = Y[i].reveal_list()
            b = self.X[i].reveal_list()
            if debug:
                loss = self.losses[i].reveal()
                exp = self.get_extra_debugging(i)
                nabla = self.nabla_X[i].reveal_list()
            truth = argmax(a)
            guess = argmax(b)
            correct = truth == guess
            if debug:
                to_print = (1 - correct) * (n_printed < 10)
                n_printed.iadd(to_print)
                print_ln_if(to_print, '%s: %s %s %s %s %s %s',
	                    i, truth, guess, loss, b, exp, nabla)
            return correct
        return _()

    @property
    def n_outputs(self):
        return self.d_out

    def get_extra_debugging(self, i):
        return ''

    @staticmethod
    def from_args(program, N, n_output):
        if 'relu_out' in program.args:
            res = ReluMultiOutput(N, n_output)
        else:
            res = MultiOutput(N, n_output, approx='approx' in program.args)
            res.cheaper_loss = 'mse' in program.args
        res.compute_loss = not 'no_loss' in program.args
        for arg in program.args:
            m = re.match('approx=(.*)', arg)
            if m:
                res.approx = float(m.group(1))
        return res

class MultiOutput(MultiOutputBase):
    """
    Output layer for multi-class classification with softmax and cross entropy.

    :param N: number of examples
    :param d_out: number of classes
    :param approx: use ReLU division instead of softmax for the loss
    """
    def __init__(self, N, d_out, approx=False, debug=False):
        MultiOutputBase.__init__(self, N, d_out)
        self.exp = sfix.Matrix(N, d_out)
        self.approx = approx
        self.positives = sint.Matrix(N, d_out)
        self.relus = sfix.Matrix(N, d_out)
        self.cheaper_loss = False
        self.debug = debug
        self.true_X = sfix.Array(N)

    def __repr__(self):
        return '%s(%s, %s, approx=%s)' % \
            (type(self).__name__, self.N, self.d_out, self.approx)

    def _forward(self, batch):
        N = len(batch)
        d_out = self.X.sizes[1]
        tmp = self.losses
        @for_range_opt_multithread(self.n_threads, N)
        def _(i):
            if self.approx:
                if self.cheaper_loss or isinstance(self.approx, float):
                    limit = 0
                else:
                    limit = 0.1
                positives = self.X[i].get_vector() > limit
                relus = positives.if_else(self.X[i].get_vector(), 0)
                self.positives[i].assign_vector(positives)
                self.relus[i].assign_vector(relus)
                if self.compute_loss:
                    if self.cheaper_loss:
                        s = sum(relus)
                        tmp[i] = sum((self.Y[batch[i]][j] * s - relus[j]) ** 2
                                     for j in range(d_out)) / s ** 2 * 0.5
                    else:
                        div = relus / sum(relus).expand_to_vector(d_out)
                        self.losses[i] = -sfix.dot_product(
                            self.Y[batch[i]].get_vector(), log_e(div))
            else:
                e, m = exp_for_softmax(self.X[i])
                self.exp[i].assign_vector(e)
                if self.compute_loss:
                    true_X = sfix.dot_product(self.Y[batch[i]], self.X[i])
                    tmp[i] = m + log_e(sum(e)) - true_X
                    self.true_X[i] = true_X
        self.l.write(sum(tmp.get_vector(0, N)) / N)

    def eval(self, N, top=False):
        d_out = self.X.sizes[1]
        if top:
            res = sint.Array(N)
            @for_range_opt_multithread(self.n_threads, N)
            def _(i):
                res[i] = argmax(self.X[i])
            return res
        res = sfix.Matrix(N, d_out)
        if self.approx:
            @for_range_opt_multithread(self.n_threads, N)
            def _(i):
                relus = (self.X[i].get_vector() > 0).if_else(
                    self.X[i].get_vector(), 0)
                res[i].assign_vector(relus / sum(relus).expand_to_vector(d_out))
            return res
        @for_range_opt_multithread(self.n_threads, N)
        def _(i):
            x = self.X[i].get_vector() - \
                util.max(self.X[i].get_vector()).expand_to_vector(d_out)
            e = exp(x)
            res[i].assign_vector(e / sum(e).expand_to_vector(d_out))
        return res

    def backward(self, batch):
        d_out = self.X.sizes[1]
        if self.approx:
            @for_range_opt_multithread(self.n_threads, len(batch))
            def _(i):
                if self.cheaper_loss:
                    s = sum(self.relus[i])
                    ss = s * s * s
                    inv = 1 / ss
                    @for_range_opt(d_out)
                    def _(j):
                        res = 0
                        for k in range(d_out):
                            relu = self.relus[i][k]
                            summand = relu - self.Y[batch[i]][k] * s
                            summand *= (sfix.from_sint(j == k) - relu)
                            res += summand
                        fallback = -self.Y[batch[i]][j]
                        res *= inv
                        self.nabla_X[i][j] = self.positives[i][j].if_else(res, fallback)
                    return
                relus = self.relus[i].get_vector()
                if isinstance(self.approx, float):
                    relus += self.approx
                positives = self.positives[i].get_vector()
                inv = (1 / sum(relus)).expand_to_vector(d_out)
                truths = self.Y[batch[i]].get_vector()
                raw = truths / relus - inv
                self.nabla_X[i] = -positives.if_else(raw, truths)
            self.maybe_debug_backward(batch)
            return
        @for_range_opt_multithread(self.n_threads, len(batch))
        def _(i):
            div = softmax_from_exp(self.exp[i])
            self.nabla_X[i][:] = -self.Y[batch[i]][:] + div
        self.maybe_debug_backward(batch)

    def maybe_debug_backward(self, batch):
        if self.debug:
            @for_range(len(batch))
            def _(i):
                check = 0
                for j in range(self.X.sizes[1]):
                    to_check = self.nabla_X[i][j].reveal()
                    check += (to_check > len(batch)) + (to_check < -len(batch))
                print_ln_if(check, 'X %s', self.X[i].reveal_nested())
                print_ln_if(check, 'exp %s', self.exp[i].reveal_nested())
                print_ln_if(check, 'nabla X %s',
                            self.nabla_X[i].reveal_nested())

    def get_extra_debugging(self, i):
        if self.approx:
            return self.relus[i].reveal_list()
        else:
            return self.exp[i].reveal_list()

class ReluMultiOutput(MultiOutputBase):
    """
    Output layer for multi-class classification with back-propagation
    based on ReLU division.

    :param N: number of examples
    :param d_out: number of classes
    """
    def forward(self, batch, training=None):
        self.l.write(999)

    def backward(self, batch):
        N = len(batch)
        d_out = self.X.sizes[1]
        relus = sfix.Matrix(N, d_out)
        @for_range_opt_multithread(self.n_threads, len(batch))
        def _(i):
            positives = self.X[i].get_vector() > 0
            relus = positives.if_else(self.X[i].get_vector(), 0)
            s = sum(relus)
            inv = 1 / s
            prod = relus * inv
            res = prod - self.Y[batch[i]].get_vector()
            self.nabla_X[i].assign_vector(res)

class DenseBase(Layer):
    thetas = lambda self: (self.W, self.b)
    nablas = lambda self: (self.nabla_W, self.nabla_b)

    def output_weights(self):
        self.W.print_reveal_nested()
        print_ln('%s', self.b.reveal_nested())

    def reveal_parameters_to_binary(self, reshape=None):
        if reshape:
            trans = self.W.transpose()
            O = trans.sizes[0]
            tmp = MultiArray([O] + reshape,
                             value_type=self.W.value_type,
                             address=trans.address)
            X, Y, C = reshape
            @for_range(O)
            def _(i):
                @for_range(C)
                def _(j):
                    part = tmp.get_vector_by_indices(i, None, None, j)
                    part.reveal().binary_output()
        else:
            self.W.transpose().reveal_to_binary_output()
        if self.input_bias:
            self.b.reveal_to_binary_output()

    def backward_params(self, f_schur_Y, batch):
        N = len(batch)
        tmp = Matrix(self.d_in, self.d_out, unreduced_sfix)

        # A (f_schur_Y/nabla_Y) is stored at sequential batch indices [0, 1, ..., N-1]
        A = sfix.Matrix(N * self.d, self.d_out, address=f_schur_Y.address)
        # B (X) is stored at the full dataset size, not just the batch
        B = sfix.Matrix(self.N * self.d, self.d_in, address=self.X.address)

        @multithread(self.n_threads, self.d_in)
        def _(base, size):
            # For A: use sequential indices [0, 1, ..., N*d-1]
            # For B: use actual batch indices expanded for d dimension
            batch_d_indices = regint.Array(N * self.d)
            @for_range(N)
            def _(i):
                # batch[i] gives the actual sample index in the full dataset
                # For Dense with d>1, we need to map to flattened indices
                actual_sample_idx = batch[i]
                @for_range(self.d)
                def _(d_idx):
                    batch_d_indices[i * self.d + d_idx] = actual_sample_idx * self.d + d_idx

            mp = B.direct_trans_mul(A, reduce=False,
                                    indices=(regint.inc(size, base),
                                             batch_d_indices.get_vector(),
                                             regint.inc(N * self.d),
                                             regint.inc(self.d_out)))

            tmp.assign_part_vector(mp, base)

        progress('nabla W (matmul)')

        @multithread(self.n_threads, self.d_in * self.d_out,
                     max_size=get_program().budget)
        def _(base, size):
            self.nabla_W.assign_vector(
                tmp.get_vector(base, size).reduce_after_mul(), base=base)

        if self.print_random_update:
            print_ln('backward %s', self)
            i = regint.get_random(64) % self.d_in
            j = regint.get_random(64) % self.d_out
            print_ln('%s at (%s, %s): before=%s after=%s A=%s B=%s',
                     str(self.nabla_W), i, j, tmp[i][j].v.reveal(),
                     self.nabla_W[i][j].reveal(),
                     A.get_column(j).reveal(),
                     B.get_column_by_row_indices(
                         batch.get_vector(), i).reveal())
            print_ln('batch=%s B=%s', batch,
                     [self.X[bi][0][i].reveal() for bi in batch])

        progress('nabla W')

        self.nabla_b.assign_vector(sum(sum(f_schur_Y[k][j].get_vector()
                                           for k in range(N))
                                       for j in range(self.d)))

        progress('nabla b')

        if self.debug_output:
            print_ln('dense nabla Y %s', self.nabla_Y.reveal_nested())
            print_ln('dense W %s', self.W.reveal_nested())
            print_ln('dense nabla X %s', self.nabla_X.reveal_nested())
        if self.debug:
            limit = N * self.debug
            @for_range_opt(self.d_in)
            def _(i):
                @for_range_opt(self.d_out)
                def _(j):
                    to_check = self.nabla_W[i][j].reveal()
                    check = sum(to_check > limit) + sum(to_check < -limit)
                    @if_(check)
                    def _():
                        print_ln('nabla W %s %s %s: %s', i, j, self.W.sizes, to_check)
                        print_ln('Y %s', [f_schur_Y[k][0][j].reveal()
                                          for k in range(N)])
                        print_ln('X %s', [self.X[k][0][i].reveal()
                                          for k in range(N)])
            @for_range_opt(self.d_out)
            def _(j):
                to_check = self.nabla_b[j].reveal()
                check = sum(to_check > limit) + sum(to_check < -limit)
                @if_(check)
                def _():
                    print_ln('nabla b %s %s: %s', j, len(self.b), to_check)
                    print_ln('Y %s', [f_schur_Y[k][0][j].reveal()
                                      for k in range(N)])
            @for_range_opt(len(batch))
            def _(i):
                to_check = self.nabla_X[i].get_vector().reveal()
                check = sum(to_check > limit) + sum(to_check < -limit)
                @if_(check)
                def _():
                    print_ln('X %s %s', i, self.X[i].reveal_nested())
                    print_ln('Y %s %s', i, f_schur_Y[i].reveal_nested())

class Dense(DenseBase):
    """ Fixed-point dense (matrix multiplication) layer.
    Supports inputs of size [N, d, d_in] to map to [N, d, d_out]. If d > 1, the layer
    behaves like torch's nn.Linear which loops over the additional d

    :param N: number of examples
    :param d_in: input dimension
    :param d_out: output dimension
    :param d: (optional) extra dimension
    """
    def __init__(self, N, d_in, d_out, d=1, activation='id', debug=False):
        if activation == 'id':
            self.activation_layer = None
        elif activation == 'relu':
            self.activation_layer = Relu([N, d, d_out])
        elif activation == 'square':
            self.activation_layer = Square([N, d, d_out])
        else:
            raise CompilerError('activation not supported: %s', activation)

        self.N = N
        self.d_in = d_in
        self.d_out = d_out
        self.d = d
        self.activation = activation

        self.X = Tensor([N, d, d_in], sfix)
        self.Y = Tensor([N, d, d_out], sfix)
        self.W = Tensor([d_in, d_out], sfix)
        self.b = sfix.Array(d_out)

        back_N = min(N, self.back_batch_size)
        self.nabla_Y = Tensor([back_N, d, d_out], sfix)
        self.nabla_X = Tensor([back_N, d, d_in], sfix)
        self.nabla_W = Tensor([d_in, d_out], sfix)
        self.nabla_b = sfix.Array(d_out)

        self.debug = debug

        l = self.activation_layer
        if l:
            self.f_input = l.X
            l.Y = self.Y
            l.nabla_Y = self.nabla_Y
        else:
            self.f_input = self.Y

    def __repr__(self):
        return '%s(%s, %s, %s, activation=%s)' % \
            (type(self).__name__, self.N, self.d_in,
             self.d_out, repr(self.activation))

    def reset(self):
        d_in = self.d_in
        d_out = self.d_out
        r = math.sqrt(6.0 / (d_in + d_out))
        print('Initializing dense weights in [%f,%f]' % (-r, r))
        self.W.randomize(-r, r, n_threads=self.n_threads)
        self.b.assign_all(0)

    def input_from(self, player, **kwargs):
        self.W.input_from(player, **kwargs)
        if self.input_bias:
            self.b.input_from(player, **kwargs)

    def compute_f_input(self, batch):
        N = len(batch)
        if self.input_bias:
            prod = MultiArray([N, self.d, self.d_out], sfix)
        else:
            prod = self.f_input

        # flattened_array version
        result_matrix = sfix.Matrix(N * self.d, self.d_out, address=prod.address)
        max_size = get_program().budget

        # X is stored at full dataset indices, batch specifies which samples to use
        X_sub = sfix.Matrix(self.N * self.d, self.d_in, address=self.X.address)

        # Precompute batch_d_indices for all N*d elements
        # For each sample in batch, expand to d consecutive indices
        batch_d_indices = regint.Array(N * self.d)
        @for_range(N)
        def _(i):
            actual_sample = batch[i]
            batch_d_indices.assign(regint.inc(self.d, actual_sample * self.d), i * self.d)

        @multithread(self.n_threads, N * self.d, max_size)
        def _(base, size):
            result_matrix.assign_part_vector(
                X_sub.direct_mul(self.W, indices=(
                    batch_d_indices.get_vector(base, size), regint.inc(self.d_in),
                    regint.inc(self.d_in), regint.inc(self.d_out))), base)

        if self.input_bias:
            if self.d_out == 1:
                @multithread(self.n_threads, N)
                def _(base, size):
                    v = prod.get_vector(base, size) + self.b.expand_to_vector(0, size)
                    self.f_input.assign_vector(v, base)
            else:
                @for_range_multithread(self.n_threads, 100, [N, self.d])
                def _(i, j):
                    v = prod[i][j].get_vector() + self.b.get_vector()
                    self.f_input[i][j].assign_vector(v)

        progress('f input')

    def _forward(self, batch=None):
        if not issubclass(self.W.value_type, _single) \
           or not issubclass(self.X.value_type, _single):
            raise CompilerError(
                'dense inputs have to be sfix in arithmetic circuits')

        if batch is None:
            batch = regint.Array(self.N)
            batch.assign(regint.inc(self.N))
        self.compute_f_input(batch=batch)
        if self.activation_layer:
            self.activation_layer.forward(batch, training=True)
        if self.debug_output:
            print_ln('dense X %s', self.X.reveal_nested())
            print_ln('dense W %s', self.W.reveal_nested())
            print_ln('dense b %s', self.b.reveal_nested())
            print_ln('dense Y %s', self.Y.reveal_nested())
        if self.debug:
            limit = self.debug
            @for_range_opt(len(batch))
            def _(i):
                @for_range_opt(self.d_out)
                def _(j):
                    to_check = self.Y[i][0][j].reveal()
                    check = to_check > limit
                    @if_(check)
                    def _():
                        print_ln('dense Y %s %s %s %s', i, j, self.W.sizes, to_check)
                        print_ln('X %s', self.X[i].reveal_nested())
                        print_ln('W %s',
                                 [self.W[k][j].reveal() for k in range(self.d_in)])

    def backward(self, compute_nabla_X=True, batch=None):
        N = len(batch)
        d = self.d
        d_out = self.d_out
        X = self.X
        Y = self.Y
        W = self.W
        b = self.b
        nabla_X = self.nabla_X
        nabla_Y = self.nabla_Y
        nabla_W = self.nabla_W
        nabla_b = self.nabla_b

        if self.activation_layer:
            self.activation_layer.backward(batch)
            f_schur_Y = self.activation_layer.nabla_X
        else:
            f_schur_Y = nabla_Y

        if compute_nabla_X:
            nabla_X.alloc()

            # flattened matrix version
            result_matrix = sfix.Matrix(N * self.d, self.d_in, address=nabla_X.address)
            # Note: f_schur_Y is stored at indices [0, 1, ..., N-1] not at actual batch indices
            @multithread(self.n_threads, N * self.d)
            def _(base, size):
                X_sub = sfix.Matrix(N * self.d, self.d_out, address=f_schur_Y.address)

                result_matrix.assign_part_vector(
                    X_sub.direct_mul_trans(self.W, indices=(regint.inc(size, base=base),
                                                            regint.inc(self.d_out),
                                                            regint.inc(self.d_out),
                                                            regint.inc(self.d_in))),
                base)

            if self.print_random_update:
                print_ln('backward %s', self)
                index = regint.get_random(64) % self.nabla_X.total_size()
                print_ln('%s nabla_X at %s: %s', str(self.nabla_X),
                         index, self.nabla_X.to_array()[index].reveal())

            progress('nabla X')

        self.backward_params(f_schur_Y, batch=batch)

class QuantizedDense(DenseBase):
    def __init__(self, N, d_in, d_out):
        self.N = N
        self.d_in = d_in
        self.d_out = d_out
        self.d = 1
        self.H = math.sqrt(1.5 / (d_in + d_out))

        self.W = sfix.Matrix(d_in, d_out)
        self.nabla_W = self.W.same_shape()
        self.T = sint.Matrix(d_in, d_out)
        self.b = sfix.Array(d_out)
        self.nabla_b = self.b.same_shape()

        self.X = Tensor([N, 1, d_in], sfix)
        self.Y = Tensor([N, 1, d_out], sfix)
        self.nabla_Y = self.Y.same_shape()

    def reset(self):
        @for_range(self.d_in)
        def _(i):
            @for_range(self.d_out)
            def _(j):
                self.W[i][j] = sfix.get_random(-1, 1)
        self.b.assign_all(0)

    def _forward(self):
        @for_range_opt(self.d_in)
        def _(i):
            @for_range_opt(self.d_out)
            def _(j):
                over = self.W[i][j] > 0.5
                under = self.W[i][j] < -0.5
                self.T[i][j] = over.if_else(1, under.if_else(-1, 0))
                over = self.W[i][j] > 1
                under = self.W[i][j] < -1
                self.W[i][j] = over.if_else(1, under.if_else(-1, self.W[i][j]))
        @for_range_opt(self.N)
        def _(i):
            assert self.d_out == 1
            self.Y[i][0][0] = self.b[0] + self.H * sfix._new(
                sint.dot_product([self.T[j][0] for j in range(self.d_in)],
                                 [self.X[i][0][j].v for j in range(self.d_in)]))

    def backward(self, compute_nabla_X=False):
        assert not compute_nabla_X
        self.backward_params(self.nabla_Y)

class Dropout(NoVariableLayer):
    """ Dropout layer.

    :param N: number of examples
    :param shape: list [N, ...] where N is the number of examples and an arbitrary amount of further dimensions
    :param alpha: probability (power of two)
    """
    def __init__(self, N, d1=None, d2=1, alpha=0.5):
        if isinstance(N, list) or isinstance(N, tuple):
            shape = N
            assert d1 is None, ("If shape is given as list/tuple, d1 must be None. "
                                "Alpha must be passed explicitly for backwards compatibility.")
        else:
            assert d1 is not None, "At least one non-batch dimension must be set"
            shape = [N, d1] if d2 == 1 else [N, d1, d2]
        self.N = shape[0]
        self.X = Tensor(shape, sfix)
        self.Y = Tensor(shape, sfix)
        self.nabla_Y = Tensor(shape, sfix)
        self.nabla_X = Tensor(shape, sfix)
        self.alpha = alpha
        self.B = MultiArray(shape, sint)

    def __repr__(self):
        return '%s(%s, alpha=%s)' % \
            (type(self).__name__, self.shape, self.alpha)

    def forward(self, batch, training=False):
        if training:
            n_bits = -math.log(self.alpha, 2)
            assert n_bits == int(n_bits)
            n_bits = int(n_bits)
            @for_range_opt_multithread(self.n_threads, len(batch))
            def _(i):
                size = reduce(operator.mul, self.shape[1:])
                self.B[i].assign_vector(util.tree_reduce(
                    util.or_op, (sint.get_random_bit(size=size)
                                 for i in range(n_bits))))
            @for_range_opt_multithread(self.n_threads, len(batch))
            def _(i):
                self.Y[i].assign_vector(1 / (1 - self.alpha) *
                    self.X[batch[i]].get_vector() * self.B[i].get_vector())
        else:
            @for_range(len(batch))
            def _(i):
                self.Y[i] = self.X[batch[i]]
        if self.debug_output:
            print_ln('dropout X %s', self.X.reveal_nested())
            print_ln('dropout Y %s', self.Y.reveal_nested())

    def backward(self, compute_nabla_X=True, batch=None):
        if compute_nabla_X:
            @for_range_opt_multithread(self.n_threads, len(batch))
            def _(i):
                self.nabla_X[batch[i]].assign_vector(
                    self.nabla_Y[i].get_vector() * self.B[i].get_vector())
        if self.debug_output:
            print_ln('dropout nabla_Y %s', self.nabla_Y.reveal_nested())
            print_ln('dropout nabla_X %s', self.nabla_X.reveal_nested())

class ElementWiseLayer(NoVariableLayer):
    def __init__(self, shape, inputs=None):
        self.X = Tensor(shape, sfix)
        self.Y = Tensor(shape, sfix)
        backward_shape = list(shape)
        backward_shape[0] = min(shape[0], self.back_batch_size)
        self.nabla_X = Tensor(backward_shape, sfix)
        self.nabla_Y = Tensor(backward_shape, sfix)
        self.inputs = inputs

    def f_part(self, base, size):
        return self.f(self.X.get_vector(base, size))

    def f_prime_part(self, base, size):
        return self.f_prime(self.Y.get_vector(base, size))

    def _forward(self, batch=[0]):
        n_per_item = reduce(operator.mul, self.X.sizes[1:])
        @multithread(self.n_threads, len(batch) * n_per_item,
                     max_size=program.budget)
        def _(base, size):
            self.Y.assign_vector(self.f_part(base, size), base)

        if self.debug_output:
            name = self
            @for_range(len(batch))
            def _(i):
                print_ln('%s X %s %s', name, i, self.X[i].reveal_nested())
                print_ln('%s Y %s %s', name, i, self.Y[i].reveal_nested())

    def backward(self, batch):
        f_prime_bit = MultiArray(self.X.sizes, self.prime_type)
        n_elements = len(batch) * reduce(operator.mul, f_prime_bit.sizes[1:])

        @multithread(self.n_threads, n_elements)
        def _(base, size):
            f_prime_bit.assign_vector(self.f_prime_part(base, size), base)

        progress('f prime')

        @multithread(self.n_threads, n_elements)
        def _(base, size):
            self.nabla_X.assign_vector(self.nabla_Y.get_vector(base, size) *
                                       f_prime_bit.get_vector(base, size),
                                       base)

        progress('f prime schur Y')

        if self.debug_output:
            name = self
            @for_range(len(batch))
            def _(i):
                print_ln('%s X %s %s', name, i, self.X[i].reveal_nested())
                print_ln('%s f_prime %s %s', name, i, f_prime_bit[i].reveal_nested())
                print_ln('%s nabla Y %s %s', name, i, self.nabla_Y[i].reveal_nested())
                print_ln('%s nabla X %s %s', name, i, self.nabla_X[i].reveal_nested())

class Relu(ElementWiseLayer):
    """ Fixed-point ReLU layer.

    :param shape: input/output shape (tuple/list of int)
    """
    prime_type = sint

    def __init__(self, shape, inputs=None):
        super(Relu, self).__init__(shape)
        self.comparisons = None

    def forward(self, batch=None, training=False):
        if training and not self.comparisons:
            self.comparisons = MultiArray(self.shape, sint)
        super(Relu, self).forward(batch=batch, training=training)

    def f_part(self, base, size):
        x = self.X.get_vector(base, size)
        c = x > 0
        if self.comparisons:
            self.comparisons.assign_vector(c, base)
        return c.if_else(x, 0)

    def f_prime_part(self, base, size):
        return self.comparisons.get_vector(base, size)


class Gelu(ElementWiseLayer):
    """ Fixed-point GeLU layer.
    Based on Dong et al., "PUMA: SECURE INFERENCE OF LLAMA-7B IN FIVE MINUTES"

    :param shape: input/output shape (tuple/list of int)
    """
    prime_type = sfix

    def __init__(self, shape, inputs=None, approx=True):
        super(Gelu, self).__init__(shape)
        self.approx = approx
        self.z0s = MultiArray(shape, sint)
        self.z1s = MultiArray(shape, sint)
        self.z2s = MultiArray(shape, sint)

        self.x2s = MultiArray(shape, sfix)
        self.x3s = MultiArray(shape, sfix)
        self.x4s = MultiArray(shape, sfix)

        self.poly_f_0_0 = -0.5054031199708174
        self.poly_f_0_1 = -0.42226581151983866
        self.poly_f_0_2 = -0.11807612951181953
        self.poly_f_0_3 = -0.011034134030615728

        self.poly_f_1_0 = 0.008526321541038084
        self.poly_f_1_1 = 0.5
        self.poly_f_1_2 = 0.3603292692789629
        self.poly_f_1_4 = -0.037688200365904236
        self.poly_f_1_6 = 0.0018067462606141187

    def f_part(self, base, size):
        x = self.X.get_vector(base, size)

        if self.approx:
            return self.compute_gelu_approx(x, base, size)
        else:
            return self.compute_gelu_sigmoid(x)

    def compute_gelu_approx(self, x, base, size):
        # print_ln("GELU inputs %s", x.reveal())
        b0 = x < -4
        b1 = x < -1.95
        b2 = 3 < x

        z0 = b0 ^ b1
        z1 = b1 ^ b2 ^ 1
        z2 = b2

        x1 = x
        x2 = x ** 2
        x3 = x2 * x1
        x4 = x2 ** 2
        x6 = x3 ** 2

        f_0 = self.poly_f_0_0 + self.poly_f_0_1 * x1 + self.poly_f_0_2 * x2 + self.poly_f_0_3 * x3
        f_1 = self.poly_f_1_0 + self.poly_f_1_1 * x1 + self.poly_f_1_2 * x2 + self.poly_f_1_4 * x4 + self.poly_f_1_6 * x6

        self.z0s.assign_vector(z0, base)
        self.z1s.assign_vector(z1, base)
        self.z2s.assign_vector(z2, base)

        self.x2s.assign_vector(x2, base)
        self.x3s.assign_vector(x3, base)
        self.x4s.assign_vector(x6, base)

        return (z0 * f_0) + (z1 * f_1) + (z2 * x)

    def compute_gelu_sigmoid(self, x, base=0):
        return x * sigmoid(0.071355 * (x ** 3) + 1.595769 * x)

    def tanh(self, x, base=0):
        exp_2x = exp(2 * x)

        real_tanh = (exp_2x - 1) / (exp_2x + 1)
        return real_tanh

    def f_prime_part(self, base, size):
        if self.approx:
            return self.f_prime_part_approx(base, size)
        else:
            return self.f_prime_part_sigmoid(base, size)

    def f_prime_part_approx(self, base, size):
        # what we compute here is all derivatives
        # we need to compute the derivative of the function at the point
        poly_prime_f_0_0 = self.poly_f_0_1
        poly_prime_f_0_1 = self.poly_f_0_2 * 2
        poly_prime_f_0_2 = self.poly_f_0_3 * 3

        poly_prime_f_1_0 = self.poly_f_1_1
        poly_prime_f_1_1 = self.poly_f_1_2 * 2
        poly_prime_f_1_3 = self.poly_f_1_4 * 4
        poly_prime_f_1_5 = self.poly_f_1_6 * 6

        x1 = self.X.get_vector(base, size)
        x2 = self.x2s.get_vector(base, size)
        x3 = self.x3s.get_vector(base, size)
        x4 = self.x4s.get_vector(base, size)
        x5 = x4 * x1

        f_0_prime = poly_prime_f_0_0 + poly_prime_f_0_1 * x1 + poly_prime_f_0_2 * x2
        f_1_prime = poly_prime_f_1_0 + poly_prime_f_1_1 * x1 + poly_prime_f_1_3 * x3 + poly_prime_f_1_5 * x5

        z0 = self.z0s.get_vector(base, size)
        z1 = self.z1s.get_vector(base, size)
        z2 = self.z2s.get_vector(base, size)

        print_ln("gelu backward x %s res %s", x1.reveal()[:8], ((z0 * f_0_prime) + (z1 * f_1_prime) + z2).reveal()[:8])

        return (z0 * f_0_prime) + (z1 * f_1_prime) + z2

    def f_prime_part_sigmoid(self, base, size):
        x = self.X.get_vector(base, size)
        # return 0.5 * (1 + self.tanh(0.0356774 * x ** 3 + 0.797884 * x))
        print_ln("f sigmoid")
        x3 = x ** 3
        exp_term = exp(1.59577 * x + 0.071355 * x3)
        return (exp(3.19154* x + 0.14271 * x) + exp_term * (1 + 1.59577 * x + 0.214065 * x3)) / (1 + exp_term) ** 2



class Tanh(ElementWiseLayer):

    prime_type = sfix

    def __init__(self, shape, inputs=None):
        super(Tanh, self).__init__(shape)
        self.tanh_computations = MultiArray(shape, sfix)

    def f_part(self, base, size):
        x = self.X.get_vector(base, size)
        res = self.tanh(x)
        self.tanh_computations.assign_vector(res, base)
        return res

    def tanh(self, x):
        return 2 * sigmoid(2 * x) - 1

    def f_prime_part(self, base, size):
        return 1 - self.tanh_computations.get_vector(base, size) ** 2


class Square(ElementWiseLayer):
    """ Fixed-point square layer.

    :param shape: input/output shape (tuple/list of int)
    """
    f = staticmethod(lambda x: x ** 2)
    f_prime = staticmethod(lambda x: cfix(2, size=x.size) * x)
    prime_type = sfix

class PoolBase(NoVariableLayer):
    def __init__(self, shape, strides=(1, 2, 2, 1), ksize=(1, 2, 2, 1),
                 padding='VALID'):
        assert len(shape) == 4
        assert min(shape) > 0, shape
        for x in strides, ksize:
            for i in 0, 3:
                assert x[i] == 1
        self.X = Tensor(shape, sfix)
        if padding == 'SAME':
            output_shape = [int(math.ceil(shape[i] / strides[i])) for i in range(4)]
            padding = [0, 0]
        else:
            if padding == 'VALID':
                padding = 0
            if isinstance(padding, int):
                padding = [padding, padding]
            output_shape = [shape[0]] + [
                (shape[i + 1] + 2 * padding[i] - ksize[i + 1]) // \
                strides [i + 1] + 1 for i in range(2)] + [shape[3]]
        self.Y = Tensor(output_shape, sfix)
        self.strides = strides
        self.ksize = ksize
        self.padding = padding
        self.nabla_X = Tensor(shape, sfix)
        self.nabla_Y = Tensor(output_shape, sfix)
        self.N = shape[0]
        self.comparisons = Tensor([self.N, self._X.sizes[3],
                                   output_shape[1], output_shape[2],
                                   ksize[1] * ksize[2]], sint)

    def __repr__(self):
        return '%s(%s, strides=%s, ksize=%s, padding=%s)' % \
            (type(self).__name__, self._X.sizes, self.strides,
             self.ksize, self.padding)

    def traverse(self, batch, process):
        need_padding = [self.strides[i] * (self.Y.sizes[i] - 1) + self.ksize[i] >
                        self.X.sizes[i] for i in range(4)]
        if not program.options.budget:
            budget = max(10000, program.budget)
        else:
            budget = program.budget
        @for_range_opt_multithread(self.n_threads,
                                   [len(batch), self.X.sizes[3]], budget=budget)
        def _(l, k):
            bi = batch[l]
            XX = self.X[bi]
            @for_range_opt(self.Y.sizes[1], budget=budget)
            def _(i):
                h_base = self.strides[1] * i - self.padding[1]
                hs = [h_base + jj for jj in range(self.ksize[1])]
                if need_padding[1]:
                    h_ins = [(h < self.X.sizes[1]) * (h >= 0) for h in hs]
                else:
                    h_ins = [True] * self.ksize[1]
                @for_range_opt(self.Y.sizes[2], budget=budget)
                def _(j):
                    w_base = self.strides[2] * j - self.padding[1]
                    pool = []
                    ws = [w_base + jj for jj in range(self.ksize[2])]
                    if need_padding[2]:
                        w_ins = [(w < self.X.sizes[2]) * (w >= 0) for w in ws]
                    else:
                        w_ins = [True] * self.ksize[2]
                    for ii in range(self.ksize[1]):
                        h = hs[ii]
                        h_in = h_ins[ii]
                        XXX = XX[h_in * h]
                        for jj in range(self.ksize[2]):
                            w = ws[jj]
                            w_in = w_ins[jj]
                            if not is_zero(h_in * w_in):
                                pool.append([h_in * w_in * XXX[w_in * w][k],
                                             h_in, w_in, h, w])
                    process(pool, bi, k, i, j)

class MaxPool(PoolBase):
    """ Fixed-point MaxPool layer.

    :param shape: input shape (tuple/list of four int)
    :param strides: strides (tuple/list of four int, first and last must be 1)
    :param ksize: kernel size (tuple/list of four int, first and last must be 1)
    :param padding: :py:obj:`'VALID'` (default), :py:obj:`'SAME'`, integer, or
      list/tuple of integers

    """
    def forward(self, batch=None, training=False):
        if batch is None:
            batch = Array.create_from(regint(0))
        if training:
            self.comparisons.alloc()
        self._forward(batch=batch, training=training)

    @_layer_method_call_tape
    def _forward(self, batch, training):
        def process(pool, bi, k, i, j):
            def m(a, b):
                c = a[0] > b[0]
                l = [c * x for x in a[1]]
                l += [(1 - c) * x for x in b[1]]
                return c.if_else(a[0], b[0]), l
            red = util.tree_reduce(m, [(x[0], [1] if training else [])
                                       for x in pool])
            self.Y[bi][i][j][k] = red[0]
            for ii, x in enumerate(red[1]):
                self.comparisons[bi][k][i][j][ii] = x
        self.traverse(batch, process)

    def backward(self, compute_nabla_X=True, batch=None):
        if compute_nabla_X:
            self.nabla_X.alloc()
            self.nabla_X.assign_all(0)
            break_point('maxpool-backward')
            def process(pool, bi, k, i, j):
                for (x, h_in, w_in, h, w), c \
                    in zip(pool, self.comparisons[bi][k][i][j]):
                    hh = h * h_in
                    ww = w * w_in
                    res = h_in * w_in * c * self.nabla_Y[bi][i][j][k]
                    get_program().protect_memory(True)
                    self.nabla_X[bi][hh][ww][k] += res
                    get_program().protect_memory(False)
        self.traverse(batch, process)

class Argmax(NoVariableLayer):
    """ Fixed-point Argmax layer.

    :param shape: input shape (tuple/list of two int)
    """
    def __init__(self, shape):
        assert len(shape) == 2
        self.X = Tensor(shape, sfix)
        self.Y = Array(shape[0], sint)

    def _forward(self, batch=[0]):
        assert len(batch) == 1
        self.Y[batch[0]] = argmax(self.X[batch[0]])

class Concat(NoVariableLayer):
    """ Fixed-point concatentation layer.

    :param inputs: two input layers (tuple/list)
    :param dimension: dimension for concatenation (must be 3)
    """
    def __init__(self, inputs, dimension):
        self.inputs = inputs
        self.dimension = dimension
        shapes = [inp.shape for inp in inputs]
        assert dimension == 3
        assert len(shapes[0]) == 4
        for shape in shapes:
            assert len(shape) == len(shapes[0])
        shape = []
        for i in range(len(shapes[0])):
            if i == dimension:
                shape.append(sum(x[i] for x in shapes))
            else:
                shape.append(shapes[0][i])
        self.Y = Tensor(shape, sfix)
        self.bases = [sum(x[dimension] for x in shapes[:k])
                      for k in range(len(shapes))]
        self.addresses = Array.create_from(regint(list(
            x.Y.address for x in inputs)))

    def _forward(self, batch=[0]):
        assert len(batch) == 1
        @for_range_multithread(self.n_threads, 1, self.Y.sizes[1:3])
        def _(i, j):
            if len(set(self.bases)) == 1:
                @for_range(len(self.inputs))
                def _(k):
                    self.Y[batch[0]][i][j].assign_part_vector(
                        MultiArray(
                            self.inputs[0].shape,
                            address=self.addresses[k])[i][j].get_vector(),
                        k * self.bases[1])
            else:
                X = [x.Y[batch[0]] for x in self.inputs]
                for k in range(len(self.inputs)):
                    self.Y[batch[0]][i][j].assign_part_vector(
                        X[k][i][j].get_vector(), self.bases[k])

class Add(NoVariableLayer):
    """ Fixed-point addition layer.

    :param inputs: two input layers with same shape (tuple/list)
    """
    def __init__(self, inputs):
        assert len(inputs) > 1
        shape = inputs[0].shape
        for inp in inputs:
            assert inp.shape == shape
        self.Y = Tensor(shape, sfix)
        self.inputs = inputs

        self.nabla_Y = Tensor(shape, sfix)

    def _forward(self, batch=[0]):
        @multithread(self.n_threads, self.Y[0].total_size())
        def _(base, size):
            for bb in batch:
                tmp = sum(inp.Y[bb].get_vector(base, size)
                          for inp in self.inputs)
                self.Y[bb].assign_vector(tmp, base)

    def backward(self, compute_nabla_X=True, batch=None):
        if compute_nabla_X:
            for inp in self.inputs:
                @multithread(self.n_threads, self.Y.total_size())
                def _(base, size):
                    inp.nabla_X.assign_vector(self.nabla_Y.get_vector(base, size), base)


class FusedBatchNorm(Layer):
    """ Fixed-point fused batch normalization layer (inference only).

    :param shape: input/output shape (tuple/list of four int)
    """
    def __init__(self, shape, inputs=None):
        assert len(shape) == 4
        self.X = Tensor(shape, sfix)
        self.Y = Tensor(shape, sfix)
        self.weights = sfix.Array(shape[3])
        self.bias = sfix.Array(shape[3])
        self.inputs = inputs

    def input_from(self, player, **kwargs):
        self.weights.input_from(player, **kwargs)
        self.bias.input_from(player, **kwargs)
        tmp = sfix.Array(len(self.bias))
        tmp.input_from(player, **kwargs)
        tmp.input_from(player, **kwargs)

    def _forward(self, batch=[0]):
        assert len(batch) == 1
        @for_range_opt_multithread(self.n_threads, self.X.sizes[1:3])
        def _(i, j):
            self.Y[batch[0]][i][j].assign_vector(
                self.X[batch[0]][i][j].get_vector() * self.weights.get_vector()
                + self.bias.get_vector())

class BatchNorm(Layer):
    """ Fixed-point batch normalization layer.

    :param shape: input/output shape (tuple/list of four int)
    :param approx: use approximate square root

    """
    thetas = lambda self: (self.weights, self.bias)
    nablas = lambda self: (self.nabla_weights, self.nabla_bias)

    def __init__(self, shape, approx=True, args=None):
        assert len(shape) in (2, 3, 4)
        self.Y = sfix.Tensor(shape)
        if len(shape) == 4:
            shape = [shape[0], shape[1] * shape[2], shape[3]]
        elif len(shape) == 2:
            shape = [shape[0], 1, shape[1]]
        self.my_Y = sfix.Tensor(shape, address=self.Y.address)
        tensors = (Tensor(shape, sfix) for i in range(3))
        self.X, self.nabla_X, self.nabla_Y = tensors
        arrays = (sfix.Array(shape[2]) for i in range(4))
        self.var, self.mu, self.weights, self.bias = arrays
        arrays = (sfix.Array(shape[2]) for i in range(4))
        self.mu_hat, self.var_hat, self.nabla_weights, self.nabla_bias = arrays
        self.epsilon = 2 ** (-sfix.f * 2 // 3 + 1)
        self.momentum = 0.1
        if args != None:
            approx = 'precisebn' not in args
        self.approx = approx
        if approx:
            print('Approximate square root inverse in batch normalization')
            self.InvertSqrt = mpc_math.InvertSqrt
        else:
            print('Precise square root inverse in batch normalization')
            self.InvertSqrt = lambda x: 1 / mpc_math.sqrt(x)
        self.is_trained = False

    def __repr__(self):
        return '%s(%s, approx=%s)' % \
            (type(self).__name__, self.X.sizes, self.approx)

    def reset(self):
        self.bias.assign_all(0)
        self.weights.assign_all(1)
        self.mu_hat.assign_all(0)
        self.var_hat.assign_all(0)

    def _output(self, batch, mu, var):
        factor = sfix.Array(len(mu))
        factor[:] = self.InvertSqrt(var[:] + self.epsilon) * self.weights[:]
        @for_range_opt_multithread(self.n_threads,
                                   [len(batch), self.X.sizes[1]])
        def _(i, j):
            tmp = (self.X[i][j][:] - mu[:]) * factor[:]
            self.my_Y[i][j][:] = self.bias[:] + tmp

    @_layer_method_call_tape
    def forward(self, batch, training=False):
        if training or not self.is_trained:
            d = self.X.sizes[1]
            d_in = self.X.sizes[2]
            s = sfix.Array(d_in)
            @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
            def _(i, j):
                return (self.X[batch[i]][j].get_vector())
            s.assign(_())
            @multithread(self.n_threads, d_in)
            def _(base, size):
                self.mu.assign_vector(
                    s.get_vector(base, size) / (len(batch) * d), base)
            @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
            def _(i, j):
                item = self.X[batch[i]][j].get_vector()
                return ((item - self.mu[:]) ** 2)
            self.var.assign(_())
            @multithread(self.n_threads, d_in)
            def _(base, size):
                self.var.assign_vector(
                    self.var.get_vector(base, size) / (len(batch) * d - 1),
                    base)
            for x, y, in (self.mu_hat, self.mu), (self.var_hat, self.var):
                x[:] = self.momentum * y[:] + (1 - self.momentum) * x[:]
            self._output(batch, self.mu, self.var)
            if self.print_random_update:
                i = regint.get_random(64) % len(batch)
                j = regint.get_random(64) % d
                k = regint.get_random(64) % d_in
                for x in self.mu, self.var:
                    print_ln('%s at %s: %s', str(x), k, x[k].reveal())
                print_ln('%s at (%s, %s, %s): in=%s out=%s',
                         str(self.Y), i, j, k, self.X[i][j][k].reveal(),
                         self.my_Y[i][j][k].reveal())
        else:
            self._output(batch, self.mu_hat, self.var_hat)

    def backward(self, batch, compute_nabla_X=True):
        factor = Array.create_from(
            self.InvertSqrt(self.var[:] + self.epsilon))
        mynYf = self.X.same_shape()
        gamnY = self.X.same_shape()
        gamnYd = self.X.same_shape()
        nYdf = self.X.same_shape()
        d = self.X.sizes[1]
        d_in = self.X.sizes[2]
        @for_range_opt_multithread(self.n_threads, [len(batch), d])
        def _(i, j):
            tmp = self.weights[:] * self.nabla_Y[i][j][:]
            gamnY[i][j] = tmp
            gamnYd[i][j] = tmp * (self.X[i][j][:] - self.mu[:])
            mynYf[i][j] = tmp * factor[:]
            nYdf[i][j] = self.nabla_Y[i][j][:] * \
                    (self.X[i][j][:] - self.mu[:]) * factor[:]
        @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
        def _(i, j):
            return (self.nabla_Y[i][j][:])
        self.nabla_bias.assign(_())
        @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
        def _(i, j):
            return (nYdf[i][j])
        self.nabla_weights.assign(_())
        factor3 = Array.create_from(factor[:] ** 3)
        @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
        def _(i, j):
                return (mynYf[i][j])
        s1 = Array.create_from(_())
        @multithread(self.n_threads, len(s1))
        def _(base, size):
            s1.assign_vector(s1.get_vector(base, size) / (len(batch) * d), base)
        @map_sum_simple(self.n_threads, [len(batch), d], sfix, d_in)
        def _(i, j):
            return (gamnYd[i][j][:] * factor3[:])
        s2 = Array.create_from(_())
        @multithread(self.n_threads, len(s2))
        def _(base, size):
            s2.assign_vector(
                s2.get_vector(base, size) / (len(batch) * d - 1), base)
        @for_range_opt_multithread(self.n_threads, [len(batch), d])
        def _(i, j):
            self.nabla_X[i][j][:] = mynYf[i][j][:] \
                - s1[:] - (self.X[i][j][:] - self.mu[:]) * s2[:]
        if self.print_random_update:
            print_ln('backward %s', self)
            i = regint.get_random(64) % len(batch)
            j = regint.get_random(64) % d
            k = regint.get_random(64) % d_in
            for x in self.nabla_bias, self.nabla_weights:
                print_ln('%s at %s: %s', str(x), k, x[k].reveal())
            print_ln('%s at (%s, %s, %s): in=%s out=%s', str(self.Y), i, j, k,
                     self.nabla_Y[i][j][k].reveal(),
                     self.nabla_X[i][j][k].reveal())

    def reveal_parameters_to_binary(self):
        for param in self.thetas() + (self.mu_hat, self.var_hat):
            param.reveal().binary_output()

class LayerNorm(Layer):  # Changed class name
    """ Fixed-point layer normalization layer.
    For now assumes we only want to normalize over the last dimension

    :param shape: input/output shape (tuple/list of any number of int)
    :param approx: use approximate square root

    """
    thetas = lambda self: (self.weights, self.bias)
    nablas = lambda self: (self.nabla_weights, self.nabla_bias)

    def __init__(self, shape, approx=False, layernorm_eps=None, args=None):
        if len(shape) == 2:
            shape = [shape[0], 1, shape[1]] # Not sure why this extra dimension is added
        tensors = (Tensor(shape, sfix) for i in range(4))
        self.X, self.Y, self.nabla_X, self.nabla_Y = tensors
        self.epsilon = 2 ** (-sfix.f * 2 // 3 + 1) #if layernorm_eps is not None else sfix(layernorm_eps)
        self.approx = approx
        if approx:
            print('Approximate square root inverse in layer normalization')
            self.InvertSqrt = mpc_math.InvertSqrt
        else:
            print('Precise square root inverse in layer normalization')
            self.InvertSqrt = lambda x: 1 / mpc_math.sqrt(x)
        self.weights = sfix.Array(shape[-1])
        self.bias = sfix.Array(shape[-1])

        batch_shape = [shape[0]] + list(self.X.sizes[1:-1])
        self.mu = sfix.Tensor(batch_shape)
        self.var = sfix.Tensor(batch_shape)
        self.nabla_weights = sfix.Array(shape[-1])
        self.nabla_bias = sfix.Array(shape[-1])

    def __repr__(self):
        return '%s(%s, approx=%s)' % \
            (type(self).__name__, self.X.sizes, self.approx)

    def reset(self):  # Simplified reset method
        self.bias.assign_all(0)
        self.weights.assign_all(1)

    def _output(self, batch, mu, var):
        batch_shape = [len(batch)] + list(self.X.sizes[1:-1])
        factor = sfix.Tensor(batch_shape)

        @multithread(self.n_threads, len(batch))
        def _(base, size):
            factor.assign_part_vector(
                self.InvertSqrt(var.get_part_vector(base, size) + self.epsilon),
                base)

        @for_range_opt_multithread(self.n_threads,
                                   batch_shape)
        def _(*arg):
            sel_X = self.X
            sel_Y = self.Y
            mu_sel = mu
            fac_sel = factor
            for ar in arg:
                sel_X = sel_X[ar]
                sel_Y = sel_Y[ar]
                mu_sel = mu_sel[ar]
                fac_sel = fac_sel[ar]
            tmp = self.weights[:] * (sel_X[:] - mu_sel) * fac_sel  # Removed self.mu reference
            sel_Y[:] = self.bias[:] + tmp

    def forward(self, batch, training=False):
        d = self.X.sizes[1]
        d_in = self.X.sizes[2]
        X_batch = MultiArray([len(batch), self.X.sizes[1], self.X.sizes[2]], sfix)
        X_batch.assign_vector(self.X.get_slice_vector(batch))
        batch_shape = [len(batch)] + list(self.X.sizes[1:-1])

        @for_range_opt_multithread(self.n_threads, batch_shape)
        def _(*arg):
            sel = X_batch
            for ar in arg:
                sel = sel[ar]
            res = sum(sel[:])
            if len(arg) == 2:
                self.mu[arg[0]][arg[1]] = res
            else:
                raise NotImplementedError("Only 3D tensors supported")

        @multithread(self.n_threads, self.mu.total_size())
        def _(base, size):
            total_dim = self.X.sizes[-1]
            self.mu.assign_vector(
                self.mu.get_vector(base, size) / total_dim, base)

        @for_range_opt_multithread(self.n_threads, batch_shape)
        def _(*arg):
            sel = X_batch
            mu_sel = self.mu
            for ar in arg:
                sel = sel[ar]
                mu_sel = mu_sel[ar]
            res = sum((sel[:] - mu_sel) ** 2) # Removed self.mu reference
            if len(arg) == 2:
                self.var[arg[0]][arg[1]] = res
            else:
                raise NotImplementedError("Only 3D tensors supported")

        @multithread(self.n_threads, self.var.total_size())
        def _(base, size):
            total_dim = self.X.sizes[-1]
            self.var.assign_vector(
                self.var.get_vector(base, size) / (total_dim),
                base)
        self._output(batch, self.mu, self.var)  # Simplified to always use current batch statistics
        if self.print_random_update:
            i = regint.get_random(64) % len(batch)
            j = regint.get_random(64) % d
            k = regint.get_random(64) % d_in
            for x in self.mu, self.var:
                print_ln('%s at %s: %s', str(x), k, x[k].reveal())
            print_ln('%s at (%s, %s, %s): in=%s out=%s',
                     str(self.Y), i, j, k, self.X[i][j][k].reveal(),
                     self.Y[i][j][k].reveal())

    def backward(self, batch, compute_nabla_X=True):
        batch_shape = [len(batch)] + list(self.X.sizes[1:-1])
        factor = sfix.Tensor(batch_shape)
        factor[:] = self.InvertSqrt(self.var[:] + self.epsilon) # TODO: Can we cache this?

        # Gradients wrt outputs stored in self.nabla_Y
        norm = self.X.same_shape()  # Gradient wrt scaled input (gamma * nabla_Y)
        nYdf = self.X.same_shape()  # Used for weights gradient computation
        dNorm = self.X.same_shape() # only needed for nabla_X comp
        # dNormNorm = self.X.same_shape()

        # print("layernorm back ", batch, nYdf.sizes, factor.sizes)
        # print("batch shape", batch_shape, self.nabla_Y.sizes)
        # print(self.nabla_bias.length, self.X.sizes)

        @for_range_opt_multithread(self.n_threads, batch_shape)
        def _(*arg):
            assert len(arg) == 2, "Only 3D tensors supported"
            norm[arg[0]][arg[1]][:] = (self.X[batch[arg[0]]][arg[1]][:] - self.mu[arg[0]][arg[1]]) * factor[arg[0]][arg[1]] # norm_bti
            nYdf[arg[0]][arg[1]][:] = self.nabla_Y[batch[arg[0]]][arg[1]][:] * norm[arg[0]][arg[1]][:]

            dNorm[arg[0]][arg[1]][:] = self.nabla_Y[batch[arg[0]]][arg[1]][:] * self.weights[:] # dnorm_i
            # dNormNorm[arg[0]][arg[1]][:] = dNorm[arg[0]][arg[1]][:] * norm[arg[0]][arg[1]][:]

            # Sum over the appropriate axes for nabla_weights and nabla_bias
        @map_sum_simple(self.n_threads, batch_shape, sfix, self.X.sizes[-1])
        def _(*arg):
            sel = self.nabla_Y
            for ar in arg:
                sel = sel[ar]
            return sel[:]
        self.nabla_bias.assign(_())

        @map_sum_simple(self.n_threads, batch_shape, sfix, self.X.sizes[-1])
        def _(*arg):
            sel = nYdf
            for ar in arg:
                sel = sel[ar]
            return sel[:]
        self.nabla_weights.assign(_())

        if compute_nabla_X:
            # sum_dNorm = sfix.Array(self.X.sizes[-1])
            # sum_dNormNorm = sfix.Array(self.X.sizes[-1])
            #
            # @map_sum_simple(self.n_threads, batch_shape, sfix, self.X.sizes[-1])
            # def _(*arg):
            #     sel = dNormNorm
            #     for ar in arg:
            #         sel = sel[ar]
            #     return sel[:]
            # sum_dNormNorm.assign(_())

            # print_ln("sum norm %s", sum_dNorm[:].reveal())
            # print_ln("sum norm norm %s", sum_dNormNorm[:].reveal())
            # print_ln("norm %s", norm[:].reveal()[:8]) # corr
            # print_ln("dnorm %s", dNorm[:].reveal()[:8])

            # Compute final gradient wrt input X
            @for_range_opt_multithread(self.n_threads, batch_shape)
            def _(*arg):

                if len(arg) == 2:
                    mean_dnorm = sum(dNorm[arg[0]][arg[1]]) / self.X.sizes[-1]

                    self.nabla_X[arg[0]][arg[1]][:] = (dNorm[arg[0]][arg[1]][:] - mean_dnorm) * factor[arg[0]][arg[1]]
                    mean_dnormnorm = sum(self.nabla_X[arg[0]][arg[1]][:] * norm[arg[0]][arg[1]]) / self.X.sizes[-1]
                    self.nabla_X[arg[0]][arg[1]][:] -= norm[arg[0]][arg[1]] * mean_dnormnorm

                else:
                    raise NotImplementedError("Only 3D tensors supported")
                # sel_nX[:] = sel_dnorm[:] - sum_dNorm - sel_norm[:] * sum_dNormNorm
                # print_ln("layernorm result compute_x %s", sel_nX[:].reveal())

class QuantBase(object):
    bias_before_reduction = True

    @staticmethod
    def new_squant():
        class _(squant):
            @classmethod
            def get_params_from(cls, player):
                cls.set_params(sfloat.get_input_from(player),
                               sint.get_input_from(player))
            @classmethod
            def get_input_from(cls, player, size=None):
                return cls._new(sint.get_input_from(player, size=size))
        return _

    def const_div(self, acc, n):
        logn = int(math.log(n, 2))
        acc = (acc + n // 2)
        if 2 ** logn == n:
            acc = acc.round(self.output_squant.params.k + logn, logn, nearest=True)
        else:
            acc = acc.int_div(sint(n), self.output_squant.params.k + logn)
        return acc

class FixBase:
    bias_before_reduction = False

    class my_squant(sfix):
        params = None

    @classmethod
    def new_squant(cls):
        return cls.my_squant

    def input_params_from(self, player):
        pass

    def const_div(self, acc, n):
        return (sfix._new(acc) * self.output_squant(1 / n)).v

class BaseLayer(Layer):
    def __init__(self, input_shape, output_shape, inputs=None):
        self.input_shape = input_shape
        self.output_shape = output_shape

        self.input_squant = self.new_squant()
        self.output_squant = self.new_squant()

        self.X = Tensor(input_shape, self.input_squant)
        self.Y = Tensor(output_shape, self.output_squant)

        back_shapes = list(input_shape), list(output_shape)
        for x in back_shapes:
            x[0] = min(x[0], self.back_batch_size)

        self.nabla_X = Tensor(back_shapes[0], self.input_squant)
        self.nabla_Y = Tensor(back_shapes[1], self.output_squant)
        self.inputs = inputs

    def temp_shape(self):
        return [0]

    @property
    def N(self):
        return self.input_shape[0]

class ConvBase(BaseLayer):
    fewer_rounds = True
    use_conv2ds = True
    temp_weights = None
    temp_inputs = None
    def thetas(self):
        if self.use_bias:
            return self.weights, self.bias
        else:
            return tuple([self.weights])
    def nablas(self):
        if self.use_bias:
            return self.nabla_weights, self.nabla_bias
        else:
            return tuple([self.nabla_weights])

    @classmethod
    def init_temp(cls, layers):
        size = 0
        for layer in layers:
            size = max(size, reduce(operator.mul, layer.temp_shape()))
        cls.temp_weights = sfix.Array(size)
        cls.temp_inputs = sfix.Array(size)

    def __init__(self, input_shape, weight_shape, bias_shape, output_shape, stride,
                 padding='SAME', tf_weight_format=False, inputs=None,
                 weight_type=None, bias=True):
        super(ConvBase, self).__init__(input_shape, output_shape, inputs=inputs)

        self.weight_shape = weight_shape
        self.bias_shape = bias_shape
        self.stride = stride
        self.tf_weight_format = tf_weight_format
        self.use_bias = bias
        if padding == 'SAME':
            # https://web.archive.org/web/20171223022012/https://www.tensorflow.org/api_guides/python/nn
            self.padding = []
            for i in 1, 2:
                s = stride[i - 1]
                assert output_shape[i] >= input_shape[i] // s
                if tf_weight_format:
                    w = weight_shape[i - 1]
                else:
                    w = weight_shape[i]
                if (input_shape[i] % stride[1] == 0):
                    pad_total = max(w - s, 0)
                else:
                    pad_total = max(w - (input_shape[i] % s), 0)
                self.padding.append(pad_total // 2)
        elif padding == 'VALID':
            self.padding = [0, 0]
        elif isinstance(padding, int):
            self.padding = [padding, padding]
        else:
            self.padding = padding

        if weight_type:
            self.weight_squant = weight_type
        else:
            self.weight_squant = self.new_squant()

        self.bias_squant = self.new_squant()

        self.weights = Tensor(weight_shape, self.weight_squant)
        if self.use_bias:
            self.bias = Array(output_shape[-1], self.bias_squant)

        self.nabla_weights = Tensor(weight_shape, self.weight_squant)
        if self.use_bias:
            self.nabla_bias = Array(output_shape[-1], self.bias_squant)

        self.unreduced = Tensor(self.output_shape, sint, address=self.Y.address)

        if tf_weight_format:
            weight_in = weight_shape[2]
        else:
            weight_in = weight_shape[3]
        assert(weight_in == input_shape[-1])
        assert(bias_shape[0] == output_shape[-1])
        assert(len(bias_shape) == 1)
        assert(len(input_shape) == 4)
        assert(len(output_shape) == 4)
        assert(len(weight_shape) == 4)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, padding=%s, tf_weight_format=%s)' % \
            (type(self).__name__, self.X.sizes, self.weight_shape,
             self.bias_shape, self.Y.sizes, self.stride, repr(self.padding),
             self.tf_weight_format)

    def input_from(self, player, **kwargs):
        self.input_params_from(player)
        self.weights.input_from(player, budget=100000, **kwargs)
        if self.input_bias:
            self.bias.input_from(player, **kwargs)

    def output_weights(self):
        self.weights.print_reveal_nested()
        if self.use_bias:
            print_ln('%s', self.bias.reveal_nested())

    def reveal_parameters_to_binary(self):
        assert not self.tf_weight_format
        n_filters = self.weights.shape[0]
        n_channels = self.weights.shape[3]
        @for_range(n_filters)
        def _(i):
            @for_range(n_channels)
            def _(j):
                part = self.weights.get_vector_by_indices(i, None, None, j)
                part.reveal().binary_output()
        if self.use_bias:
            self.bias.reveal_to_binary_output()

    def dot_product(self, iv, wv, out_y, out_x, out_c):
        if self.use_bias:
            bias = self.bias[out_c]
            acc = self.output_squant.unreduced_dot_product(iv, wv)
            acc.v += bias.v
            acc.res_params = self.output_squant.params
            #self.Y[0][out_y][out_x][out_c] = acc.reduce_after_mul()
            self.unreduced[0][out_y][out_x][out_c] = acc.v
        else:
            acc = self.output_squant.unreduced_dot_product(iv, wv)
            acc.res_params = self.output_squant.params
            self.unreduced[0][out_y][out_x][out_c] = acc.v

    def reduction(self, batch_length=1):
        unreduced = self.unreduced
        n_summands = self.n_summands()
        #start_timer(2)
        n_outputs = batch_length * reduce(operator.mul, self.output_shape[1:])
        @multithread(self.n_threads, n_outputs, max_size=program.budget)
        def _(base, n_per_thread):
            res = self.input_squant().unreduced(
                sint.load_mem(unreduced.address + base,
                              size=n_per_thread),
                self.weight_squant(),
                self.output_squant.params,
                n_summands).reduce_after_mul()
            res.store_in_mem(self.Y.address + base)
        #stop_timer(2)

    def temp_shape(self):
        return list(self.output_shape[1:]) + [self.n_summands()]

    def prepare_temp(self):
        shape = self.temp_shape()
        inputs = MultiArray(shape, self.input_squant,
                            address=self.temp_inputs)
        weights = MultiArray(shape, self.weight_squant,
                             address=self.temp_weights)
        return inputs, weights

class Conv2d(ConvBase):
    def n_summands(self):
        _, weights_h, weights_w, _ = self.weight_shape
        _, inputs_h, inputs_w, n_channels_in = self.input_shape
        return weights_h * weights_w * n_channels_in

    def _forward(self, batch):
        if not issubclass(self.weights.value_type, _single) \
           or not issubclass(self.X.value_type, _single):
            raise CompilerError(
                'convolution inputs have to be sfix in arithmetic circuits')

        if self.tf_weight_format:
            assert(self.weight_shape[3] == self.output_shape[-1])
            weights_h, weights_w, _, _ = self.weight_shape
        else:
            assert(self.weight_shape[0] == self.output_shape[-1])
            _, weights_h, weights_w, _ = self.weight_shape
        _, inputs_h, inputs_w, n_channels_in = self.input_shape
        _, output_h, output_w, n_channels_out = self.output_shape

        stride_h, stride_w = self.stride
        padding_h, padding_w = self.padding

        if self.use_conv2ds:
            part_size = 1
            @for_range_opt_multithread(self.n_threads,
                                       [len(batch), n_channels_out])
            def _(i, j):
                inputs = self.X.get_slice_vector(
                    batch.get_part(i * part_size, part_size))
                if self.tf_weight_format:
                    weights = self.weights.get_vector_by_indices(None, None, None, j)
                else:
                    weights = self.weights.get_part_vector(j)
                inputs = inputs.pre_mul()
                weights = weights.pre_mul()
                res = sint(size = output_h * output_w * part_size)
                conv2ds(res, inputs, weights, output_h, output_w,
                        inputs_h, inputs_w, weights_h, weights_w,
                        stride_h, stride_w, n_channels_in, padding_h, padding_w,
                        part_size)
                if self.use_bias:
                    if self.bias_before_reduction:
                        res += self.bias.expand_to_vector(j, res.size).v
                    else:
                        res += self.bias.expand_to_vector(j, res.size).v << \
                            self.weight_squant.f
                addresses = regint.inc(res.size,
                                       self.unreduced[i * part_size].address + j,
                                       n_channels_out)
                res.store_in_mem(addresses)
            self.reduction(len(batch))
            if self.debug_output:
                print_ln('%s weights %s', self, self.weights.reveal_nested())
                if self.use_bias:
                    print_ln('%s bias %s', self, self.bias.reveal_nested())
                @for_range(len(batch))
                def _(i):
                    print_ln('%s X %s %s', self, i, self.X[batch[i]].reveal_nested())
                    print_ln('%s Y %s %s', self, i, self.Y[i].reveal_nested())
            return
        else:
            assert len(batch) == 1
            if self.fewer_rounds:
                inputs, weights = self.prepare_temp()

        @for_range_opt_multithread(self.n_threads,
                                   [output_h, output_w, n_channels_out])
        def _(out_y, out_x, out_c):
                    in_x_origin = (out_x * stride_w) - padding_w
                    in_y_origin = (out_y * stride_h) - padding_h
                    iv = []
                    wv = []
                    for filter_y in range(weights_h):
                        in_y = in_y_origin + filter_y
                        inside_y = (0 <= in_y) * (in_y < inputs_h)
                        for filter_x in range(weights_w):
                            in_x = in_x_origin + filter_x
                            inside_x = (0 <= in_x) * (in_x < inputs_w)
                            inside = inside_y * inside_x
                            if is_zero(inside):
                                continue
                            for in_c in range(n_channels_in):
                                iv += [self.X[0][in_y * inside_y]
                                       [in_x * inside_x][in_c]]
                                wv += [self.weights[out_c][filter_y][filter_x][in_c]]
                                wv[-1] *= inside
                    if self.fewer_rounds:
                        inputs[out_y][out_x][out_c].assign(iv)
                        weights[out_y][out_x][out_c].assign(wv)
                    else:
                        self.dot_product(iv, wv, out_y, out_x, out_c)

        if self.fewer_rounds:
            @for_range_opt_multithread(self.n_threads,
                                       list(self.output_shape[1:]))
            def _(out_y, out_x, out_c):
                self.dot_product(inputs[out_y][out_x][out_c],
                                 weights[out_y][out_x][out_c],
                                 out_y, out_x, out_c)

        self.reduction()

class QuantConvBase(QuantBase):
    def input_params_from(self, player):
        for s in self.input_squant, self.weight_squant, self.bias_squant, self.output_squant:
            s.get_params_from(player)
        print('WARNING: assuming that bias quantization parameters are correct')
        self.output_squant.params.precompute(self.input_squant.params, self.weight_squant.params)

class QuantConv2d(QuantConvBase, Conv2d):
    pass

class FixConv2d(Conv2d, FixBase):
    """ Fixed-point 2D convolution layer.

    :param input_shape: input shape (tuple/list of four int)
    :param weight_shape: weight shape (tuple/list of four int)
    :param bias_shape: bias shape (tuple/list of one int)
    :param output_shape: output shape (tuple/list of four int)
    :param stride: stride (tuple/list of two int)
    :param padding: :py:obj:`'SAME'` (default), :py:obj:`'VALID'`, or tuple/list of two int
    :param tf_weight_format: weight shape format is (height, width, input channels, output channels) instead of the default (output channels, height, width, input channels)
    """

    def reset(self):
        assert not self.tf_weight_format
        n_in = reduce(operator.mul, self.weight_shape[1:])
        r = math.sqrt(6.0 / (n_in + self.weight_shape[0]))
        print('Initializing convolution weights in [%f,%f]' % (-r, r))
        self.weights.randomize(-r, r, n_threads=self.n_threads)
        if self.use_bias:
            self.bias.assign_all(0)

    def backward(self, compute_nabla_X=True, batch=None):
        assert self.use_conv2ds

        assert not self.tf_weight_format
        _, weights_h, weights_w, _ = self.weight_shape
        _, inputs_h, inputs_w, n_channels_in = self.input_shape
        _, output_h, output_w, n_channels_out = self.output_shape

        stride_h, stride_w = self.stride
        padding_h, padding_w = self.padding

        N = len(batch)

        if self.use_bias:
            self.nabla_bias.assign_all(0)

            @for_range(N)
            def _(i):
                self.nabla_bias.assign_vector(
                    self.nabla_bias.get_vector() + sum(sum(
                        self.nabla_Y[i][j][k].get_vector() for k in range(output_w))
                                                       for j in range(output_h)))

        input_size = inputs_h * inputs_w * N
        batch_repeat = regint.Matrix(N, inputs_h * inputs_w)
        batch_repeat.assign_vector(batch.get(
            regint.inc(input_size, 0, 1, 1, N)) *
                                   reduce(operator.mul, self.input_shape[1:]))

        @for_range_opt_multithread(self.n_threads, [n_channels_in, n_channels_out])
        def _(i, j):
            a = regint.inc(input_size, self.X.address + i, n_channels_in, N,
                           inputs_h * inputs_w)
            inputs = sfix.load_mem(batch_repeat.get_vector() + a).pre_mul()
            b = regint.inc(N * output_w * output_h, self.nabla_Y.address + j, n_channels_out, N)
            rep_out = regint.inc(output_h * output_w * N, 0, 1, 1, N) * \
                reduce(operator.mul, self.output_shape[1:])
            nabla_outputs = sfix.load_mem(rep_out + b).pre_mul()
            res = sint(size = weights_h * weights_w)
            conv2ds(res, inputs, nabla_outputs, weights_h, weights_w, inputs_h,
                    inputs_w, output_h, output_w, -stride_h, -stride_w, N,
                    padding_h, padding_w, 1)
            reduced = unreduced_sfix._new(res).reduce_after_mul()
            self.nabla_weights.assign_vector_by_indices(reduced, j, None, None, i)

        if compute_nabla_X:
            assert tuple(self.stride) == (1, 1)
            reverse_weights = MultiArray(
                [n_channels_in, weights_h, weights_w, n_channels_out], sfix)
            @for_range_opt_multithread(self.n_threads, n_channels_in)
            def _(l):
                @for_range(weights_h)
                def _(j):
                    @for_range(weights_w)
                    def _(k):
                        addresses = regint.inc(n_channels_out,
                            self.weights[0][j][weights_w-k-1].get_address(l),
                            reduce(operator.mul, self.weights.sizes[1:]))
                        reverse_weights[l][weights_h-j-1][k].assign_vector(
                            self.weights.value_type.load_mem(addresses))
            padded_w = inputs_w + 2 * padding_w
            padded_h = inputs_h + 2 * padding_h
            if padding_h or padding_w:
                output = MultiArray(
                    [N, padded_h, padded_w, n_channels_in], sfix)
            else:
                output = self.nabla_X
            @for_range_opt_multithread(self.n_threads,
                                       [N, n_channels_in])
            def _(i, j):
                res = sint(size = (padded_w * padded_h))
                conv2ds(res, self.nabla_Y[i].get_vector().pre_mul(),
                        reverse_weights[j].get_vector().pre_mul(),
                        padded_h, padded_w, output_h, output_w,
                        weights_h, weights_w, 1, 1, n_channels_out,
                        weights_h - 1, weights_w - 1, 1)
                output.assign_vector_by_indices(
                    unreduced_sfix._new(res).reduce_after_mul(),
                    i, None, None, j)
            if padding_h or padding_w:
                @for_range_opt_multithread(self.n_threads, N)
                def _(i):
                    @for_range(inputs_h)
                    def _(j):
                        @for_range(inputs_w)
                        def _(k):
                            jj = j + padding_w
                            kk = k + padding_w
                            self.nabla_X[i][j][k].assign_vector(
                                output[i][jj][kk].get_vector())

        if self.debug_output:
            @for_range(len(batch))
            def _(i):
                print_ln('%s X %s %s', self, i, list(self.X[i].reveal_nested()))
                print_ln('%s nabla Y %s %s', self, i, list(self.nabla_Y[i].reveal_nested()))
                if compute_nabla_X:
                    print_ln('%s nabla X %s %s', self, i, self.nabla_X[batch[i]].reveal_nested())
            print_ln('%s nabla weights %s', self,
                     (self.nabla_weights.reveal_nested()))
            print_ln('%s weights %s', self, (self.weights.reveal_nested()))
            if self.use_bias:
                print_ln('%s nabla b %s', self, (self.nabla_bias.reveal_nested()))
                print_ln('%s bias %s', self, (self.bias.reveal_nested()))

class QuantDepthwiseConv2d(QuantConvBase, Conv2d):
    def n_summands(self):
        _, weights_h, weights_w, _ = self.weight_shape
        return weights_h * weights_w

    def _forward(self, batch):
        assert len(batch) == 1
        assert(self.weight_shape[-1] == self.output_shape[-1])
        assert(self.input_shape[-1] == self.output_shape[-1])

        _, weights_h, weights_w, _ = self.weight_shape
        _, inputs_h, inputs_w, n_channels_in = self.input_shape
        _, output_h, output_w, n_channels_out = self.output_shape

        stride_h, stride_w = self.stride
        padding_h, padding_w = self.padding

        depth_multiplier = 1

        if self.use_conv2ds:
            assert depth_multiplier == 1
            assert self.weight_shape[0] == 1
            @for_range_opt_multithread(self.n_threads, n_channels_in)
            def _(j):
                inputs = self.X.get_vector_by_indices(0, None, None, j)
                assert not self.tf_weight_format
                weights = self.weights.get_vector_by_indices(0, None, None,
                                                             j)
                inputs = inputs.pre_mul()
                weights = weights.pre_mul()
                res = sint(size = output_h * output_w)
                conv2ds(res, inputs, weights, output_h, output_w,
                        inputs_h, inputs_w, weights_h, weights_w,
                        stride_h, stride_w, 1, padding_h, padding_w, 1)
                res += self.bias.expand_to_vector(j, res.size).v
                self.unreduced.assign_vector_by_indices(res, 0, None, None, j)
            self.reduction()
            return
        else:
            if self.fewer_rounds:
                inputs, weights = self.prepare_temp()

        @for_range_opt_multithread(self.n_threads,
                                   [output_h, output_w, n_channels_in])
        def _(out_y, out_x, in_c):
                    for m in range(depth_multiplier):
                        oc = m + in_c * depth_multiplier
                        in_x_origin = (out_x * stride_w) - padding_w
                        in_y_origin = (out_y * stride_h) - padding_h
                        iv = []
                        wv = []
                        for filter_y in range(weights_h):
                            for filter_x in range(weights_w):
                                in_x = in_x_origin + filter_x
                                in_y = in_y_origin + filter_y
                                inside = (0 <= in_x) * (in_x < inputs_w) * \
                                         (0 <= in_y) * (in_y < inputs_h)
                                if is_zero(inside):
                                    continue
                                iv += [self.X[0][in_y][in_x][in_c]]
                                wv += [self.weights[0][filter_y][filter_x][oc]]
                                wv[-1] *= inside
                        if self.fewer_rounds:
                            inputs[out_y][out_x][oc].assign(iv)
                            weights[out_y][out_x][oc].assign(wv)
                        else:
                            self.dot_product(iv, wv, out_y, out_x, oc)

        if self.fewer_rounds:
            @for_range_opt_multithread(self.n_threads,
                                       list(self.output_shape[1:]))
            def _(out_y, out_x, out_c):
                self.dot_product(inputs[out_y][out_x][out_c],
                                 weights[out_y][out_x][out_c],
                                 out_y, out_x, out_c)

        self.reduction()

class AveragePool2d(BaseLayer):
    def __init__(self, input_shape, output_shape, filter_size, strides=(1, 1)):
        super(AveragePool2d, self).__init__(input_shape, output_shape)
        self.filter_size = filter_size
        self.strides = strides
        for i in (0, 1):
            if strides[i] == 1:
                assert output_shape[1+i] == 1
                assert filter_size[i] == input_shape[1+i]
            else:
                assert strides[i] == filter_size[i]
                assert output_shape[1+i] * strides[i] == input_shape[1+i]

    def input_from(self, player, raw=False):
        self.input_params_from(player)

    def _forward(self, batch=[0]):
        assert len(batch) == 1

        _, input_h, input_w, n_channels_in = self.input_shape
        _, output_h, output_w, n_channels_out = self.output_shape

        assert n_channels_in == n_channels_out

        padding_h, padding_w = (0, 0)
        stride_h, stride_w = self.strides
        filter_h, filter_w = self.filter_size
        n = filter_h * filter_w
        print('divisor: ', n)

        @for_range_opt_multithread(self.n_threads,
                                   [output_h, output_w, n_channels_in])
        def _(out_y, out_x, c):
            in_x_origin = (out_x * stride_w) - padding_w
            in_y_origin = (out_y * stride_h) - padding_h
            fxs = util.max(-in_x_origin, 0)
            #fxe = min(filter_w, input_w - in_x_origin)
            fys = util.max(-in_y_origin, 0)
            #fye = min(filter_h, input_h - in_y_origin)
            acc = 0
            #fc = 0
            for i in range(filter_h):
                filter_y = fys + i
                for j in range(filter_w):
                    filter_x = fxs + j
                    in_x = in_x_origin + filter_x
                    in_y = in_y_origin + filter_y
                    acc += self.X[0][in_y][in_x][c].v
                    #fc += 1
            acc = self.const_div(acc, n)
            self.Y[0][out_y][out_x][c] = self.output_squant._new(acc)

def easyConv2d(input_shape, batch_size, out_channels, kernel_size, stride=1,
               padding=0, bias=True, **kwargs):
    """ More convenient interface to :py:class:`FixConv2d`.

    :param input_shape: input shape (tuple/list of four int)
    :param out_channels: output channels (int)
    :param kernel_size: kernel size (int or tuple/list of two int)
    :param stride: stride (int or tuple/list of two int)
    :param padding: :py:obj:`'SAME'`, :py:obj:`'VALID'`, int, or tuple/list of two int
    :param bias: whether layer has bias (bool)

    """
    if isinstance(kernel_size, int):
        kernel_size = (kernel_size, kernel_size)
    if isinstance(stride, int):
        stride = (stride, stride)
    weight_shape = [out_channels] + list(kernel_size) +  [input_shape[-1]]
    output_shape = [batch_size] + list(
        apply_padding(input_shape[1:3], kernel_size, stride, padding)) + \
            [out_channels]
    padding = padding.upper() if isinstance(padding, str) \
        else padding
    return FixConv2d(input_shape, weight_shape, (out_channels,), output_shape,
                     stride, padding, bias=bias, **kwargs)

def easyMaxPool(input_shape, kernel_size, stride=None, padding=0):
    """ More convenient interface to :py:class:`MaxPool`.

    :param input_shape: input shape (tuple/list of four int)
    :param kernel_size: kernel size (int or tuple/list of two int)
    :param stride: stride (int or tuple/list of two int)
    :param padding: :py:obj:`'SAME'`, :py:obj:`'VALID'`, int,
      or tuple/list of two int

    """
    kernel_size, stride, padding = \
        _standardize_pool_options(kernel_size, stride, padding)
    return MaxPool(input_shape, [1] + list(stride) + [1],
                   [1] + list(kernel_size) + [1], padding)

def _standardize_pool_options(kernel_size, stride, padding):
    if isinstance(kernel_size, int):
        kernel_size = (kernel_size, kernel_size)
    if isinstance(stride, int):
        stride = (stride, stride)
    if stride == None:
        stride = kernel_size
    padding = padding.upper() if isinstance(padding, str) \
        else padding
    return kernel_size, stride, padding

class QuantAveragePool2d(QuantBase, AveragePool2d):
    def input_params_from(self, player):
        print('WARNING: assuming that input and output quantization parameters are the same')
        for s in self.input_squant, self.output_squant:
            s.get_params_from(player)

class FixAveragePool2d(PoolBase, FixBase):
    """ Fixed-point 2D AvgPool layer.

    :param input_shape: input shape (tuple/list of four int)
    :param output_shape: output shape (tuple/list of four int)
    :param filter_size: filter size (int or tuple/list of two int)
    :param strides: strides (int or tuple/list of two int)
    :param padding: :py:obj:`'SAME'`, :py:obj:`'VALID'`, int,
      or tuple/list of two int

   """
    def __init__(self, input_shape, output_shape, filter_size, strides=(1, 1),
                 padding=0):
        filter_size, strides, padding = \
            _standardize_pool_options(filter_size, strides, padding)
        PoolBase.__init__(self, input_shape, [1] + list(strides) + [1],
                          [1] + list(filter_size) + [1], padding)
        self.pool_size = reduce(operator.mul, filter_size)
        self.d_out = self.Y.shape[-1]
        if output_shape:
            assert self.Y.shape == list(output_shape)

    def _forward(self, batch):
        def process(pool, bi, k, i, j):
            self.Y[bi][i][j][k] = sum(x[0] for x in pool) * (1 / self.pool_size)
        self.traverse(batch, process)

    def backward(self, compute_nabla_X=True, batch=None):
        if compute_nabla_X:
            self.nabla_X.alloc()
            self.nabla_X.assign_all(0)
            break_point()
            def process(pool, bi, k, i, j):
                part = self.nabla_Y[bi][i][j][k] * (1 / self.pool_size)
                for x, h_in, w_in, h, w in pool:
                    hh = h * h_in
                    ww = w * w_in
                    res = h_in * w_in * part
                    get_program().protect_memory(True)
                    self.nabla_X[bi][hh][ww][k] += res
                    get_program().protect_memory(False)
        self.traverse(batch, process)

class QuantReshape(QuantBase, BaseLayer):
    def __init__(self, input_shape, _, output_shape):
        super(QuantReshape, self).__init__(input_shape, output_shape)

    def input_from(self, player):
        print('WARNING: assuming that input and output quantization parameters are the same')
        _ = self.new_squant()
        for s in self.input_squant, _, self.output_squant:
            s.set_params(sfloat.get_input_from(player), sint.get_input_from(player))
        for i in range(2):
            sint.get_input_from(player)

    def _forward(self, batch):
        assert len(batch) == 1
        # reshaping is implicit
        self.Y.assign(self.X)

class QuantSoftmax(QuantBase, BaseLayer):
    def input_from(self, player):
        print('WARNING: assuming that input and output quantization parameters are the same')
        for s in self.input_squant, self.output_squant:
            s.set_params(sfloat.get_input_from(player), sint.get_input_from(player))

    def _forward(self, batch):
        assert len(batch) == 1
        assert(len(self.input_shape) == 2)

        # just print the best
        def comp(left, right):
            c = left[1].v.greater_than(right[1].v, self.input_squant.params.k)
            #print_ln('comp %s %s %s', c.reveal(), left[1].v.reveal(), right[1].v.reveal())
            return [c.if_else(x, y) for x, y in zip(left, right)]
        print_ln('guess: %s', util.tree_reduce(comp, list(enumerate(self.X[0])))[0].reveal())

class BertBase(BaseLayer, FixBase):
    pass

# class BertEmbedding(BertBase): # we dont do embedding

class BertPooler(BertBase):

    thetas = lambda self: self.dense.thetas()
    nablas = lambda self: self.dense.nablas() # refer to downstream layers?

    def __init__(self, n_examples, seq_len, hidden_state):
        input_shape = [n_examples, seq_len, hidden_state]
        output_shape = [n_examples, hidden_state]
        super(BertPooler, self).__init__(input_shape, output_shape)
        self.dense = Dense(n_examples, hidden_state, hidden_state)
        self.activation = Tanh(output_shape)

        self.d_out = hidden_state


    def _forward(self, batch):
        # self.dense.X.address = self.X.address
        self.activation.X.address = self.dense.Y.address
        self.activation.Y.address = self.Y.address

        # grab the first repr?
        # batch contains [n_batch, n_heads, n_dim]
        @for_range(len(batch))
        def _(j):
            self.dense.X[j][:] = self.X[batch[j]][0][:]

        # if self.debug_output:
        #     print_ln("forward layer pooler.dense X %s", self.dense.X.reveal_nested())

        self.dense.forward(batch)
        # print_ln("LINEAR Layer weights after bertpooler.dense: %s", self.opt.layers[-2].W.reveal_nested())

        self.activation._forward(batch)
        # print_ln("LINEAR Layer weights after bertpooler.activation: %s", self.opt.layers[-2].W.reveal_nested())

    def reset(self):
        self.dense.reset()
        self.activation.reset()

    def load_state_dict(self, state_dict, input_via):
        import numpy
        self.dense.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['dense.weight'], 0, 1))
        self.dense.b = sfix.input_tensor_via(input_via, state_dict['dense.bias'])

    def backward(self, compute_nabla_X=True, batch=None):
        if batch is None:
            batch = regint.Array(self.N)
            batch.assign(regint.inc(self.N))

        self.activation.nabla_X.alloc()

        self.activation.nabla_Y.address = self.nabla_Y.address
        self.dense.nabla_Y.address = self.activation.nabla_X.address
        self.dense.nabla_X.address = self.nabla_X.address # TODO: size mismatch here, but should be okay? cause rest 0s?

        self.activation.backward(batch)
        self.dense.backward(compute_nabla_X, batch)

class BertEncoder(BertBase):

    # I think this is unused?

    def __init__(self, n_examples, n_layers, d_model, n_heads, d_k, d_v, d_ff, dropout=0.1):
        input_shape = [n_examples, d_model]
        output_shape = [n_examples, d_model]
        super(BertEncoder, self).__init__(input_shape, output_shape)
        self.layers = []
        for _ in range(n_layers):
            self.layers.append(BertLayer(n_examples, d_model, n_heads, d_k, d_v, d_ff, dropout))

        for i in enumerate(1, len(self.layers)):
            self.layers[i].X.address = self.layers[i - 1].Y.address

        self.layers[0].X.address = self.X.address
        self.layers[-1].Y.address = self.Y.address

    def _forward(self, batch):
        for layer in self.layers:
            layer.forward(batch)

    def reset(self):
        for layer in self.layers:
            layer.reset()


class BertLayer(BertBase):

    thetas = lambda self: self.multi_head_attention.thetas() + self.intermediate.thetas() + self.output.thetas() #+ tuple(self.nabla_hidden_state)
    nablas = lambda self: self.multi_head_attention.nablas() + self.intermediate.nablas() + self.output.nablas() #+ tuple(self.nabla_hidden_state)

    def __init__(self, n_examples, seq_len, hidden_state, intermediate_size, num_attention_heads, layernorm_eps, dropout=0.1, rsqrt_approx=True, batch_size=None):
        input_shape = [n_examples, seq_len, hidden_state]
        output_shape = [n_examples, seq_len, hidden_state] # TODO: we could make this batch_size
        super(BertLayer, self).__init__(input_shape, output_shape)

        internal_shape = batch_size if batch_size is not None else n_examples
        self.multi_head_attention = MultiHeadAttention(internal_shape, seq_len, hidden_state, num_attention_heads, dropout, layernorm_eps, rsqrt_approx)
        self.intermediate = BertIntermediate(internal_shape, hidden_state, intermediate_size, seq_len)
        self.output = BertOutput(internal_shape, intermediate_size, hidden_state, seq_len, dropout, layernorm_eps, rsqrt_approx)

        self.hidden_state = sfix.Tensor(input_shape) # TODO: Could also make this smaller
        # self.nabla_hidden_state = sfix.Tensor(input_shape)
        # self.nabla_hidden_state.alloc()

        # self.X.address = self.multi_head_attention.X.address
        # self.Y.address = self.output.Y.address

        self.d_out = hidden_state

        print("Init BertLayer", input_shape, output_shape)

    def forward(self, batch, training=False):
        if batch is None:
            batch = Array.create_from(regint(0))

        self.multi_head_attention._X.address = self.X.address
        self.output.Y.address = self.Y.address
        self.hidden_state.address = self.X.address
        # self.multi_head_attention.Y.address = self.Y.address

        self.multi_head_attention.forward(batch, self.hidden_state, training)
        # if self.debug_output:
            # print_ln("our layer X %s %s", self.X[0][0][0].reveal(), self.output.X[0][0][0].reveal())

        if self.debug_output:
            print_ln("forward layer multi_head_attention %s %s", self.multi_head_attention.Y[0][1][0].reveal(), sum(sum(self.multi_head_attention.Y[0].reveal())))
            # print_ln("forward layer multi_head_attention full %s", self.multi_head_attention.Y.reveal())

        print("Forward Attention")

        batch_inc = regint.Array(len(batch))
        batch_inc.assign(regint.inc(len(batch)))
        self.intermediate.X.address = self.multi_head_attention.Y.address
        self.intermediate.forward(batch_inc)

        if self.debug_output:
            print_ln("forward layer intermediate %s %s %s", self.intermediate.Y.shape, self.intermediate.Y[0][1][0:20].reveal(), sum(sum(self.intermediate.Y[0].reveal())))

            print_ln(" ")

        self.output.X.address = self.intermediate.Y.address
        self.output.forward(batch_inc, self.multi_head_attention.Y, training)
        # self.output.Y.address = self.output.X.address

        if self.debug_output:
            print_ln("our output %s %s %s %s", self.Y.address, len(self.Y[0].reveal()), self.Y[0][0][0:20].reveal(), sum(sum(self.Y[0].reveal())))
            # print_ln("our output %s %s %s %s", self.Y.address, len(self.Y[0].reveal()), self.Y[0][0][0:20].reveal(), sum(sum(self.Y[0].reveal())))
            # print_ln("our output %s %s %s %s", self.Y.address, len(self.Y[0].reveal()), self.Y[0][0][0:20].reveal(), sum(sum(self.Y[0].reveal())))

            print_ln("our layer output %s %s %s %s", self.output.Y.address, len(self.Y[0].reveal()), self.output.Y[0][0][0:20].reveal(), sum(sum(self.output.Y[0].reveal())))
            # print_ln("shapes %s %s", self.Y.sizes, self.output.Y.sizes)
            # print_ln("types %s %s %s %s %s %s", self.Y.value_type, self.output.Y.value_type, type(self.Y), type(self.output.Y), self, self.output)

        print("Forward BertLayer")

    def reset(self):
        self.multi_head_attention.reset()
        self.intermediate.reset()
        self.output.reset()

    def load_state_dict(self, state_dict, input_via):
        import numpy
        # format of state_dict
        # ['attention.self.query.weight', 'attention.self.query.bias', 'attention.self.key.weight', 'attention.self.key.bias', 'attention.self.value.weight', 'attention.self.value.bias', 'attention.output.dense.weight', 'attention.output.dense.bias', 'attention.output.LayerNorm.weight', 'attention.output.LayerNorm.bias', 'intermediate.dense.weight', 'intermediate.dense.bias', 'output.dense.weight', 'output.dense.bias', 'output.LayerNorm.weight', 'output.LayerNorm.bias']
        # set the values of the layers
        self.multi_head_attention.wq.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['attention.self.query.weight'], 0, 1))
        self.multi_head_attention.wq.b = sfix.input_tensor_via(input_via, state_dict['attention.self.query.bias'])
        self.multi_head_attention.wk.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['attention.self.key.weight'], 0, 1))
        self.multi_head_attention.wk.b = sfix.input_tensor_via(input_via, state_dict['attention.self.key.bias'])
        self.multi_head_attention.wv.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['attention.self.value.weight'], 0, 1))
        self.multi_head_attention.wv.b = sfix.input_tensor_via(input_via, state_dict['attention.self.value.bias'])

        self.multi_head_attention.output.dense.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['attention.output.dense.weight'], 0, 1))
        self.multi_head_attention.output.dense.b = sfix.input_tensor_via(input_via, state_dict['attention.output.dense.bias'])
        self.multi_head_attention.output.layer_norm.weights = sfix.input_tensor_via(input_via, state_dict['attention.output.LayerNorm.weight'])
        self.multi_head_attention.output.layer_norm.bias = sfix.input_tensor_via(input_via, state_dict['attention.output.LayerNorm.bias'])

        self.intermediate.dense.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['intermediate.dense.weight'], 0, 1))
        self.intermediate.dense.b = sfix.input_tensor_via(input_via, state_dict['intermediate.dense.bias'])

        self.output.dense.W = sfix.input_tensor_via(input_via, numpy.swapaxes(state_dict['output.dense.weight'], 0, 1))
        # print_ln("output.dense.W state_dict %s", self.output.dense.W[0][0].reveal())
        self.output.dense.b = sfix.input_tensor_via(input_via, state_dict['output.dense.bias'])
        self.output.layer_norm.weights = sfix.input_tensor_via(input_via, state_dict['output.LayerNorm.weight'])
        self.output.layer_norm.bias = sfix.input_tensor_via(input_via, state_dict['output.LayerNorm.bias'])

    def backward(self, compute_nabla_X=True, batch=None):
        # layer.inputs[0].nabla_Y.address = \
        #     layer.nabla_X.address
        # assign nabla_X and Y
        self.multi_head_attention.nabla_X.alloc()
        self.intermediate.nabla_X.alloc()
        self.output.nabla_X.alloc()

        self.output.nabla_Y.address = self.nabla_Y.address
        self.intermediate.nabla_Y.address = self.output.nabla_X.address
        self.multi_head_attention.nabla_Y.address = self.intermediate.nabla_X.address
        # self.multi_head_attention.nabla_X.address = self.nabla_X.address

        nabla_y_multi_head_attention_from_layernorm = self.output.backward(True, batch)
        # print_ln("Backward BertLayer.output.nabla_X %s", self.output.nabla_X.reveal_nested()[:8])
        self.intermediate.backward(True, batch)

        # residual, add it to Y because it gave the output of multihadattention to output
        @multithread(self.n_threads, len(batch))
        def _(base, size):
            self.multi_head_attention.nabla_Y.assign_part_vector(
                self.multi_head_attention.nabla_Y.get_part_vector(base, size) +
                nabla_y_multi_head_attention_from_layernorm.get_part_vector(base, size), base)

        if compute_nabla_X:
            self.multi_head_attention.nabla_X.address = self.nabla_X.address

        nabla_y_hidden_state = self.multi_head_attention.backward(compute_nabla_X, batch)

        if compute_nabla_X:
            print_ln("Bertlayer nabla_x %s %s", nabla_y_hidden_state.get_vector().reveal()[-8:], self.nabla_X.get_vector().reveal()[-8:])
            # and add hidden_state back to nabla_X, add to x because we gave x to multi_head_attention
            @multithread(self.n_threads, len(batch))
            def _(base, size):
                self.nabla_X.assign_part_vector(
                    self.nabla_X.get_part_vector(base, size) +
                    nabla_y_hidden_state.get_part_vector(base, size), base)


class BertIntermediate(BertBase):

    thetas = lambda self: self.dense.thetas()
    nablas = lambda self: self.dense.nablas()

    def __init__(self, n_examples, hidden_size, intermediate_size, seq_len):
        input_shape = [n_examples, seq_len, hidden_size]
        output_shape = [n_examples, seq_len, intermediate_size]
        super(BertIntermediate, self).__init__(input_shape, output_shape)
        self.dense = Dense(n_examples, hidden_size, intermediate_size, seq_len)
        self.activation = Gelu([n_examples, seq_len, intermediate_size])


    def forward(self, batch=None, training=None):
        self.dense.X.address = self.X.address
        self.activation.X.address = self.dense.Y.address
        self.activation.Y.address = self.Y.address

        self.dense.forward(batch)
        if self.debug_output:
            print_ln("forward layer intermediate.dense %s", self.dense.Y[0][0][0:20].reveal())

        self.activation._forward(batch)

    def reset(self):
        self.dense.reset()

    def backward(self, compute_nabla_X=True, batch=None):
        self.activation.nabla_X.alloc()

        # print_ln("Backward BertIntermediate.nabla_X %s", self.nabla_X.reveal_nested()[:8])

        self.activation.nabla_Y.address = self.nabla_Y.address
        self.dense.nabla_Y.address = self.activation.nabla_X.address
        self.dense.nabla_X.address = self.nabla_X.address

        self.activation.backward(batch)
        self.dense.backward(compute_nabla_X, batch)


class BertOutput(BertBase):

    thetas = lambda self: self.dense.thetas() + self.layer_norm.thetas()
    nablas = lambda self: self.dense.nablas() + self.layer_norm.nablas()

    def __init__(self, n_examples, intermediate_size, hidden_size, seq_len, dropout=0.1, layernorm_eps=1e-12, rsqrt_approx=True):
        input_shape = [n_examples, seq_len, intermediate_size]
        output_shape = [n_examples, seq_len, hidden_size]
        self.input_shape = input_shape
        print("INSTANTIATING BERTOUTPUT with ", input_shape, output_shape, intermediate_size, hidden_size, rsqrt_approx)
        super(BertOutput, self).__init__(input_shape, output_shape)
        self.dense = Dense(n_examples, intermediate_size, hidden_size, seq_len)
        self.layer_norm = LayerNorm(output_shape, layernorm_eps=layernorm_eps, approx=rsqrt_approx)
        self.dropout = Dropout([n_examples, seq_len, hidden_size], alpha=dropout)


    def forward(self, batch, input_tensor, training=False, input_tensor_batch=None):
        # Because input_tensor might be the full training data shape
        self.dense.X.address = self.X.address
        self.dropout.X.address = self.dense.Y.address
        self.layer_norm.X.address = self.dropout.Y.address
        self.layer_norm.Y.address = self.Y.address

        self.dense.forward(batch)
        if self.debug_output:
            print_ln("forward layer output.dense %s", self.dense.Y[0][0][0:20].reveal())

        self.dropout.forward(batch, training)

        if input_tensor_batch is not None:
            input_tensor_batch_arr = MultiArray([len(batch), input_tensor.sizes[1], input_tensor.sizes[2]], sfix)
            input_tensor_batch_arr.assign_vector(input_tensor.get_slice_vector(input_tensor_batch))
            @multithread(self.n_threads, len(batch))
            def _(base, size):
                self.layer_norm.X.assign_part_vector(
                    self.layer_norm.X.get_part_vector(base, size) +
                    input_tensor_batch_arr.get_part_vector(base, size), base)
        else:
            @multithread(self.n_threads, len(batch))
            def _(base, size):
                self.layer_norm.X.assign_part_vector(
                    self.layer_norm.X.get_part_vector(base, size) +
                    input_tensor.get_part_vector(base, size), base)
        # if self.debug_output:
        #     print_ln("input tensor %s", input_tensor.reveal())

        # self.layer_norm.X[:] += input_tensor[:] # TODO: is it maybe this addition since we take the last value? would be strange

        if self.debug_output:
            print_ln("forward layer layer_norm_add %s", self.layer_norm.X[0][0][0:20].reveal())
            print_ln("")
        self.layer_norm.forward(batch)



    def reset(self):
        self.dense.reset()

    def backward(self, compute_nabla_X=True, batch=None):
        self.layer_norm.nabla_X.alloc()
        self.dropout.nabla_X.alloc()

        self.layer_norm.nabla_Y.address = self.nabla_Y.address
        self.dropout.nabla_Y.address = self.layer_norm.nabla_X.address
        self.dense.nabla_Y.address= self.dropout.nabla_X.address
        self.dense.nabla_X.address = self.nabla_X.address

        # layer norm flows back to dropout but also to hidden_tensor... nabla hidden state?

        self.layer_norm.backward(batch, compute_nabla_X)
        self.dropout.backward(compute_nabla_X, batch)

        if self.debug_output:
            print_ln("backward layer dense x %s", self.dropout.nabla_X[0][0][0:20].reveal())

        self.dense.backward(compute_nabla_X, batch)

        return self.layer_norm.nabla_X

class MultiHeadAttention(BertBase):

    thetas = lambda self: self.wq.thetas() + self.wk.thetas() + self.wv.thetas() + self.output.thetas()
    nablas = lambda self: self.wq.nablas() + self.wk.nablas() + self.wv.nablas() + self.output.nablas()

    def __init__(self, n_examples, seq_len, hidden_size, num_attention_heads, dropout=0.1, layernorm_eps=1e-12, rsqrt_approx=True, batch_size=None):

        # In the first layer the internal_shape is different from n_examples, afterwards it is the same
        internal_shape = batch_size if batch_size is not None else n_examples
        self.n_examples = internal_shape

        input_shape = [n_examples, seq_len, hidden_size]
        output_shape = [internal_shape, seq_len, hidden_size]
        super().__init__(input_shape, output_shape)

        print("Multheadattention", rsqrt_approx, input_shape, output_shape)
        self.num_attention_heads = num_attention_heads
        self.attention_head_size = int(hidden_size / num_attention_heads)
        self.all_head_size = self.num_attention_heads * self.attention_head_size
        self.hidden_size = hidden_size
        self.seq_len = seq_len

        self.hidden_size = hidden_size
        self.wq = Dense(n_examples, hidden_size, self.all_head_size, self.seq_len)
        self.wk = Dense(n_examples, hidden_size, self.all_head_size, self.seq_len)
        self.wv = Dense(n_examples, hidden_size, self.all_head_size, self.seq_len)
        self.dropout = Dropout([internal_shape, self.num_attention_heads, self.seq_len, self.seq_len], alpha=dropout) # I think? # TODO: DROPOUT?

        self.output = BertOutput(internal_shape, hidden_size, hidden_size, seq_len, dropout, layernorm_eps, rsqrt_approx)
        self.context = sfix.Tensor([internal_shape, self.seq_len, hidden_size])
        self.nabla_context = sfix.Tensor([internal_shape, self.seq_len, hidden_size])

        # self.context_nabla

        self.attention_scores = MultiArray([internal_shape, self.num_attention_heads, self.seq_len, self.seq_len], sfix)
        self.nabla_attention_scores = MultiArray([internal_shape, self.num_attention_heads, self.seq_len, self.seq_len], sfix)
        self.nabla_preattention_scores = MultiArray([internal_shape, self.num_attention_heads, self.seq_len, self.seq_len], sfix)

    def forward(self, batch=None, hidden_state=None, training=None):
        N = len(batch)

        # set up layers
        dense_layers = [self.wq, self.wk, self.wv]
        for layer in dense_layers:
            layer.X.address = self.X.address

        self.output.X.address = self.context.address
        self.output.Y.address = self.Y.address

        self.wq.forward(batch)
        self.wk.forward(batch)
        self.wv.forward(batch)

        inc_batch = regint.Array(N)
        inc_batch.assign(regint.inc(N))

        if self.debug_output:
            # print_ln('forward layer wq full %s', self.wq.X.reveal())
            print_ln('forward layer wv %s %s', self.wv.Y[0][0][0:10].reveal(), sum(self.wv.Y[0][0].reveal()))
            print_ln('forward layer hidden_state %s', hidden_state[0][1][0:10].reveal())
            # print_ln('forward layer wv full %s', self.wv.Y.reveal())

        # max_size = program.budget // self.attention_head_size
        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads])
        def _(i, j):
        # for j in range(self.num_attention_heads):
            query_sub = sfix.Matrix(self.seq_len, self.attention_head_size) # this is mem inefficient?
            key_sub = sfix.Matrix(self.seq_len, self.attention_head_size)
            # print(self.wq.Y.shape, "wk Y shape", i, self.attention_head_size, j, self.wq.Y[i], self.wq.Y[i][:])

            @for_range_opt(self.seq_len)
            def _(k):
            # for k in range(self.seq_len):
                query_sub[k] = self.wq.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)
                key_sub[k] = self.wk.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)

            # print_ln("query_sub %s %s", i, j)
            res = query_sub.direct_mul_trans(key_sub)
            self.attention_scores[i].assign_part_vector(res, j)

        if self.debug_output:
            print_ln('forward layer attention_scores %s', self.attention_scores[0][0].reveal())
            # print_ln('forward layer attention_scores full %s', self.attention_scores.reveal())

        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads, self.seq_len])
        def _(i, j, k):
            self.attention_scores[i][j][k][:] = self.attention_scores[i][j][k][:] / math.sqrt(self.attention_head_size)
            self.attention_scores[i][j][k][:] = softmax(self.attention_scores[i][j][k][:])

        self.dropout.X.address = self.attention_scores.address
        self.dropout.forward(batch=inc_batch, training=training)

        if self.debug_output:
            print_ln('forward layer dropout full %s', self.dropout.Y.reveal())

        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads])
        def _(i, j):
            value_sub = sfix.Matrix(self.seq_len, self.attention_head_size)

            @for_range_opt([self.seq_len])
            def _(k):
                value_sub[k] = self.wv.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)
                # value_sub[k] = self.wv.Y[i][k][j * self.attention_head_size:(j + 1) * self.attention_head_size]

            res = sfix.Matrix(self.seq_len, self.attention_head_size)
            res.assign_vector(self.dropout.Y[i][j].direct_mul(value_sub))
            # res = self.dropout.Y[i][j].direct_mul(value_sub)

            @for_range_opt([self.seq_len])
            def _(k):
                self.context[i][k].assign_part_vector(res[k],
                    j * self.attention_head_size
                )
            # for k in range(self.seq_len):
            #     self.context[i][k][j * self.attention_head_size:(j + 1) * self.attention_head_size] = res[k * self.attention_head_size:(k + 1) * self.attention_head_size]

            # How to transfer to forward?

        # missing half of the values ?
        # print_ln('forward layer old_context %s', self.old_context[0].get_vector().reveal())
        if self.debug_output:
            print_ln('forward layer multiheadattention before internal output %s', self.context[0][0][0:20].get_vector().reveal())

        if self.debug_output:
            print_ln('forward layer hidden_state %s', hidden_state[0][1][0:20].reveal())

        self.output.forward(inc_batch, hidden_state, training, batch)
        if self.debug_output:
            print_ln('forward multiheadattention output %s', self.output.Y[0][0][0:20].reveal())
            print_ln("")

    # return context

    def reset(self):
        self.wq.reset()
        self.wk.reset()
        self.wv.reset()
        self.output.reset()

    def backward(self, compute_nabla_X=True, batch=None):
        N = len(batch)
        dense_layers = [self.wq, self.wk, self.wv]
        for layer in dense_layers:
            layer.nabla_Y.alloc() # we will fill them manually below
            layer.nabla_X.alloc() # we have to add them up layer

        self.output.nabla_Y.address = self.nabla_Y.address

        self.output.nabla_X.alloc()
        self.nabla_context.address = self.output.nabla_X.address

        self.nabla_attention_scores.address = self.dropout.nabla_X

        nabla_y_hidden_state = self.output.backward(True, batch)

        if self.debug_output:
            print_ln("backward layer attention output.nabla_Y %s", self.output.nabla_Y.reveal_nested()[0][0][:8])
            print_ln("backward layer attention output.nabla_X %s", self.output.nabla_X.reveal_nested()[0][0][:8])

        # Backprop context
        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads])
        def _(i, j):
            res = sfix.Matrix(self.seq_len, self.attention_head_size)
            value_sub = sfix.Matrix(self.seq_len, self.attention_head_size)

            @for_range_opt([self.seq_len])
            def _(k):
                # dout_bth
                res[k].assign_vector(self.nabla_context[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)) # nabla_Y
                # value_t2
                value_sub[k] = self.wv.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)

            nabla_value_sub = sfix.Matrix(self.seq_len, self.attention_head_size)

            # dvalue_t2 = dout_bth * att_bth
            nabla_value_sub.assign_vector(self.dropout.Y[i][j].direct_trans_mul(res))
            # nabla_value_sub.assign_vector(self.context[i][j].direct_trans_mul(res))

            # datt_bth = dout_bth * value_t2
            self.dropout.nabla_Y[i][j].assign_vector(res.direct_mul_trans(value_sub))

            @for_range_opt([self.seq_len])
            def _(k):
                # value_sub[k] = self.wv.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)
                self.wv.nabla_Y[i][k].assign_part_vector(
                    nabla_value_sub[k],
                j * self.attention_head_size)

            print("RES MULTI BACK", self.dropout.Y, res, self.num_attention_heads, self.attention_head_size)

        self.dropout.nabla_X.alloc()
        self.dropout.backward(True, batch)

        if self.debug_output:
            # Dropout nabla y is correct
            # wv nabla_Y also correct
            print_ln("backward layer attention dropout.nabla_Y %s", self.dropout.nabla_Y.reveal_nested()[:8])
            print_ln("backward layer attention wv.nabla_Y %s", self.wv.nabla_Y.reveal_nested()[:8])

        # attention to pre
        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads, self.seq_len])
        def _(i, j, k):
            @for_range_opt([self.seq_len, self.seq_len])
            def _(t1, t2):
                indicator = cfix(t1 == t2)
                # local_deriv = self.attention_scores[i][j][k][t1] * (indicator - self.attention_scores[i][j][k][t2])
                local_deriv = self.dropout.Y[i][j][k][t1] * (indicator - self.dropout.Y[i][j][k][t2])

                # print_ln("indiciator %s %s %s %s %s %s", t1, t2, indicator, local_deriv.reveal(), self.dropout.Y[i][j][k][t1].reveal(), self.attention_scores[i][j][k][t2].reveal())
                self.nabla_preattention_scores[i][j][k][t2] += local_deriv * self.dropout.nabla_X[i][j][k][t1] # x or y?

        print_ln("attention_scores %s", self.attention_scores.reveal())
        print_ln("nabla preattention scores %s", self.nabla_preattention_scores.reveal())

        scale = 1 / math.sqrt(self.attention_head_size)
        # backward pass 1
        @for_range_opt_multithread(self.n_threads, [N, self.num_attention_heads])
        def _(i, j):
            # for j in range(self.num_attention_heads):
            query_sub = sfix.Matrix(self.seq_len, self.attention_head_size)
            key_sub = sfix.Matrix(self.seq_len, self.attention_head_size)
            # print(self.wq.Y.shape, "wk Y shape", i, self.attention_head_size, j, self.wq.Y[i], self.wq.Y[i][:])
            @for_range_opt(self.seq_len)
            def _(k): # This mempcopy is ugly
                query_sub[k] = self.wq.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)
                key_sub[k] = self.wk.Y[i][k].get_part_vector(j * self.attention_head_size, self.attention_head_size)

            # nabla_query_sub = key_sub.direct_trans_mul(self.nabla_preattention_scores[i][j])
            # nabla_key_sub = self.nabla_preattention_scores[i][j].direct_mul_trans(key_sub)

            print_ln("preatt %s", self.nabla_preattention_scores[i][j].reveal())

            nabla_query_sub = sfix.Matrix(self.seq_len, self.attention_head_size)
            nabla_key_sub_trans = sfix.Matrix(self.attention_head_size, self.seq_len)
            nabla_query_sub.assign_vector(self.nabla_preattention_scores[i][j].direct_trans_mul(key_sub) * scale)
            nabla_key_sub_trans.assign_vector(query_sub.direct_trans_mul(self.nabla_preattention_scores[i][j]) * scale)
            nabla_key_sub = nabla_key_sub_trans.transpose()

            print_ln("nabla query sub %s", nabla_query_sub.reveal())
            print_ln("nabla key sub %s", nabla_key_sub.reveal())

            # nabla_key_sub is seq_len_seqlen, copy back into wk which is seq_len, all_head_size
            @for_range_opt(self.seq_len)
            def _(k): # This mempcopy is ugly?
                self.wq.nabla_Y[i][k].assign_part_vector(nabla_query_sub[k], j * self.attention_head_size)
                self.wk.nabla_Y[i][k].assign_part_vector(nabla_key_sub[k], j * self.attention_head_size)

        if self.debug_output:
            print_ln("backward layer attention wq.nabla_Y %s", self.wq.nabla_Y.reveal_nested()[:8])

            # wk slightly off
            print_ln("backward layer attention wk.nabla_Y %s", self.wk.nabla_Y.reveal_nested()[:8])

        self.wq.backward(compute_nabla_X, batch)
        self.wk.backward(compute_nabla_X, batch)
        self.wv.backward(compute_nabla_X, batch)

        @multithread(self.n_threads, len(batch))
        def _(base, size):
            sum_layers = sum([layer.nabla_X.get_part_vector(base, size) for layer in dense_layers])
            self.nabla_X.assign_part_vector(
                sum_layers, base)

        if self.debug_output:
            # TODO: Wq seems off still
            print_ln("backward layer attention wq.nabla_X %s", self.wq.nabla_X.reveal_nested()[:8])

        return nabla_y_hidden_state

class Optimizer:
    """ Base class for graphs of layers. """
    n_threads = Layer.n_threads
    always_shuffle = True
    shuffle = True
    time_layers = False
    revealing_correctness = False
    early_division = False
    output_diff = False
    output_grad = False
    output_stats = False
    print_accuracy = True
    time_training = True

    @staticmethod
    def from_args(program, layers):
        if 'adam' in program.args or 'adamapprox' in program.args:
            res = Adam(layers, 1, approx='adamapprox' in program.args)
        elif 'amsgrad' in program.args:
            res = Adam(layers, approx=True, amsgrad=True)
        elif 'amsgradprec' in program.args:
            res = Adam(layers, approx=False, amsgrad=True)
        elif 'quotient' in program.args:
            res = Adam(layers, approx=True, amsgrad=True, normalize=True)
        else:
            res = SGD(layers, 1)
        res.early_division = 'early_div' in program.args
        res.output_diff = 'output_diff' in program.args
        res.output_grad = 'output_grad' in program.args
        res.output_stats = 'output_stats' in program.args
        return res

    def __init__(self, layers=[], report_loss=None, time_layers=False,
                 program=None):
        if get_program().options.binary:
            raise CompilerError(
                'machine learning code not compatible with binary circuits')
        self.tol = 0.000
        self.report_loss = report_loss
        self.X_by_label = None
        self.print_update_average = False
        self.print_random_update = False
        self.print_losses = False
        self.print_loss_reduction = False
        self.i_epoch = MemValue(0)
        self.stopped_on_loss = MemValue(0)
        self.stopped_on_low_loss = MemValue(0)
        self.layers = layers
        self.time_layers = time_layers
        if program:
            self.time_layers |= 'time_layers' in program.args
        if self.time_layers:
            for i, layer in enumerate(layers):
                print('Timer %d: %s' % (100 + i, repr(layer)))
        get_program().reading('deep learning', 'KS22')

    @property
    def layers(self):
        """ Get all layers. """
        return self._layers

    @layers.setter
    def layers(self, layers):
        """ Construct linear graph from list of layers. """
        self._layers = layers
        self.thetas = []
        prev = None
        for layer in layers:
            if not layer.inputs and prev is not None:
                layer.inputs = [prev]
            prev = layer
            self.thetas.extend(layer.thetas())

    def set_layers_with_inputs(self, layers):
        """ Construct graph from :py:obj:`inputs` members of list of layers. """
        self._layers = layers
        used = set([None])
        for layer in reversed(layers):
            inputs = layer.inputs or []
            layer.last_used = list(filter(lambda x: x not in used, inputs))
            used.update(inputs)

    def set_learning_rate(self, lr):
        print('Setting learning rate to', lr)
        self.gamma = MemValue(cfix(lr))

    def reset(self):
        """ Initialize weights. """
        for layer in self.layers:
            layer.reset()
        self.i_epoch.write(0)
        self.stopped_on_loss.write(0)

    def batch_for(self, layer, batch):
        if layer in (self.layers[0], self.layers[-1]):
            assert not isinstance(layer, BatchNorm)
            return batch
        else:
            batch = regint.Array(len(batch))
            batch.assign(regint.inc(len(batch)))
            return batch

    @_no_mem_warnings
    def forward(self, N=None, batch=None, keep_intermediate=True,
                model_from=None, training=False, run_last=True,
                delete_params=False):
        """ Compute graph.

        :param N: batch size (used if batch not given)
        :param batch: indices for computation (:py:class:`~Compiler.types.Array` or list)
        :param keep_intermediate: do not free memory of intermediate results after use
        """
        if batch is None:
            batch = regint.Array(N)
            batch.assign(regint.inc(N))
        for i, layer in enumerate(self.layers):
            if layer.inputs and len(layer.inputs) == 1 and layer.inputs[0] is not None:
                layer._X.address = layer.inputs[0].Y.address
            layer.Y.alloc()
            if model_from is not None:
                layer.input_from(model_from)
            break_point('pre-forward-layer-%d' % i)
            if self.time_layers:
                start_timer(100 + i)
            if i != len(self.layers) - 1 or run_last:
                for theta in layer.thetas():
                    theta.alloc()
                layer.forward(batch=self.batch_for(layer, batch),
                              training=training)
                if self.print_random_update:
                    print_ln('forward layer %s', layer)
                    l = min(100, layer.Y[i].total_size())
                    i = regint.get_random(64) % len(batch)
                    if l < 100:
                        j = 0
                    else:
                        j = regint.get_random(64) % \
                            (layer.Y[i].total_size() - l)
                    print_ln('forward layer %s at (%s, %s): %s', layer, i, j,
                             layer.Y[i].to_array().get_vector(j, l).reveal())
                    i = regint.get_random(64) % layer.Y[0].total_size()
                    print_ln('forward layer %s vertical at %s: %s', layer, i,
                             [layer.Y[j].to_array()[i].reveal()
                              for j in range(len(batch))])
            if self.time_layers:
                stop_timer(100 + i)
            break_point('post-forward-layer-%d' % i)
            if not keep_intermediate:
                for l in layer.last_used:
                    l.Y.delete()
            if delete_params:
                for theta in layer.thetas():
                    theta.delete()

    @_no_mem_warnings
    def eval(self, data, batch_size=None, top=False):
        """ Compute evaluation after training.

        :param data: sample data (:py:class:`Compiler.types.Matrix` with one row per sample)
        :param top: return top prediction instead of probability distribution
        :returns: sfix/sint Array (depening on :py:obj:`top`)

        """
        MultiArray.disable_index_checks()
        Array.check_indices = False
        if isinstance(self.layers[-1].Y, Array) or top:
            if top:
                res = sint.Array(len(data))
            else:
                res = sfix.Array(len(data))
        else:
            res = sfix.Matrix(len(data), self.layers[-1].d_out)
        self.set_layers_with_inputs(self.layers)
        def f(start, batch_size, batch):
            batch.assign_vector(regint.inc(batch_size, start))
            self.forward(batch=batch, run_last=False, keep_intermediate=False)
            part = self.layers[-1].eval(batch_size, top=top)
            res.assign_part_vector(part.get_vector(), start)
            if self.output_stats:
                for layer in self.layers[:-1]:
                    print_ln(layer)
                    self.stat(' Y', layer.Y)
        self.run_in_batches(f, data, batch_size or len(self.layers[1]._X))
        return res

    @_no_mem_warnings
    def backward(self, batch):
        """ Compute backward propagation. """
        for i, layer in reversed(list(enumerate(self.layers))):
            assert len(batch) <= layer.back_batch_size
            if self.time_layers:
                start_timer(200 + i)
            if not layer.inputs:
                layer.backward(compute_nabla_X=False,
                               batch=self.batch_for(layer, batch))
            else:
                if len(layer.inputs) == 1:
                    layer.nabla_X.alloc()
                layer.backward(batch=self.batch_for(layer, batch))
                if len(layer.inputs) == 1:
                    layer.inputs[0].nabla_Y.address = \
                        layer.nabla_X.address
                    if i == len(self.layers) - 1 and self.early_division:
                        layer.nabla_X.assign_vector(
                            layer.nabla_X.get_vector() / len(batch))
            if self.time_layers:
                stop_timer(200 + i)

    @classmethod
    def stat(cls, name, tensor):
        zero, neg, small = (cint.Array(cls.n_threads) for i in range(3))
        s, mx, mn = (cfix.Array(cls.n_threads) for i in range(3))
        for x in zero, neg, small, s, mx, mn:
            x.assign_all(0)
        total = tensor.total_size()
        @multithread(cls.n_threads, total)
        def _(base, size):
            tn = get_thread_number() - 1
            tmp = Array.create_from(
                tensor.get_vector(base, size).reveal())
            @for_range_opt(size, budget=1000)
            def _(i):
                zero[tn] += tmp[i] == 0
                neg[tn] += tmp[i] < 0
                small[tn] += abs(tmp[i]) < 2 ** (-tmp[i].f / 2)
                s[tn] += tmp[i]
                mx[tn] = util.max(mx[tn], tmp[i])
                mn[tn] = util.min(mn[tn], tmp[i])
            tmp.delete()
        print_str(
            ' %s 0:%s/%s, <0:%s/%s, >0:%s/%s, ~0:%s/%s sum:%s max:%s min:%s ',
            name, sum(zero), total, sum(neg), total,
            total - sum(zero) - sum(neg), total,
            sum(small) - sum(zero), total, sum(s), util.max(mx), util.min(mn))
        if len(tensor.shape) == 4:
            corners = sum(([tensor[0][i][j][0] for j in (0, -1)]
                           for i in (0, -1)), [])
        elif len(tensor.shape) == 1:
            x = tensor.to_array()
            corners = [x[i] for i in (0, len(x) // 2 - 1, -1)]
        else:
            x = tensor[0].to_array()
            corners = [x[i] for i in (0, len(x) // 2 - 1, -1)]
        print_ln('corners:%s shape:%s', util.reveal(corners), tensor.shape)

    def update(self, i_epoch, i_batch, batch):
        if self.output_grad:
            @if_(i_batch % 100 == 0)
            def _():
                for layer in self.layers[:-1]:
                    cfix(10000).binary_output()
                    break_point()
                    layer.nabla_Y.get_vector(size=2000).reveal().binary_output()
                    break_point()
                    for theta, nabla in zip(layer.thetas(), layer.nablas()):
                        cfix(5000).binary_output()
                        break_point()
                        nabla.get_vector().reveal().binary_output()
                        break_point()
        if self.output_stats:
            old_params = []
            @if_((i_batch % self.output_stats == 0).bit_or(i_epoch == 0))
            def _():
                for i, layer in enumerate(self.layers[:-1]):
                    print_ln(layer)
                    if layer == self.layers[0]:
                        x = Array.create_from(layer.X.get_slice_vector(batch))
                        self.stat(' 0 X', x)
                    else:
                        self.stat(' %d X' % i, layer.X)
                    self.stat(' %d Y' % i, layer.Y)
                    self.stat(' %d nabla_Y' % i, layer.nabla_Y)
                    for nabla in layer.nablas():
                        self.stat(' %d grad' % i, nabla)
                    for theta in layer.thetas():
                        self.stat(' %d param' % i, theta)
                        if theta.total_size() < 1000:
                            old_params.append(theta.get_vector())
        if self.time_layers:
            start_timer(1000)
        self._update(i_epoch, MemValue(i_batch), batch)
        if self.time_layers:
            stop_timer(1000)
        if self.output_stats:
            @if_(i_batch % self.output_stats == 0)
            def _():
                for i, layer in enumerate(self.layers[:-1]):
                    for theta in layer.thetas():
                        if theta.total_size() < 1000:
                            print_ln(layer)
                            self.stat(' %d diff' % i, Array.create_from(
                                theta.get_vector() - old_params[0]))
                            del old_params[0]

    @_no_mem_warnings
    def run(self, batch_size=None, stop_on_loss=0):
        """ Run training.

        :param batch_size: batch size (defaults to example size of first layer)
        :param stop_on_loss: stop when loss falls below this (default: 0)
        """
        if self.n_epochs == 0:
            return
        if batch_size is not None:
            N = batch_size
        else:
            N = self.layers[0].N
        i = self.i_epoch
        n_iterations = MemValue(0)
        self.n_correct = MemValue(0)
        @for_range(self.n_epochs)
        def _(_):
            if self.X_by_label is None:
                self.X_by_label = [[None] * self.layers[0].N]
            assert len(self.X_by_label) in (1, 2)
            assert N % len(self.X_by_label) == 0
            n = N // len(self.X_by_label)
            n_per_epoch = int(math.ceil(1. * max(len(X) for X in
                                                 self.X_by_label) / n))
            print('%d runs per epoch' % n_per_epoch)
            indices_by_label = []
            for label, X in enumerate(self.X_by_label):
                indices = regint.Array(n * n_per_epoch)
                indices_by_label.append(indices)
                indices.assign(regint.inc(len(X)))
                missing = len(indices) - len(X)
                if missing:
                    indices.assign_vector(
                        regint.get_random(int(math.log2(len(X))), size=missing),
                        base=len(X))
                if self.shuffle and (self.always_shuffle or n_per_epoch > 1):
                    indices.shuffle()
            loss_sum = MemValue(sfix(0))
            self.n_correct.write(0)
            @for_range(n_per_epoch)
            def _(j):
                n_iterations.iadd(1)
                batch = regint.Array(N)
                for label, X in enumerate(self.X_by_label):
                    indices = indices_by_label[label]
                    batch.assign(indices.get_vector(j * n, n) +
                                 regint(label * len(self.X_by_label[0]), size=n),
                                 label * n)
                self.forward(batch=batch, training=True)
                self.backward(batch=batch)
                self.update(i, j, batch=batch)
                loss_sum.iadd(self.layers[-1].l)
                if self.print_loss_reduction:
                    before = self.layers[-1].average_loss(N)
                    self.forward(batch=batch)
                    after = self.layers[-1].average_loss(N)
                    print_ln('loss reduction in batch %s: %s (%s - %s)', j,
                             before - after, before, after)
                elif self.print_losses:
                    print_str('\rloss in batch %s: %s/%s', j,
                             self.layers[-1].average_loss(N),
                             loss_sum.reveal() / (j + 1))
                if self.revealing_correctness:
                    part_truth = self.layers[-1].Y.same_shape()
                    part_truth.assign_vector(
                        self.layers[-1].Y.get_slice_vector(batch))
                    self.n_correct.iadd(
                        self.layers[-1].reveal_correctness(batch_size, part_truth))
                if stop_on_loss:
                    loss = self.layers[-1].average_loss(N)
                    res = (loss < stop_on_loss) * (loss >= -1)
                    self.stopped_on_loss.write(1 - res)
                    print_ln_if(
                        self.stopped_on_loss,
                        'aborting epoch because loss is outside range: %s',
                        loss)
                    return res
            if self.print_losses:
                print_ln()
            self.missing_newline = False
            if self.report_loss and self.layers[-1].compute_loss and self.layers[-1].approx != 5:
                print_ln('loss in epoch %s: %s', i,
                         (loss_sum.reveal() * cfix(1 / n_per_epoch)))
            else:
                print_str('done with epoch %s', i)
                if self.time_training or self.print_losses:
                    print_ln()
                else:
                    print_str('\r')
                    self.missing_newline = True
            if self.time_training:
                time()
            i.iadd(1)
            res = True
            if self.tol > 0:
                res *= (1 - (loss_sum >= 0) * \
                        (loss_sum < self.tol * n_per_epoch)).reveal()
            self.stopped_on_low_loss.write(1 - res)
            return res

    def reveal_correctness(self, data, truth, batch_size=128, running=False):
        """ Test correctness by revealing results.

        :param data: test sample data
        :param truth: test labels
        :param batch_size: batch size
        :param running: output after every batch

        """
        N = data.sizes[0]
        n_correct = MemValue(0)
        loss = MemValue(sfix(0))
        def f(start, batch_size, batch):
            batch.assign_vector(regint.inc(batch_size, start))
            self.forward(batch=batch, run_last=False)
            part_truth = truth.get_part(start, batch_size)
            n_correct.iadd(
                self.layers[-1].reveal_correctness(batch_size, part_truth))
            loss.iadd(self.layers[-1].l * batch_size)
            if running:
                total = start + batch_size
                print_str('\rpart acc: %s (%s/%s) ',
                          cfix(n_correct, k=63, f=31) / total, n_correct, total)
        self.run_in_batches(f, data, batch_size, truth)
        if running:
            print_ln()
        loss = loss.reveal()
        if cfix.f < 31:
            loss = cfix._new(loss.v << (31 - cfix.f), k=63, f=31)
        return n_correct, loss / N

    def run_in_batches(self, f, data, batch_size, truth=None):
        batch_size = min(batch_size, data.sizes[0])
        training_data = self.layers[0]._X.array._address
        training_truth = self.layers[-1].Y.address
        self.layers[0]._X.address = data.address
        if truth:
            self.layers[-1].Y.address = truth.address
        N = data.sizes[0]
        batch = regint.Array(batch_size)
        @for_range(N // batch_size)
        def _(i):
            start = i * batch_size
            f(start, batch_size, batch)
        batch_size = N % batch_size
        if batch_size:
            start = N - batch_size
            f(start, batch_size, regint.Array(batch_size))
        self.layers[0].X.address = training_data
        self.layers[-1].Y.address = training_truth

    @_no_mem_warnings
    def run_by_args(self, program, n_runs, batch_size, test_X, test_Y,
                    acc_batch_size=None, reset=True):
        MultiArray.disable_index_checks()
        Array.check_indices = False
        if acc_batch_size is None:
            acc_batch_size = batch_size
        depreciation = None
        if program is None:
            class A:
                pass
            program = A()
            program.args = []
        for arg in program.args:
            m = re.match('rate(.*)', arg)
            if m:
                self.set_learning_rate(float(m.group(1)))
            m = re.match('dep(.*)', arg)
            if m:
                depreciation = float(m.group(1))
        if 'nomom' in program.args:
            self.momentum = 0
        self.print_losses |= 'print_losses' in program.args
        self.print_random_update = 'print_random_update' in program.args
        Layer.print_random_update = self.print_random_update
        self.time_layers = 'time_layers' in program.args
        self.revealing_correctness &= not 'no_acc' in program.args
        self.layers[-1].compute_loss = not 'no_loss' in program.args
        if 'full_cisc' in program.args:
            program.options.keep_cisc = 'FPDiv,exp2_fx,log2_fx'
        model_input = 'model_input' in program.args
        acc_first = model_input and not 'train_first' in program.args
        self.output_stats = 'output_stats' in program.args
        small_bench = 'bench10' in program.args or 'bench1' in program.args
        if model_input:
            for layer in self.layers:
                layer.input_from(0)
        elif reset and not 'no_reset' in program.args and not small_bench:
            self.reset()
        else:
            for layer in self.layers:
                for theta in layer.thetas():
                    theta.alloc()
        if 'one_iter' in program.args:
            print_float_prec(16)
            self.output_weights()
            print_ln('loss')
            self.eval(
                self.layers[0].X.get_part(0, batch_size),
                batch_size=batch_size).print_reveal_nested()
            for layer in self.layers:
                layer.X.get_part(0, batch_size).print_reveal_nested()
            print_ln('%s', self.layers[-1].Y.get_part(0, batch_size).reveal_nested())
            batch = Array.create_from(regint.inc(batch_size))
            self.forward(batch=batch, training=True)
            self.backward(batch=batch)
            self.update(0, batch=batch)
            print_ln('loss %s', self.layers[-1].l.reveal())
            self.output_weights()
            return
        if small_bench:
            n = 1 if 'bench1' in program.args else 10
            print('benchmarking %s iterations' % n)
            # force allocatoin
            self.layers[0].X, self.layers[-1].Y
            @for_range(n)
            def _(i):
                batch = Array.create_from(regint.inc(batch_size))
                self.forward(batch=batch, training=True)
                self.backward(batch=batch)
                self.update(0, batch=batch, i_batch=0)
            return
        @for_range(n_runs)
        def _(i):
            if not acc_first:
                if self.time_training:
                    start_timer(1)
                self.run(batch_size,
                         stop_on_loss=0 if 'no_loss' in program.args or
                         'no_stop_on_loss' else 100)
                if self.time_training:
                    stop_timer(1)
            if 'no_acc' in program.args:
                return
            N = self.layers[0].X.sizes[0]
            n_trained = (N + batch_size - 1) // batch_size * batch_size
            if not acc_first and self.print_accuracy and \
               self.revealing_correctness:
                print_ln('train_acc: %s (%s/%s)',
                         cfix(self.n_correct, k=63, f=31) / n_trained,
                         self.n_correct, n_trained)
            if test_X and test_Y:
                print('use test set')
                n_test = len(test_Y)
                n_correct, loss = self.reveal_correctness(
                    test_X, test_Y, acc_batch_size,
                    running='part_acc' in program.args)
                print_ln('test loss: %s', loss)
                if self.print_accuracy:
                    print_ln('acc: %s (%s/%s)',
                             cfix(n_correct, k=63, f=31) / n_test,
                             n_correct, n_test)
            if acc_first:
                if self.time_training:
                    start_timer(1)
                self.run(batch_size)
                if self.time_training:
                    stop_timer(1)
            else:
                @if_(util.or_op(self.stopped_on_loss, (n_correct <
                                int(n_test // self.layers[-1].n_outputs * 1.2))
                                    if test_X and test_Y else 0))
                def _():
                    self.gamma.imul(.5)
                    if 'crash' in program.args:
                        @if_(self.gamma == 0)
                        def _():
                            runtime_error('diverging')
                    self.reset()
                    print_ln('reset after reducing learning rate to %s',
                             self.gamma)
            if depreciation:
                self.gamma.imul(depreciation)
                print_ln('reducing learning rate to %s', self.gamma)
            print_ln_if(self.stopped_on_low_loss,
                        'aborting run because of low loss')
            return 1 - self.stopped_on_low_loss
        if self.missing_newline:
            print_ln('')
        if 'model_output' in program.args:
            self.output_weights()

    def fit(self, X, Y, epochs=1, batch_size=128, validation_data=(None, None),
            program=None, reset=True, print_accuracy=False, print_loss=False,
            sample_mask=None):
        """ Train model.

        :param X: training sample data (sfix tensor)
        :param Y: training labels (sint/sfix tensor)
        :param epochs: number of epochs (int)
        :param batch_size: batch size (int)
        :param validation_data: tuple of test sample data and labels for
          accuracy testing (optional; reveals labels)
        :param program: :py:class:`~Compile.program.Program` instance to use
          command-line parameters (optional)
        :param reset: whether to initialize model
        :param print_accuracy: print accuracy on training data (reveals labels)
        :param print_loss: reveal and print training loss after every batch
        :param sample_mask: 0/1 vector or Array to mask samples (experimental,
          only for 0/1 labels, 0 means ignore sample)

        """
        self.layers[0].X = X
        self.layers[-1].Y = Y
        if sample_mask:
            self.layers[-1].set_sample_mask(sample_mask)
        self.revealing_correctness = print_accuracy
        self.print_losses = print_loss
        self.time_training = False
        self.run_by_args(program, epochs, batch_size, *validation_data,
                         reset=reset)

    def output_weights(self):
        print_float_precision(max(6, sfix.f // 3))
        for layer in self.layers:
            layer.output_weights()

    def summary(self):
        sizes = [var.total_size() for var in self.thetas]
        print(sizes)
        print('Trainable params:', sum(sizes))

    @property
    def trainable_variables(self):
        """ List of all trainable variables. """
        return list(self.thetas)

    def reveal_model_to_binary(self):
        """ Reveal model and store it in the binary output file, see
        :ref:`reveal-model` for details. """
        input_shape = self.layers[0]._X.shape
        for layer in self.layers:
            if len(input_shape) == 4 and isinstance(layer, DenseBase):
                layer.reveal_parameters_to_binary(reshape=input_shape[1:])
            else:
                layer.reveal_parameters_to_binary()
            input_shape = layer._Y.shape

class Adam(Optimizer):
    """ Adam/AMSgrad optimizer.

    :param layers: layers of linear graph
    :param approx: use approximation for inverse square root (bool)
    :param amsgrad: use AMSgrad (bool)
    """
    def __init__(self, layers, n_epochs=1, approx=False, amsgrad=False,
                 normalize=False):
        super(Adam, self).__init__()
        self.set_learning_rate(.001)
        self.beta1 = 0.9
        self.beta2 = 0.999
        self.beta1_power = MemValue(cfix(1))
        self.beta2_power = MemValue(cfix(1))
        self.epsilon = max(2 ** -((sfix.k - sfix.f - 8) / (1 + approx)), 10 ** -8)
        self.n_epochs = n_epochs
        self.approx = approx
        self.amsgrad = amsgrad
        self.normalize = normalize
        if amsgrad:
            print_both('Using AMSgrad ', end='')
        else:
            print_both('Using Adam ', end='')
        if approx:
            print_both('with inverse square root approximation')
        else:
            print_both('with more precise inverse square root')
        if normalize:
            print_both('Normalize gradient')

        self.layers = layers
        self.ms = []
        self.vs = []
        self.gs = []
        self.vhats = []
        for layer in layers:
            for nabla in layer.nablas():
                self.gs.append(nabla)
                for x in self.ms, self.vs:
                    x.append(nabla.same_shape())
                if amsgrad:
                    self.vhats.append(nabla.same_shape())

    def _update(self, i_epoch, i_batch, batch):
        self.beta1_power *= self.beta1
        self.beta2_power *= self.beta2
        m_factor = MemValue(1 / (1 - self.beta1_power))
        v_factor = MemValue(1 / (1 - self.beta2_power))
        for i_layer, (m, v, g, theta) in enumerate(zip(self.ms, self.vs,
                                                       self.gs, self.thetas)):
            if self.normalize:
                abs_g = g.same_shape()
                @multithread(self.n_threads, g.total_size())
                def _(base, size):
                    abs_g.assign_vector(abs(g.get_vector(base, size)), base)
                max_g = tree_reduce_multithread(self.n_threads,
                                                util.max, abs_g.get_vector())
                scale = MemValue(sfix._new(library.AppRcr(
                    max_g.v, max_g.k, max_g.f, simplex_flag=True)))
            @multithread(self.n_threads, m.total_size(),
                         max_size=get_program().budget)
            def _(base, size):
                m_part = m.get_vector(base, size)
                v_part = v.get_vector(base, size)
                g_part = g.get_vector(base, size)
                if self.normalize:
                    g_part *= scale.expand_to_vector(size)
                m_part = self.beta1 * m_part + (1 - self.beta1) * g_part
                v_part = self.beta2 * v_part + (1 - self.beta2) * g_part ** 2
                m.assign_vector(m_part, base)
                v.assign_vector(v_part, base)
                mhat = m_part * m_factor.expand_to_vector(size)
                vhat = v_part * v_factor.expand_to_vector(size)
                if self.amsgrad:
                    v_max = self.vhats [i_layer].get_vector(base, size)
                    vhat = util.max(vhat, v_max)
                    self.vhats[i_layer].assign_vector(vhat, base)
                diff = self.gamma.expand_to_vector(size) * mhat
                if self.approx:
                    diff *= mpc_math.InvertSqrt(vhat + self.epsilon ** 2)
                else:
                    diff /= mpc_math.sqrt(vhat) + self.epsilon
                theta.assign_vector(theta.get_vector(base, size) - diff, base)
                if self.output_diff:
                    @if_(i_batch % 100 == 0)
                    def _():
                        diff.reveal().binary_output()
            if self.output_stats and m.total_size() < 1000:
                @if_(i_batch % self.output_stats == 0)
                def _():
                    self.stat('g', g)
                    self.stat('m', m)
                    self.stat('v', v)
                    self.stat('vhat', self.vhats[i_layer])
                    self.stat('theta', theta)

class SGD(Optimizer):
    """ Stochastic gradient descent.

    :param layers: layers of linear graph
    :param n_epochs: number of epochs for training
    :param report_loss: disclose and print loss
    """
    def __init__(self, layers, n_epochs=1, debug=False, report_loss=None):
        super(SGD, self).__init__(report_loss=report_loss)
        self.momentum = 0.9
        self.layers = layers
        self.n_epochs = n_epochs
        self.nablas = []
        self.momentum_values = []
        self.delta_thetas = []
        for layer in layers:
            self.nablas.extend(layer.nablas())
            for theta in layer.thetas():
                self.momentum_values.append(theta.same_shape())
                self.delta_thetas.append(theta.same_shape())
        self.set_learning_rate(0.01)
        self.debug = debug
        print_both('Using SGD')

    @_no_mem_warnings
    def reset(self, X_by_label=None):
        """ Reset layer parameters.

        :param X_by_label: if given, set training data by public labels for balancing
        """
        self.X_by_label = X_by_label
        if X_by_label is not None:
            for label, X in enumerate(X_by_label):
                @for_range_multithread(self.n_threads, 1, len(X))
                def _(i):
                    j = i + label * len(X_by_label[0])
                    self.layers[0].X[j] = X[i]
                    self.layers[-1].Y[j] = label
        for y in self.momentum_values:
            y.assign_all(0)
        for y in self.delta_thetas:
            y.assign_all(0)
        super(SGD, self).reset()

    def _update(self, i_epoch, i_batch, batch):
        for nabla, theta, momentum_value, delta_theta in zip(self.nablas, self.thetas,
                                             self.momentum_values, self.delta_thetas):
            @multithread(self.n_threads, nabla.total_size())
            def _(base, size):
                old = momentum_value.get_vector(base, size)
                red_old = self.momentum * old
                rate = self.gamma.expand_to_vector(size)
                nabla_vector = nabla.get_vector(base, size)
                log_batch_size = math.log(len(batch), 2)
                # divide by len(batch) by truncation
                # increased rate if len(batch) is not a power of two
                diff = red_old - nabla_vector
                # assuming rate is already synchronized
                pre_trunc = diff.v.mul(rate.v, sync=False)
                momentum_value.assign_vector(diff, base)
                k = max(nabla_vector.k, rate.k) + rate.f
                m = rate.f + int(log_batch_size)
                if self.early_division:
                    v = pre_trunc
                else:
                    v = pre_trunc.round(k, m, signed=True,
                                        nearest=sfix.round_nearest)
                new = nabla_vector._new(v)
                delta_theta.assign_vector(new, base)
                theta.assign_vector(theta.get_vector(base, size) +
                                    delta_theta.get_vector(base, size), base)
            if self.print_update_average:
                vec = abs(delta_theta.get_vector().reveal())
                print_ln('update average: %s (%s)',
                         sum(vec) * cfix(1 / len(vec)), len(vec))
            if self.debug:
                limit = int(self.debug)
                d = delta_theta.get_vector().reveal()
                aa = [cfix.Array(len(d.v)) for i in range(3)]
                a = aa[0]
                a.assign(d)
                @for_range(len(a))
                def _(i):
                    x = a[i]
                    print_ln_if((x > limit) + (x < -limit),
                                'update epoch=%s %s index=%s %s',
                                i_epoch.read(), str(delta_theta), i, x)
                a = aa[1]
                a.assign(nabla.get_vector().reveal())
                @for_range(len(a))
                def _(i):
                    x = a[i]
                    print_ln_if((x > len(batch) * limit) + (x < -len(batch) * limit),
                                'nabla epoch=%s %s index=%s %s',
                                i_epoch.read(), str(nabla), i, x)
                a = aa[2]
                a.assign(theta.get_vector().reveal())
                @for_range(len(a))
                def _(i):
                    x = a[i]
                    print_ln_if((x > limit) + (x < -limit),
                                'theta epoch=%s %s index=%s %s',
                                i_epoch.read(), str(theta), i, x)
            if self.print_random_update:
                print_ln('update')
                l = min(100, nabla.total_size())
                if l < 100:
                    index = 0
                else:
                    index = regint.get_random(64) % (nabla.total_size() - l)
                print_ln('%s at %s: nabla=%s update=%s theta=%s', str(theta),
                         index, nabla.to_array().get_vector(index, l).reveal(),
                         delta_theta.to_array().get_vector(index, l).reveal(),
                         theta.to_array().get_vector(index, l).reveal())
        self.gamma.imul(1 - 10 ** - 6)

def apply_padding(input_shape, kernel_size, strides, padding):
    if isinstance(padding, int):
        padding = [padding, padding]
    if isinstance(padding, (tuple, list)):
        input_shape = [input_shape[i] + 2*padding[i] for i in range(len(input_shape))]
        padding = 'valid'
    if padding.lower() == 'valid':
        res = (input_shape[0] - kernel_size[0]) // strides[0] + 1, \
            (input_shape[1] - kernel_size[1]) // strides[1] + 1,
        assert min(res) > 0, (input_shape, kernel_size, strides, padding)
        return res
    elif padding.lower() == 'same':
        return (input_shape[0]) // strides[0], \
            (input_shape[1]) // strides[1],
    else:
        raise Exception('invalid padding: %s' % padding)

class keras:
    class layers:
        Flatten = lambda *args, **kwargs: ('flatten', args, kwargs)
        Dense = lambda *args, **kwargs: ('dense', args, kwargs)

        def Conv2D(filters, kernel_size, strides=(1, 1), padding='valid',
                   activation=None, input_shape=None):
            return 'conv2d', {'filters': filters, 'kernel_size': kernel_size,
                              'strides': strides, 'padding': padding,
                              'activation': activation}

        def MaxPooling2D(pool_size=2, strides=None, padding='valid'):
            return 'maxpool', {'pool_size': pool_size, 'strides': strides,
                               'padding': padding}

        def AveragePooling2D(pool_size=2, strides=None, padding='valid'):
            return 'avgpool', {'filter_size': pool_size, 'strides': strides,
                               'padding': padding}

        def Dropout(rate):
            l = math.log(rate, 2)
            if int(l) != l:
                raise Exception('rate needs to be a power of two')
            return 'dropout', rate

        def Activation(activation):
            assert(activation == 'relu')
            return activation,

        def BatchNormalization():
            return 'batchnorm',

    class optimizers:
        SGD = lambda *args, **kwargs: ('sgd', args, kwargs)
        Adam = lambda *args, **kwargs: ('adam', args, kwargs)

    class models:
        class Sequential:
            def __init__(self, layers):
                self.layers = layers
                self.optimizer = None
                self.opt = None

            def compile(self, optimizer):
                self.optimizer = optimizer

            def compile_by_args(self, program):
                if 'adam' in program.args:
                    self.optimizer = 'adam', [], {}
                elif 'amsgrad' in program.args:
                    self.optimizer = 'adam', [], {'amsgrad': True}
                elif 'amsgradprec' in program.args:
                    self.optimizer = 'adam', [], {'amsgrad': True,
                                                  'approx': False}
                else:
                    self.optimizer = 'sgd', [], {}

            @property
            def trainable_variables(self):
                if self.opt == None:
                    raise Exception('need to run build() or fit() first')
                return list(self.opt.thetas)

            def summary(self):
                self.opt.summary()

            def build(self, input_shape, batch_size=128, program=None):
                data_input_shape = input_shape
                if self.opt != None and \
                   input_shape == self.opt.layers[0]._X.sizes and \
                   batch_size <= self.batch_size and \
                   type(self.opt).__name__.lower() == self.optimizer[0]:
                    return
                if self.optimizer == None:
                    self.optimizer = 'inference', [], {}
                if input_shape == None:
                    raise Exception('must specify number of samples')
                Layer.back_batch_size = batch_size
                layers = []
                for i, layer in enumerate(self.layers):
                    name = layer[0]
                    if name == 'dense':
                        if len(layers) == 0:
                            N = input_shape[0]
                            n_units = reduce(operator.mul, input_shape[1:])
                        else:
                            N = batch_size
                            n_units = reduce(operator.mul,
                                             layers[-1].Y.sizes[1:])
                        if i == len(self.layers) - 1:
                            activation = layer[2].get('activation', None)
                            if activation in ('softmax', 'sigmoid'):
                                layer[2].pop('activation', None)
                            if activation == 'softmax' and layer[1][0] == 1:
                                raise CompilerError(
                                    'softmax requires more than one output neuron')
                        layers.append(Dense(N, n_units, layer[1][0],
                                            **layer[2]))
                        input_shape = layers[-1].Y.sizes
                    elif name == 'conv2d':
                        input_shape = list(input_shape) + \
                            [1] * (4 - len(input_shape))
                        print (layer[1])
                        kernel_size = layer[1]['kernel_size']
                        filters = layer[1]['filters']
                        strides = layer[1]['strides']
                        padding = layer[1]['padding']
                        layers.append(easyConv2d(
                            input_shape, batch_size, filters, kernel_size,
                            strides, padding))
                        output_shape = layers[-1].Y.sizes
                        input_shape = output_shape
                        print('conv output shape', output_shape)
                    elif name == 'maxpool':
                        pool_size = layer[1]['pool_size']
                        strides = layer[1]['strides']
                        padding = layer[1]['padding']
                        layers.append(easyMaxPool(input_shape, pool_size,
                                                  strides, padding))
                        input_shape = layers[-1].Y.sizes
                    elif name == 'avgpool':
                        layers.append(FixAveragePool2d(input_shape, None, **layer[1]))
                        input_shape = layers[-1].Y.sizes
                    elif name == 'dropout':
                        layers.append(Dropout([batch_size] + [reduce(
                            operator.mul, layers[-1].Y.sizes[1:])],
                                              alpha=layer[1]))
                        input_shape = layers[-1].Y.sizes
                    elif name == 'flatten':
                        pass
                    elif name == 'relu':
                        layers.append(Relu(layers[-1].Y.sizes))
                    elif name == 'batchnorm':
                        input_shape = layers[-1].Y.sizes
                        layers.append(BatchNorm(layers[-1].Y.sizes))
                    else:
                        raise Exception(layer[0] + ' not supported')
                if layers[-1].d_out == 1:
                    layers.append(Output(data_input_shape[0]))
                else:
                    shape = data_input_shape[0], layers[-1].d_out
                    if program:
                        layers.append(MultiOutput.from_args(program, *shape))
                    else:
                        layers.append(MultiOutput(*shape))
                if self.optimizer[1]:
                    raise Exception('use keyword arguments for optimizer')
                opt = self.optimizer[0]
                opts = self.optimizer[2]
                if opt == 'sgd':
                    opt = SGD(layers, 1)
                    momentum = opts.pop('momentum', None)
                    if momentum != None:
                        opt.momentum = momentum
                elif opt == 'adam':
                    opt = Adam(layers, amsgrad=opts.pop('amsgrad', None),
                               approx=opts.pop('approx', True))
                    beta1 = opts.pop('beta_1', None)
                    beta2 = opts.pop('beta_2', None)
                    epsilon = opts.pop('epsilon', None)
                    if beta1 != None:
                        opt.beta1 = beta1
                    if beta2:
                        opt.beta2 = beta2
                    if epsilon:
                        if epsilon < opt.epsilon:
                            print('WARNING: epsilon smaller than default might '
                                  'cause overflows')
                        opt.epsilon = epsilon
                elif opt == 'inference':
                    opt = Optimizer()
                    opt.layers = layers
                else:
                    raise Exception(opt + ' not supported')
                lr = opts.pop('learning_rate', None)
                if lr != None:
                    opt.set_learning_rate(lr)
                if opts:
                    raise Exception(opts + ' not supported')
                self.batch_size = batch_size
                self.opt = opt

            def fit(self, x, y, batch_size, epochs=1, validation_data=None):
                assert len(x) == len(y)
                self.build(x.sizes, batch_size)
                if x.total_size() != self.opt.layers[0]._X.total_size():
                    raise Exception('sample data size mismatch')
                if y.total_size() != self.opt.layers[-1].Y.total_size():
                    print (y, self.opt.layers[-1].Y)
                    raise Exception('label size mismatch')
                if validation_data == None:
                    validation_data = None, None
                else:
                    if len(validation_data[0]) != len(validation_data[1]):
                        raise Exception('test set size mismatch')
                self.opt.layers[0]._X.address = x.address
                self.opt.layers[-1].Y.address = y.address
                self.opt.run_by_args(get_program(), epochs, batch_size,
                                     validation_data[0], validation_data[1],
                                     batch_size)
                return self.opt

            def predict(self, x, batch_size=None):
                if self.opt == None:
                    raise Exception('need to run fit() or build() first')
                if batch_size != None:
                    batch_size = min(batch_size, self.batch_size)
                return self.opt.eval(x, batch_size=batch_size)

def layers_from_torch(model, data_input_shape, batch_size, input_via=None,
                      regression=False, layer_args={}, program=None):
    """ Convert a PyTorch Module object to MP-SPDZ layers.

    :param model: PyTorch Module object
    :param data_input_shape: input shape (list of four int)
    :param batch_size: batch size (int)
    :param input_via: player to input model data via (default: don't)
    :param regression: regression (default: classification)

    """
    layers = []
    named_layers = {}

    def mul(x):
        return reduce(operator.mul, x)

    import torch
    import torch.fx

    # Custom tracer to prevent inlining BERT layers
    class BertTracer(torch.fx.Tracer):
        def is_leaf_module(self, m, module_qualified_name):
            # Treat BertLayer, BertPooler, and BertEmbeddings as leaf modules (don't trace into them)
            type_name = type(m).__name__
            if any(x in type_name for x in ['BertLayer', 'BertPooler', 'BertEmbeddings']):
                return True
            return super().is_leaf_module(m, module_qualified_name)

    def process(item, inputs, input_shape, args, kwargs={}):
        # Skip assertion and validation functions from torch.fx trace
        if callable(item) and hasattr(item, '__name__') and (
                item.__name__.startswith('_assert') or
                item.__name__ in ('eq', 'getitem', 'size')):
            return
        if item == torch.cat:
            if len(inputs) > 1:
                layers.append(
                    Concat(inputs, dimension=len(inputs[0].shape) - 1))
            return
        elif item == operator.add:
            layers.append(Add(inputs))
            return
        elif item in (torch.flatten, 'flatten', 'size'):
            return
        elif item == 'view':
            assert -1 in args or \
                reduce(operator.mul, args) == reduce(operator.mul, input_shape)
            return
        elif item == torch.nn.functional.avg_pool2d:
            layers.append(FixAveragePool2d(input_shape, None, args[1],
                                           kwargs.get('stride', args[1]),
                                           kwargs.get('padding', 0)))
            input_shape = layers[-1].shape
            return
        # single-input layers from here
        if inputs and len(inputs) > 1:
            raise CompilerError('multi-input layer %s not supported' % item)
        name = type(item).__name__
        if name == 'Linear':
            assert mul(input_shape[1:]) == item.in_features
            assert item.bias is not None
            layers.append(Dense(input_shape[0], item.in_features,
                                item.out_features))
            if input_via is not None:
                shapes = [x.shape for x in (layers[-1].W, layers[-1].b)]
                import numpy
                swapped = item.weight.detach().numpy()
                if len(input_shape) == 4:
                    print (swapped.shape)
                    swapped = numpy.reshape(
                        swapped,
                        [item.out_features, input_shape[3]] + input_shape[1:3])
                    print (swapped.shape)
                    swapped = numpy.moveaxis(swapped, 1, -1)
                    print (swapped.shape)
                    swapped = numpy.reshape(
                        swapped, [item.out_features, item.in_features])
                    print (swapped.shape)
                swapped = numpy.swapaxes(swapped, 0, 1)
                layers[-1].W = sfix.input_tensor_via(
                    input_via, swapped)
                layers[-1].b = sfix.input_tensor_via(
                    input_via, item.bias.detach())
                assert layers[-1].W.shape == shapes[0]
                assert layers[-1].b.shape == shapes[1]
            input_shape = [batch_size, item.out_features]
        elif name == 'Conv2d':
            layers.append(easyConv2d(input_shape, batch_size, item.out_channels,
                                     item.kernel_size, item.stride,
                                     item.padding, item.bias is not None, **layer_args.get(item, {})))
            input_shape = layers[-1].Y.shape
            if input_via is not None:
                if item.bias is not None:
                    shapes = [x.shape for x in
                          (layers[-1].weights, layers[-1].bias)]
                else:
                    shapes = [layers[-1].weights.shape]
                print("shapes", shapes, layers[-1].weights.shape)
                import numpy
                swapped = numpy.moveaxis(
                    numpy.array(item.weight.detach()), 1, -1)
                layers[-1].weights = \
                    layers[-1].weights.value_type.input_tensor_via(
                        input_via, swapped)
                assert layers[-1].weights.shape == shapes[0], f"{layers[-1].weights.shape} != {shapes[0]}"
                if isinstance(item.bias, torch.Tensor):
                    layers[-1].bias = sfix.input_tensor_via(
                        input_via, item.bias.detach())
                    assert layers[-1].bias.shape == shapes[1]
        elif name == 'MaxPool2d':
            layers.append(easyMaxPool(input_shape, item.kernel_size,
                                      item.stride, item.padding))
            input_shape = layers[-1].shape
        elif name == 'AvgPool2d':
            layers.append(FixAveragePool2d(input_shape, None, item.kernel_size,
                                           item.stride, item.padding))
            input_shape = layers[-1].shape
        elif name == 'AdaptiveAvgPool2d' or \
             item == torch.nn.functional.adaptive_avg_pool2d:
            if name == 'AdaptiveAvgPool2d':
                output = item.output_size
            else:
                output = args[1]
            for i in (0, 1):
                assert input_shape[1 + i] % output[i] == 0
            stride = [input_shape[1 + i] // output[i] for i in (0, 1)]
            kernel_size = [input_shape[1 + i] - (output[i] - 1) * stride[i]
                           for i in (0, 1)]
            layers.append(FixAveragePool2d(input_shape, None, kernel_size,
                                           stride, padding=0))
            input_shape = layers[-1].shape
        elif name == 'ReLU' or item == torch.nn.functional.relu:
            layers.append(Relu(input_shape))
        elif name == 'Flatten':
            return
        elif name == 'BatchNorm2d' or name == 'BatchNorm1d':
            layers.append(BatchNorm(layers[-1].Y.sizes))
            if input_via is not None:
                layers[-1].epsilon = item.eps
                layers[-1].weights = sfix.input_tensor_via(input_via,
                                                           item.weight.detach())
                layers[-1].bias = sfix.input_tensor_via(input_via,
                                                        item.bias.detach())
                layers[-1].mu_hat = sfix.input_tensor_via(
                    input_via, item.running_mean.detach())
                layers[-1].var_hat = sfix.input_tensor_via(
                    input_via, item.running_var.detach())
        elif name == 'Dropout':
            alpha = item.p
            if alpha == 0.1:
                print('WARNING: dropout rate 0.1 not supported, using 0.125')
                alpha = 0.125
            layers.append(Dropout([input_shape[0]] + list(layers[-1].Y.sizes[1:]),
                                  alpha=alpha))
            input_shape = layers[-1].Y.sizes
        elif name == 'BertForSequenceClassification':
            process(item.bert)
            process(item.dropout)
            process(item.classifier)
        elif name == 'BertModel':
            bert_config = item.config
            process(item.embeddings)
            process(item.encoder)
            process(item.pooler)
        elif name == 'BertEmbeddings':
            print('Embedding layer not implemented.', item)
            pass # no-op
        elif name == 'BertEncoder':
            for x in item.layer:
                process(x)
        elif name == 'BertLayer':
            # Get config from the model or item
            if 'bert_config' in locals():
                config = bert_config
            elif hasattr(model, 'config'):
                config = model.config
            elif hasattr(item, 'config'):
                config = item.config
            else:
                raise CompilerError('BertLayer requires config but none found in model or item')
            hidden_state = config.hidden_size
            intermediate_size = config.intermediate_size
            num_attention_heads = config.num_attention_heads
            layernorm_eps = config.layer_norm_eps
            seq_len = input_shape[1]
            rsqrt_approx = False
            layer = BertLayer(input_shape[0], seq_len, hidden_state, intermediate_size, num_attention_heads,
                              layernorm_eps, 0.125, rsqrt_approx, batch_size=batch_size)
            if input_via is not None:
                layer.load_state_dict(item.state_dict(), input_via)
            layers.append(layer)
            input_shape = [batch_size, seq_len, hidden_state]
        elif name == 'BertPooler':
            # Get config from the model or item
            if 'bert_config' in locals():
                config = bert_config
            elif hasattr(model, 'config'):
                config = model.config
            elif hasattr(item, 'config'):
                config = item.config
            else:
                raise CompilerError('BertPooler requires config but none found in model or item')
            layer = BertPooler(input_shape[0], input_shape[1], config.hidden_size)
            if input_via is not None:
                layer.load_state_dict(item.state_dict(), input_via)
            layers.append(layer)
        elif name == "Identity":
            return
        else:
            raise CompilerError('unknown PyTorch module: %s' % item)
        layers[-1].inputs = inputs

    input_shape = data_input_shape + [1] * (4 - len(data_input_shape))

    # torch_layers = list(torch.fx.symbolic_trace(model).graph.nodes)
    # Use custom tracer to keep BERT layers as modules
    tracer = BertTracer()

    # Determine concrete_args based on model type
    # Check if this is BertModel or BertEncoder
    import torch as torch_module
    model_type = type(model).__name__
    if model_type == 'BertModel':
        # BertModel requires both input_ids and token_type_ids in concrete_args
        # None means they must be provided as positional args during trace
        concrete_args = {
            "attention_mask": None,
            "token_type_ids": None,
            "position_ids": None,
            "head_mask": None,
            "inputs_embeds": None,
            "encoder_hidden_states": None,
            "encoder_attention_mask": None,
            "past_key_values": None,
            "use_cache": None,
            "output_attentions": False,
            "output_hidden_states": False,
            "return_dict": False,
        }
    else:
        # BertEncoder and other modules
        concrete_args = {
            "attention_mask": None,
            "head_mask": None,
            "encoder_hidden_states": None,
            "encoder_attention_mask": None,
            "past_key_values": None,
            "use_cache": None,
            "output_attentions": False,
            "output_hidden_states": False,
            "return_dict": False,
        }

    graph = tracer.trace(model, concrete_args=concrete_args)
    torch_layers = list(graph.nodes)
    print(torch_layers)
    for i, layer in enumerate(torch_layers[1:-1]):
        # Skip non-module and non-function operations (like getitem, assertions, etc.)
        if layer.op not in ('call_module', 'call_function'):
            continue

        if layer.op == 'call_module':
            target = model
            for attr in layer.target.split('.'):
                target = getattr(target, attr)
        else:
            target = layer.target
        if not layers:
            print(f"First layer check: layer.args={layer.args}, torch_layers[i]={torch_layers[i]}")
            # First real layer - no need for assertion
            inputs = None
        else:
            if len(layer.args) < 2 or (layer.args[1] != 1 and
                                       layer.args[1] != (1, 1)):
                args = layer.args
            elif isinstance(layer.args[0], list):
                args = layer.args[0]
            else:
                args = layer.args[0],
            inputs = []
            try:
                for x in args:
                    inputs.append(named_layers[x])
            except KeyError:
                pass
            if len(inputs) == 1:
                if isinstance(inputs[0], (Dropout, BatchNorm)):
                    input_shape = inputs[0].inputs[0].Y.shape
                else:
                    input_shape = inputs[0]._Y.shape
            else:
                input_shape = None
        process(target, inputs, input_shape, layer.args, layer.kwargs)
        if layers:
            named_layers[layer] = layers[-1]

    if regression:
        layers.append(LinearOutput(data_input_shape[0], layers[-1].d_out))
    elif layers[-1].d_out == 1:
        layers.append(Output(data_input_shape[0]))
    else:
        shape = data_input_shape[0], layers[-1].d_out
        if program:
            layers.append(MultiOutput.from_args(program, *shape))
        else:
            layers.append(MultiOutput(*shape))
    return layers

class OneLayerSGD:
    def __init__(self, n_epochs=1, batch_size=1, program=None):
        self.n_epochs = n_epochs
        self.batch_size = batch_size
        self.program = program
        Layer.back_batch_size = max(Layer.back_batch_size, batch_size)

    def fit(self, X_train, y_train, **kwargs):
        """ Train classifier.

        :param X_train: training data (sfix matrix)
        :param y_train: training binary labels (sint/sfix array)
        :param sample_mask: sample masking (see :py:func:`Optimizer.fit`)

        """
        self.init(X_train)
        self.opt.fit(X_train, y_train, self.n_epochs, self.batch_size,
                     program=self.program, print_accuracy=False,
                     **kwargs)

    def fit_with_testing(self, X_train, y_train, X_test, y_test, **kwargs):
        """ Train classifier with accuracy output after every epoch.
        This reveals all labels to simplify the accuracy computation.

        :param X_train: training data (sfix matrix)
        :param y_train: training labels (sint/sfix array)
        :param X_test: testing data (sfix matrix)
        :param y_test: testing labels (sint/sfix array)
        :param sample_mask: sample masking (see :py:func:`Optimizer.fit`)

        """
        self.init(X_train)
        self.opt.print_accuracy = self.print_accuracy
        self.opt.fit(X_train, y_train, self.n_epochs, self.batch_size,
                     validation_data=(X_test, y_test), program=self.program,
                     print_accuracy=self.print_accuracy, print_loss=True,
                     **kwargs)

    def predict(self, X):
        """ Use model for prediction.

        :param X: sample data with row-wise samples (sfix matrix)
        :returns: sfix array

        """
        return self.opt.eval(X)

class SGDLogistic(OneLayerSGD):
    """ Logistic regression using SGD.
    The member :py:obj:`opt` refers to the internal instance of
    :py:class:`Optimizer`, which allows to use the funcionality
    therein.

    :param n_epochs: number of epochs
    :param batch_size: batch size
    :param program: program object to use command-line options from (default is
      not to use any)

    """
    print_accuracy = True

    def init(self, X):
        dense = Dense(*X.sizes, 1)
        if self.program:
            sigmoid = Output.from_args(X.sizes[0], self.program)
            self.opt = Optimizer.from_args(self.program, [dense, sigmoid])
        else:
            sigmoid = Output(X.sizes[0])
            self.opt = SGD([dense, sigmoid], 1)

    def predict(self, X):
        """ Use model to predict labels.

        :param X: sample data with row-wise samples (sfix matrix)
        :returns: sint array

        """
        return self.opt.eval(X, top=True)

    def predict_proba(self, X):
        """ Use model for probility estimates.

        :param X: sample data with row-wise samples (sfix matrix)
        :returns: sfix array

        """
        return super(SGDLogistic, self).predict(X)

class SGDLinear(OneLayerSGD):
    """ Linear regression using SGD.

    :param n_epochs: number of epochs
    :param batch_size: batch size
    :param program: program object to use command-line options from (default is
      not to use any)

    """
    print_accuracy = False

    def init(self, X):
        dense = Dense(*X.sizes, 1)
        output = LinearOutput(X.sizes[0])
        if self.program:
            self.opt = Optimizer.from_args(self.program, [dense, output])
        else:
            self.opt = SGD([dense, output], 1)

def solve_linear(A, b, n_iterations, progress=False, n_threads=None,
                 stop=False, already_symmetric=False, precond=False):
    """ Iterative linear solution approximation for :math:`Ax=b`.

    :param progress: print some information on the progress (implies revealing)
    :param n_threads: number of threads to use
    :param stop: whether to stop when converged (implies revealing)

    """
    assert len(b) == A.sizes[0]
    x = sfix.Array(A.sizes[1])
    x.assign_vector(sfix.get_random(-1, 1, size=len(x)))
    if already_symmetric:
        AtA = A
        r = Array.create_from(b - AtA * x)
    else:
        AtA = sfix.Matrix(len(x), len(x))
        A.trans_mul_to(A, AtA, n_threads=n_threads)
        r = Array.create_from(A.transpose() * b - AtA * x)
    if precond:
        return solve_linear_diag_precond(AtA, b, x, r, n_iterations,
                                         progress, stop)
    v = sfix.Array(A.sizes[1])
    v.assign_all(0)
    Av = sfix.Array(len(x))
    @for_range(n_iterations)
    def _(i):
        v[:] = r - sfix.dot_product(r, Av) / sfix.dot_product(v, Av) * v
        Av[:] = AtA * v
        v_norm = sfix.dot_product(v, Av)
        vr = sfix.dot_product(v, r)
        alpha = (v_norm == 0).if_else(0, vr / v_norm)
        x[:] = x + alpha * v
        r[:] = r - alpha * Av
        if progress:
            print_ln('%s alpha=%s vr=%s v_norm=%s', i, alpha.reveal(),
                     vr.reveal(), v_norm.reveal())
        if stop:
            return (alpha > 0).reveal()
    if not already_symmetric:
        AtA.delete()
    return x

def solve_linear_diag_precond(A, b, x, r, n_iterations, progress=False,
                              stop=False):
    m = 1 / A.diag()
    mr = Array.create_from(m * r[:])
    d = Array.create_from(mr)
    @for_range(n_iterations)
    def _(i):
        Ad = A * d
        d_norm = sfix.dot_product(d, Ad)
        alpha = (d_norm == 0).if_else(0, sfix.dot_product(r, mr) / d_norm)
        x[:] = x[:] + alpha * d[:]
        r_norm = sfix.dot_product(r, mr)
        r[:] = r[:] - alpha * Ad
        tmp = m * r[:]
        beta = (r_norm == 0).if_else(0, sfix.dot_product(r, tmp) / r_norm)
        mr[:] = tmp
        d[:] = tmp + beta * d
        if progress:
            print_ln('%s alpha=%s beta=%s r_norm=%s d_norm=%s', i,
                     alpha.reveal(), beta.reveal(), r_norm.reveal(),
                     d_norm.reveal())
        if stop:
            return (alpha > 0).reveal()
    return x

def mr(A, n_iterations, stop=False):
    """ Iterative matrix inverse approximation.
    This is based on the conjugate gradients algorithm in Section
    10.2.4 of `these lecture notes <https://graphics.stanford.edu/courses/cs205a-13-fall/assets/notes/cs205a_notes.pdf>`_.

    :param A: matrix to invert
    :param n_iterations: maximum number of iterations
    :param stop: whether to stop when converged (implies revealing)

    """
    assert len(A.sizes) == 2
    assert A.sizes[0] == A.sizes[1]
    M = A.same_shape()
    n = A.sizes[0]
    @for_range(n)
    def _(i):
        e = sfix.Array(n)
        e.assign_all(0)
        e[i] = 1
        M[i] = solve_linear(A, e, n_iterations, stop=stop)
    return M.transpose()

def var(x):
    """ Variance. """
    mean = MemValue(type(x[0])(0))
    @for_range_opt(len(x))
    def _(i):
        mean.iadd(x[i])
    mean /= len(x)
    res = MemValue(type(x[0])(0))
    @for_range_opt(len(x))
    def _(i):
        res.iadd((x[i] - mean.read()) ** 2)
    return res.read()

def cholesky(A, reveal_diagonal=False):
    """ Cholesky decomposition.

    :returns: lower triangular matrix

    """
    assert len(A.shape) == 2
    assert A.shape[0] == A.shape[1]
    L = A.same_shape()
    L.assign_all(0)
    diag_inv = A.value_type.Array(A.shape[0])
    @for_range(A.shape[0])
    def _(i):
        @for_range(i + 1)
        def _(j):
            sum = sfix.dot_product(L[i], L[j])

            @if_e(i == j)
            def _():
                L[i][j] = mpc_math.sqrt(A[i][i] - sum)
                diag_inv[i] = 1 / L[i][j]
                if reveal_diagonal:
                    print_ln('L[%s][%s] = %s = sqrt(%s - %s)', i, j,
                             L[i][j].reveal(), A[i][j].reveal(), sum.reveal())
            @else_
            def _():
                L[i][j] = (diag_inv[j] * (A[i][j] - sum))
    return L

def solve_lower(A, b):
    """ Linear solver where :py:obj:`A` is lower triangular quadratic. """
    assert len(A.shape) == 2
    assert A.shape[0] == A.shape[1]
    assert len(b) == A.shape[0]
    b = Array.create_from(b)
    res = sfix.Array(len(b))
    @for_range(len(b))
    def _(i):
        res[i] = b[i] / A[i][i]
        b[:] -= res[i] * A.get_column(i)
    return res

def solve_upper(A, b):
    """ Linear solver where :py:obj:`A` is upper triangular quadratic. """
    assert len(A.shape) == 2
    assert A.shape[0] == A.shape[1]
    assert len(b) == A.shape[0]
    b = Array.create_from(b)
    res = sfix.Array(len(b))
    @for_range(len(b) - 1, -1, -1)
    def _(i):
        res[i] = b[i] / A[i][i]
        b[:] -= res[i] * A.get_column(i)
    return res

def solve_cholesky(A, b, debug=False):
    """ Linear solver using Cholesky decomposition. """
    L = cholesky(A, reveal_diagonal=debug)
    if debug:
        Optimizer.stat('L', L)
    x = solve_lower(L, b)
    if debug:
        Optimizer.stat('intermediate', x)
    return solve_upper(L.transpose(), x)
