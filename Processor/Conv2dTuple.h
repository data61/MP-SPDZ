/*
 * Conv2dTuple.h
 *
 */

#ifndef PROCESSOR_CONV2DTUPLE_H_
#define PROCESSOR_CONV2DTUPLE_H_

#include <vector>
using namespace std;

class Conv2dTuple
{
public:
    int output_h, output_w;
    int inputs_h, inputs_w;
    int weights_h, weights_w;
    int stride_h, stride_w;
    int n_channels_in;
    int padding_h;
    int padding_w;
    int batch_size;
    size_t r0;
    size_t r1;
    int r2;
    vector<vector<vector<int>>> lengths;
    int filter_stride_h = 1;
    int filter_stride_w = 1;

    Conv2dTuple(const ArgVector& args, int start);

    array<int, 3> matrix_dimensions();

    template<class T>
    void pre(StackedVector<T>& S, typename T::Protocol& protocol);
    template<class T>
    void post(StackedVector<T>& S, typename T::Protocol& protocol);

    template<class T>
    void run_matrix(SubProcessor<T>& processor);
};

#endif /* PROCESSOR_CONV2DTUPLE_H_ */
