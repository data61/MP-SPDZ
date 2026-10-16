/*
 * BitMatrix.hpp
 *
 */

#ifndef OT_BITMATRIX_HPP_
#define OT_BITMATRIX_HPP_

#include "BitMatrix.h"
#include "Tools/BitVector.h"

template <class U>
size_t Matrix<U>::vertical_size() const
{
    return squares.size() * U::N_ROWS;
}

template <class U>
bool Matrix<U>::operator==(Matrix<U>& other)
{
    if (squares.size() != other.squares.size())
        throw invalid_length("Matrix");
    for (size_t i = 0; i < squares.size(); i++)
        if (not(squares[i] == other.squares[i]))
            return false;
    return true;
}

template <class U>
bool Matrix<U>::operator!=(Matrix<U>& other)
{
    return not (*this == other);
}

template <class U>
void Matrix<U>::randomize(PRNG& G)
{
    for (size_t i = 0; i < squares.size(); i++)
        squares[i].randomize(G);
}

template <class U>
void Matrix<U>::randomize(int row, PRNG& G)
{
    for (size_t i = 0; i < squares.size(); i++)
        squares[i].randomize(row, G);
}


template <class U>
void Matrix<U>::print_side_by_side(Matrix<U>& other)
{
    for (int i = 0; i < 32; i++)
    {
        for (int j = 0; j < 64; j++)
            cout << squares[0].get_bit(i,j);
        cout << " ";
        for (int j = 0; j < 64; j++)
            cout << other.squares[0].get_bit(i,j);
        cout << endl;
    }
}

template <class U>
void Matrix<U>::print_conditional(BitVector& conditions)
{
    for (int i = 0; i < 32; i++)
    {
        if (conditions.get_bit(i))
            for (int j = 0; j < 65; j++)
                cout << " ";
        for (int j = 0; j < 64; j++)
            cout << squares[0].get_bit(i,j);
        if (!conditions.get_bit(i))
            for (int j = 0; j < 65; j++)
                cout << " ";
        cout << endl;
    }
}

template <class U>
void Matrix<U>::pack(octetStream& os) const
{
    for (size_t i = 0; i < squares.size(); i++)
        squares[i].pack(os);
}

template <class U>
void Matrix<U>::unpack(octetStream& os)
{
    for (size_t i = 0; i < squares.size(); i++)
        squares[i].unpack(os);
}

template <class U>
Slice<U>::Slice(U& bm, size_t start, size_t size) :
        bm(bm), start(start)
{
    end = start + size;
    if (end > bm.squares.size())
    {
        stringstream ss;
        ss << "Matrix slice (" << start << "," << end << ") larger than matrix (" << bm.squares.size() << ")";
        throw invalid_argument(ss.str());
    }
}

template <class U>
Slice<U>& Slice<U>::rsub(Slice<U>& other)
{
    if (bm.squares.size() < other.end)
        throw invalid_length("rsub");
    for (size_t i = other.start; i < other.end; i++)
        bm.squares[i].rsub(other.bm.squares[i]);
    return *this;
}

template <class U>
Slice<U>& Slice<U>::sub(BitVector& other, int repeat)
{
    if (end * U::PartType::n_columns() > other.size() * repeat)
        throw invalid_length(to_string(U::PartType::n_columns()));
    for (size_t i = start; i < end; i++)
    {
        if (repeat > 0)
            bm.squares[i].sub(other.get_ptr_to_byte(i / repeat,
                    U::PartType::n_row_bytes()));
        else
            bm.squares[i].bit_sub(other, i * U::PartType::n_rows_allocated());
    }
    return *this;
}

template <class U>
void Slice<U>::randomize(int row, PRNG& G)
{
    for (size_t i = start; i < end; i++)
        bm.squares[i].randomize(row, G);
}

template <class U>
void Slice<U>::conditional_add(BitVector& conditions, U& other, bool useOffset)
{
    for (size_t i = start; i < end; i++)
        bm.squares[i].conditional_add(conditions, other.squares[i], useOffset * i);
}

template <class U>
template <class T>
void Slice<U>::print()
{
    cout << "hex / value" << endl;
    for (int i = 0; i < 16; i++)
    {
        cout << T(bm.squares[0].rows[i]) << endl;
    }
    cout << endl;
}

template <class U>
void Slice<U>::pack(octetStream& os) const
{
    os.reserve(U::PartType::size() * (end - start));
    for (size_t i = start; i < end; i++)
        bm.squares[i].pack(os);
}

template <class U>
void Slice<U>::unpack(octetStream& os)
{
    for (size_t i = start; i < end; i++)
        bm.squares[i].unpack(os);
}

#endif /* OT_BITMATRIX_HPP_ */
