
#ifndef _myHNF
#define _myHNF

#include <vector>
using namespace std;

#include "Math/bigint.h"
#include "Math/modp.h"
#include "Tools/BitVector.h"

typedef vector< vector<bigint> > matrix;

class imatrix : public vector< BitVector >
{
    typedef vector<BitVector> super;

public:
    bool operator!=(const imatrix& other) const;

    void hash(octetStream& o) const;
    void pack(octetStream& o) const;
    void unpack(octetStream& o);
};

/* Uses Algorithm 2.7 from Pohst-Zassenhaus to compute H and U st
		H = HNF(A) = A*U
*/
void HNF(matrix& H,matrix& U,const matrix& A);

/* S = U*A*V
   We dont care about U though
*/
void SNF(matrix& S,const matrix& A,matrix& V);

void print(const matrix& S);
void print(const imatrix& S);

// Special inverse routine, assumes A is unimodular and only
// requires column operations to create the inverse
matrix inv(const matrix& A);

// Finds a pseudo-inverse of a matrix A modulo 2
//   - Input matrix is assumed to have more rows than columns
void pinv(imatrix& Ai,const imatrix& A);

#endif
