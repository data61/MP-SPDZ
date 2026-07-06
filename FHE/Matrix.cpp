
#include "FHE/Matrix.h"
#include "Tools/Exceptions.h"
#include "Processor/OnlineOptions.h"

#include "Math/modp.hpp"

#include <stdlib.h>
#include <iostream>

using namespace std;

void ident(matrix& U,int n)
{
  U.resize(n, vector<bigint>(n) );
  for (int i=0; i<n; i++)
    { for (int j=0; j<n; j++)
        { U[i][j]=0; }
      U[i][i]=1;
    }
}


void ident(imatrix& U,int n)
{
  U.resize(n, imatrix::value_type(n));
  for (int i=0; i<n; i++)
    { for (int j=0; j<n; j++)
        { U[i][j]=0; }
      U[i][i]=1;
    }
}




matrix transpose(const matrix& A)
{
  int m=A.size(),n=A[0].size();
  matrix B(n, vector<bigint>(m) );
  for (int i=0; i<m; i++)
    { for (int j=0; j<n; j++)
        { B[j][i]=A[i][j]; }
    }
  return B;
}


matrix Mul(const matrix& A,const matrix& B)
{
  unsigned int m=A.size(),n=B[0].size(),t=A[0].size();
  if (t!=B.size()) { throw invalid_length(); }
  matrix C(m, vector<bigint>(n) );
  for (unsigned int i=0; i<m; i++)
    { for (unsigned int j=0; j<n; j++)
	{ C[i][j]=0;
          for (unsigned int k=0; k<t; k++)
	    { C[i][j]+=A[i][k]*B[k][j]; }
        }
    }
  return C;
}


/* Uses Algorithm 2.7 from Pohst-Zassenhaus to compute H and U st
		H = HNF(A) = A*U
*/
void HNF(matrix& H,matrix& U,const matrix& A)
{
  int m=A.size(),n=A[0].size(),r,i,j,k;
  
#ifdef VERBOSE
  cerr << "HNF m=" << m << ", n=" << n << endl;
#endif

  H=A;
  ident(U,n);
  r=min(m,n);
  i=0;
  bool flag=true;
  bigint mn,te;
  int step=2;
  while (flag)
    { if (step==2)
        { // Step 2
          k=-1;
          mn=bigint(0);
          for (j=i; j<n; j++)
	    { if (H[i][j]!=0 && (abs(H[i][j])<mn || mn == 0))
	        { k=j; mn=abs(H[i][j]); }
            }
          if (k!=-1)
	    { if (k!=i)
	        { // Step 3
                  for (j=0; j<m; j++)
		    { te=H[j][i]; H[j][i]=H[j][k]; H[j][k]=te; }
                  for (j=0; j<n; j++)
                    { te=U[j][i]; U[j][i]=U[j][k]; U[j][k]=te; }
	        }
	      // Step 4
              bool fl=true;
              for (j=i+1; j<n; j++)
	        { te=H[i][j]/H[i][i];
                  if (abs(H[i][j]%H[i][i])>abs(H[i][i]/2)) { te=te+1; }
                  /*
		  cout << i << " " << j << " : " ;
                  cout << H[i][j] << " " << H[i][i] << " " << te << endl;
                  */
                  for (k=0; k<m; k++) { H[k][j]=H[k][j]-te*H[k][i]; }
                  for (k=0; k<n; k++) { U[k][j]=U[k][j]-te*U[k][i]; }
	          if (H[i][j]!=0) { fl=false; }
                }
	      if (fl==true) { step=5; }
            }
	 }
       
       if (step==5)
         { // Step 5 
	   if (H[i][i]<0) 
	      { for (k=0; k<m; k++) { H[k][i]=-H[k][i]; }
	        for (k=0; k<n; k++) { U[k][i]=-U[k][i]; }
	      }
	   for (j=0; j<i; j++)
	      { te=(H[i][j]/H[i][i]);
                for (k=0; k<m; k++) { H[k][j]=H[k][j]-te*H[k][i]; }
                for (k=0; k<n; k++) { U[k][j]=U[k][j]-te*U[k][i]; }
              }
	    step=6;
          }
        if (step==6)
	  { if (i==(r-1)) 
	       { flag=false; }
             else     
	       { i=i+1;
                 if (i==(r-1)) { step=2; }
                 else          { step=2; }
	       }
	 }
	//cout << i << " " << step << "\n" << H << endl;
    }
}


bool IsDiag(const matrix& A)
{
  int i,j,r=A.size(),c=A[0].size();
  for (i=0; i<r; i++)
    { for (j=0; j<c; j++)
        { if (i!=j && A[i][j]!=0) { return false; } }
    }
  return true;
}

bool IsIdent(const matrix& A)
{
  unsigned int i,j,r=A.size();
  if (A[0].size()!=r) { throw bad_value(); }
  for (i=0; i<r; i++)
    { for (j=0; j<r; j++)
        { if (i!=j && A[i][j]!=0) { return false; } }
      if (A[i][i]!=1) { return false; } 
    }
  return true;
}


void print(const matrix& S)
{
  int m=S.size(),n=S[0].size();
  for (int i=0; i<m; i++)
    { for (int j=0; j<n; j++)
	{ cout << S[i][j] << " "; }
      cout << endl;
    }
}


void print(const imatrix& S)
{
  int m=S.size(),n=S[0].size();
  for (int i=0; i<m; i++)
    { for (int j=0; j<n; j++)
        { cout << S[i][j] << " "; }
      cout << endl;
    }
}


void SNF_Step(matrix& S,matrix& V)
{ 
  //cout << "Entering SNF_Step " << endl;
  //print(S); cout << endl; print(V);
  int m=S.size();
  matrix U2,V2;
  while (!IsDiag(S))
    { //cout << "\n\nColumn Reducing...\n";
      HNF(S,V2,S);
      S=transpose(S);
      V=Mul(V,V2);
      //cout << "\n\nRow Reducing...\n";
      ident(U2,m);
      HNF(S,U2,S);
      S=transpose(S);
      //cout << "Step "  << endl;
      //print(S); cout << endl; print(V);
    }
}
  


// S = U*A*V
void SNF(matrix& S,const matrix& A,matrix& V)
{
  int m=A.size(),n=A[0].size();

#ifdef VERBOSE
  cerr << "SNF m=" << m << ", n=" << n << endl;
#endif

  S=A;
  ident(V,n);

  /* First get a diagonal matrix using the HNF */
  matrix U2,V2;
  SNF_Step(S,V); 

  /* Now get the divisibility condition */
  int i,r;
  r=min(m,n);
  for (i=0; i<r-1; i++)
    { if ((S[i+1][i+1]%S[i][i])!=0)
	{ // Add row i+1 to row i
	  S[i][i+1]=S[i+1][i+1];
          SNF_Step(S,V);
	}
    }
}



// Special inverse routine
matrix inv(const matrix& A)
{
  matrix HA,UA;
  HNF(HA,UA,A);

  if (!IsIdent(HA)) { cout << "Error in inverse" << endl; throw bad_value(); }
  return UA;
}



/* Input matrix is assumed to have more rows than columns */
void pinv(imatrix& Ai,const imatrix& B)
{
  imatrix A=B;
  int nr=A.size(),nc=A[0].size();
  ident(Ai,nr);

  int r=0,c=0;
  bool flag=true;

  bool verbose = OnlineOptions::singleton.has_option("verbose_he_setup");

  if (verbose)
    cout << "In inverse " << nr << " x " << nc << endl;
  while (flag)
    { //cout << "Inv step r=" << r << " c=" << c << endl; 
      if ((c%100)==0 and verbose)
        cout << "Inv: " << c << " out of " << nc << endl;
      // Find pivot
      int k=r;
      while (A[k][c]==0) { k++; }
      // Swap rows if needed
      if (k!=r)
        {
          A[r].swap(A[k]);
          Ai[r].swap(Ai[k]);
        }
      // Kill off all rows above and below with a one in this position
      for (k=0; k<nr; k++)
        { if (k!=r && A[k][c]==1)
	    { // Only have to go from c onwards as rest are done
            A[k].add(A[r]);
              // Need to do all cols here
            Ai[k].add(Ai[r]);
	    }
        }
      r++; c++;
      if (c==nc) { flag=false; }
   }
}


bool imatrix::operator!=(const imatrix& other) const
{
  if (size() != other.size())
    return true;
  for (size_t i = 0; i < size(); i++)
  {
    if (at(i).size() != other[i].size())
      return true;
    for (size_t j = 0; j < at(i).size(); j++)
      if (at(i)[j] != other[i][j])
        return true;
  }
  return false;
}

void imatrix::hash(octetStream& o) const
{
  Hash hash;
  for (auto& row : *this)
      hash.update(row.get_ptr(), row.size_bytes());
  o.concat(hash.final());
}

void imatrix::pack(octetStream& o) const
{
  for (auto& x : *this)
    {
      assert(x.size() == size());
    }
  o.store(static_cast<const super&>(*this));
}

void imatrix::unpack(octetStream& o)
{
  o.get(static_cast<super&>(*this));
  for (auto& x : *this)
    {
      assert(x.size() == size());
    }
}
