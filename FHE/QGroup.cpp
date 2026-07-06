
#include "Matrix.h"
#include "QGroup.h"
#include "Math/bigint.h"
#include "Processor/OnlineOptions.h"

#include <string.h>
#include <stdlib.h>

void QGroup::assign(int mm,int seed)
{
  m=mm;
  #define numsmallprimes 46
  int small_primes[numsmallprimes]= 
     { 2, 3, 5, 7,11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
      73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,
     179,181,191,193,197,199};

  /* Create list of prime basic generators */
  vector<int> pr(m);
  int npr=0;
  for (int i=0; i<numsmallprimes; i++)
    { int p=small_primes[i];
      if (gcd(p,m)==1 && p<m)
	{ pr[npr]=p;
          npr++;
        }
    }
  matrix A(npr*2, vector<bigint>(npr));
  int i,j,te,ord,e;

  /* Basic relations...*/
  for (i=0; i<npr; i++)
    { for (j=0; j<npr; j++) { A[i][j]=0; } // initialize all to zero
      ord=1;
      te=pr[i];
      while (te!=1) { te=(te*pr[i])%m; ord++; }
      A[i][i]=ord;  // A[i][i] is the order of the i'th prime in (Z/mZ)^*
    }

  /* We want the quotient by G_2 so we set 2=1 in the group */
  A[0][0]=1;

  /* Set of random relations, but not really random as
   *   we want this to be deterministic, so each client generates
   *   the same data
   */
  srand(seed);
  i=0;
  while (i<npr)
     { te=1;
       for (j=0; j<npr; j++)
         { e=rand()%m;
	   te=(te*powerMod(pr[j],e,m))%m;
           A[i+npr][j]=e;
         }
       j=0;
       while (j<npr && te!=1)
         { while ((te%pr[j])==0)
             { te=te/pr[j];
               A[i+npr][j]=A[i+npr][j]-1;
             }
           j++;
	 }
      if (te==1) { i++; }
    }
  //cout << "Created matrix: Applying SNF" << endl;

  // S = U*A*V
  matrix S,V,Vi;
  SNF(S,A,V);

  Vi=inv(V);

  bool verbose = OnlineOptions::singleton.has_option("verbose_he_setup");
  if (verbose)
    cout << "Quotient Group Generators :\n";
  g.resize(npr); d.resize(npr);
  ngen=0;  Gord=1;
  bigint temp;
  for (i=0; i<npr; i++)
    { if (S[i][i]!=1)
	{ temp=1;
          for (j=0; j<npr; j++)
            { temp=(temp*powerMod(pr[j],Vi[i][j],m))%m; }
          g[ngen]=mpz_get_ui(temp.get_mpz_t());
          d[ngen]=mpz_get_ui(S[i][i].get_mpz_t());
	  Gord=Gord*d[ngen];
	  if (verbose)
	    cout << "\t(" << g[ngen] << "," << d[ngen] << ")" << endl;
          ngen++;
        }
    }
  
  elems.resize(Gord);
  for (i=0; i<Gord; i++)
    { elems[i]=-1; }
}



/* Dynamically fills in the array as we proceed */
int QGroup::nth_element(int n) const
{
  if (elems[n]!=-1) { return elems[n]; }

  // Go backwards, so biggest subgroup enumerated first
  int i,nn=n,elem=1;
  for (i=ngen-1; i>=0; i--)
    { int ei=nn%d[i];
      nn=(nn-ei)/d[i];
      elem=(elem*powerMod(g[i],ei,m))%m; 
    }
  elems[n]=elem;
  return elem;
}
