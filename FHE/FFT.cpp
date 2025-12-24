
#include "FHE/FFT.h"
#include "Math/Zp_Data.h"
#include "Processor/BaseMachine.h"
#include "Tools/CodeLocations.h"

#include "Math/modp.hpp"


/* Computes the FFT via Horner's Rule
   theta is assumed to be an Nth root of unity
*/
void NaiveFFT(vector<modp>& ans,vector<modp>& a,int N,const modp& theta,const Zp_Data& PrD)
{
  int i,j;
  modp thetaPow;
  assignOne(thetaPow,PrD);
  for (i=0; i<N; i++)
    { ans[i]=a[N-1];
      for (j=N-2; j>=0; j--)
	{ Mul(ans[i],ans[i],thetaPow,PrD);
          Add(ans[i],ans[i],a[j],PrD);
        }
      Mul(thetaPow,thetaPow,theta,PrD); 
    }
}


void FFT(vector<modp>& a,int N,const modp& theta,const Zp_Data& PrD)
{
  CODE_LOCATION_NO_SCOPE

  if (N==1) { return; }

  if (N<5)
    { vector<modp> b(N);
      NaiveFFT(b,a,N,theta,PrD);
      a=b;
      return;
    }

  vector<modp> a0(N/2),a1(N/2);
  int i;
  for (i=0; i<N/2; i++)
    { a0[i]=a[2*i];
      a1[i]=a[2*i+1];
    }
  modp theta2,w,t;
  Sqr(theta2,theta,PrD);
  FFT(a0,N/2,theta2,PrD);
  FFT(a1,N/2,theta2,PrD);
  assignOne(w,PrD);
  for (i=0; i<N/2; i++)
    { Mul(t,w,a1[i],PrD);
      Add(a[i],a0[i],t,PrD);
      Sub(a[i+N/2],a0[i],t,PrD);
      Mul(w,w,theta,PrD);
    }
}


/*
 * Standard FFT for n a power of two, root a n-th primitive root of unity.
 */
template<class T,class P>
void FFT_Iter(vector<T>& ioput, int n, const T& root, const P& PrD)
{
    int i, j, m;
    T t;
    
    // Bit-reversal of input
    for( i = j = 0; i < n; ++i )
    {
        if( j >= i )
        {
            t = ioput[i];
            ioput[i] = ioput[j];
            ioput[j] = t;
        }
        m = n / 2;
        
        while( (m >= 1) && (j >= m) )
        {
            j -= m;
            m /= 2;
        }
        j += m;
    }
    T u, alpha, alpha2;
    
    m = 0; j = 0; i = 0;
    // Do the transform
    for (int s = 1; s < n; s = 2*s)
    {
        m = 2*s;
        Power(alpha, root, n/m, PrD);
        assignOne(alpha2,PrD);
        for (int j = 0; j < m/2; ++j)
        {
            //root = root_table[j*n/m];
            for (int k = j; k < n; k += m)
            {
                Mul(t, alpha2, ioput[k + m/2], PrD);
                u = ioput[k];
                Add(ioput[k], u, t, PrD);
                Sub(ioput[k + m/2], u, t, PrD);
            }
            Mul(alpha2, alpha2, alpha, PrD);
        }
    }
}



/*
 * FFT modulo x^n + 1.
 *
 * n must be a power of two, root a 2n-th primitive root of unity.
 */
void FFT_Iter2(vector<modp>& ioput, int n, const modp& root, const Zp_Data& PrD)
{
    FFT_Iter(ioput, n, root, PrD, false);
}

void FFT_Iter2(vector<modp>& ioput, int n, const vector<modp>& roots,
        const Zp_Data& PrD)
{
    FFT_Iter(ioput, n, roots, PrD, false);
}

void FFT_Iter(vector<modp>& ioput, int n, const modp& root, const Zp_Data& PrD,
        bool start_with_one)
{
    vector<modp> roots(n + 1);
    assignOne(roots[0], PrD);
    for (int i = 1; i < n + 1; i++)
        Mul(roots[i], roots[i - 1], root, PrD);
    FFT_Iter(ioput, n, roots, PrD, start_with_one);
}

void FFT_Iter(vector<modp>& ioput, int n, const vector<modp>& roots,
        const Zp_Data& PrD, bool start_with_one)
{
    CODE_LOCATION_NO_SCOPE

    assert(roots.size() > size_t(n));

    int i, j, m;
    
    // Bit-reversal of input
    for( i = j = 0; i < n; ++i )
    {
        if( j >= i )
        {
            swap(ioput[i], ioput[j]);
        }
        m = n / 2;
        
        while( (m >= 1) && (j >= m) )
        {
            j -= m;
            m /= 2;
        }
        j += m;
    }
    m = 0; j = 0; i = 0;
    // Do the transform
    vector<modp> alpha2;
    alpha2.reserve(n / 2);
    for (int s = 1; s < n; s = 2*s)
    {
        m = 2*s;

        alpha2.clear();
        if (start_with_one)
        {
            for (int j = 0; j < m / 2; j++)
                alpha2.push_back(roots[j * n / m]);
        }
        else
        {
            for (int j = 0; j < m / 2; j++)
                alpha2.push_back(roots.at((j * 2 + 1) * (n / m)));
        }

        if (BaseMachine::thread_num == 0 and BaseMachine::has_singleton())
        {
            auto& queues = BaseMachine::s().queues;
            FftJob job(ioput, alpha2, m, PrD);
            int start = queues.distribute(job, n / 2);
            for (int i = start; i < n / 2; i++)
                FFT_Iter2_body(ioput, alpha2, i, m, PrD);
            if (start > 0)
                queues.wrap_up(job);
        }
        else
            for (int i = 0; i < n / 2; i++)
                FFT_Iter2_body(ioput, alpha2, i, m, PrD);
    }
}


/* This does FFT for X^N+1,
   Input and output is an array of size N (shared)
   alpha is assumed to be a generator of the N'th roots of unity mod p
   Starts at w=alpha and updates by alpha^2
*/
void FFT2(vector<modp>& a, int N, const modp& alpha, const Zp_Data& PrD)
{
  int i;
  if (N==1) { return; }

  vector<modp> a0(N/2),a1(N/2);
  for (i=0; i<N/2; i++)
    { a0[i]=a[2*i];
      a1[i]=a[2*i+1];
    }

  modp w,alpha2,temp;
  Sqr(alpha2,alpha,PrD);
  FFT2(a0,N/2,alpha2,PrD);    FFT2(a1,N/2,alpha2,PrD);

  w=alpha;
  for (i=0; i<N/2; i++)
    { Mul(temp,w,a1[i],PrD);
      Add(a[i],a0[i],temp,PrD);
      Sub(a[i+N/2],a0[i],temp,PrD);
      Mul(w,w,alpha2,PrD);
    }
}


void FFT_non_power_of_two(vector<modp>& res, const vector<modp>& input, const FFT_Data& FFTD)
{
    vector<modp> tmp(FFTD.m());
    BFFT(tmp, input, FFTD);
    for (int i = 0; i < (FFTD).phi_m(); i++)
        res[i] = tmp[(FFTD).p(i)];
}

void BFFT(vector<modp>& ans,const vector<modp>& a,const FFT_Data& FFTD,bool forward)
{
  int k2=FFTD.twop,n=FFTD.m();
  if (k2<0) { k2=-k2; }
  int r=0;
  if (forward==false) { r=1; }

  if (FFTD.twop>0)
     { vector<modp> x(k2);
       for (unsigned int i=0; i<a.size(); i++)
         { Mul(x[i],FFTD.powers[r][i],a[i],FFTD.get_prD()); }
       for (int i=a.size(); i<k2; i++)
         { assignZero(x[i],FFTD.get_prD()); }
       FFT_Iter(x,k2,FFTD.two_root[0],FFTD.get_prD());
     
       for (int i=0; i<k2; i++)
          { Mul(x[i],x[i],FFTD.b[r][i],FFTD.get_prD()); }
     
       FFT_Iter(x,k2,FFTD.two_root[1],FFTD.get_prD());
       
       for (int i=0; i<n; i++)
         { Mul(ans[i],x[i+n-1],FFTD.powers_i[r][i],FFTD.get_prD()); }
     }
  else
     { throw crash_requested(); }
}
