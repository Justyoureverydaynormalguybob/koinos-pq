// Times keypair / sign / verify for one PQClean scheme. Compiled once per scheme with -DAPI_H and -DNS.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include API_H
#define CAT_(a,b) a##b
#define CAT(a,b) CAT_(a,b)
#define F(x) CAT(NS, x)
#ifdef CTXAPI
#define SIGN(s,sl,m,ml,k) F(crypto_sign_signature)(s,sl,m,ml,NULL,0,k)
#define VERIFY(s,sl,m,ml,k) F(crypto_sign_verify)(s,sl,m,ml,NULL,0,k)
#else
#define SIGN(s,sl,m,ml,k) F(crypto_sign_signature)(s,sl,m,ml,k)
#define VERIFY(s,sl,m,ml,k) F(crypto_sign_verify)(s,sl,m,ml,k)
#endif
#ifndef N
#define N 500
#endif
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1e6 + t.tv_nsec/1e3; }
static int cmp(const void*a,const void*b){ double x=*(double*)a,y=*(double*)b; return x<y?-1:x>y; }
int main(void){
  size_t pkl=F(CRYPTO_PUBLICKEYBYTES), skl=F(CRYPTO_SECRETKEYBYTES), sgl=F(CRYPTO_BYTES);
  unsigned char *pk=malloc(N*pkl), *sk=malloc(N*skl), *sig=malloc(N*sgl), msg[34];
  size_t *siglen=malloc(N*sizeof(size_t));
  double *t=malloc(N*sizeof(double)); double a;
  for(int i=0;i<34;i++) msg[i]=(unsigned char)(0x12+i);
  for(int i=0;i<N;i++){ a=now(); F(crypto_sign_keypair)(pk+i*pkl, sk+i*skl); t[i]=now()-a; }
  qsort(t,N,sizeof(double),cmp); double kg=t[N/2];
  for(int i=0;i<N;i++){ msg[33]=(unsigned char)i; a=now(); SIGN(sig+i*sgl,&siglen[i],msg,34,sk+i*skl); t[i]=now()-a; }
  qsort(t,N,sizeof(double),cmp); double sg=t[N/2];
  int ok=0; double tot=0;
  for(int r=0;r<3;r++) for(int i=0;i<N;i++){ msg[33]=(unsigned char)i; a=now(); int rc=VERIFY(sig+i*sgl,siglen[i],msg,34,pk+i*pkl); double d=now()-a; if(r==2){t[i]=d; tot+=d;} ok+= (rc==0); }
  qsort(t,N,sizeof(double),cmp);
  // tamper check
  sig[5]^=1; int bad=VERIFY(sig,siglen[0],msg,34,pk);
  printf("%-28s pk=%5zu sig=%5zu | keygen %8.1f us | sign %8.1f us | verify median %7.1f us  mean %7.1f us | ok=%d/%d tamper_rejected=%s\n",
    STR, pkl, sgl, kg, sg, t[N/2], tot/N, ok, 3*N, bad!=0?"yes":"NO");
  return 0;
}
