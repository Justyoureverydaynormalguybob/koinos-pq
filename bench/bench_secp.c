// Times libsecp256k1 ECDSA recovery (what koinos recover_public_key does) and signing.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#ifndef N
#define N 500
#endif
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1e6 + t.tv_nsec/1e3; }
static int cmp(const void*a,const void*b){ double x=*(double*)a,y=*(double*)b; return x<y?-1:x>y; }
int main(void){
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  unsigned char sk[N][32], msg[N][32], sig65[N][65]; secp256k1_pubkey pub[N];
  double t[N], a, tot=0; int ok=0;
  FILE *u=fopen("/dev/urandom","rb"); fread(sk,1,sizeof sk,u); fread(msg,1,sizeof msg,u); fclose(u);
  for(int i=0;i<N;i++){ while(!secp256k1_ec_seckey_verify(ctx,sk[i])) sk[i][0]++; secp256k1_ec_pubkey_create(ctx,&pub[i],sk[i]); }
  for(int i=0;i<N;i++){ secp256k1_ecdsa_recoverable_signature rs; int recid; a=now();
    secp256k1_ecdsa_sign_recoverable(ctx,&rs,msg[i],sk[i],NULL,NULL);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,sig65[i]+1,&recid,&rs); sig65[i][0]=27+4+recid; t[i]=now()-a; }
  qsort(t,N,sizeof(double),cmp); double sg=t[N/2];
  for(int r=0;r<3;r++) for(int i=0;i<N;i++){ secp256k1_ecdsa_recoverable_signature rs; secp256k1_pubkey rp; unsigned char out[33]; size_t ol=33; a=now();
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&rs,sig65[i]+1,(sig65[i][0]-27)&3);
    int rc=secp256k1_ecdsa_recover(ctx,&rp,&rs,msg[i]);
    secp256k1_ec_pubkey_serialize(ctx,out,&ol,&rp,SECP256K1_EC_COMPRESSED);
    double d=now()-a; if(r==2){t[i]=d; tot+=d;} ok += rc && !memcmp(&rp,&pub[i],sizeof rp); }
  qsort(t,N,sizeof(double),cmp);
  // plain verify for reference (not what koinos does, but a common comparison)
  for(int i=0;i<N;i++){ secp256k1_ecdsa_recoverable_signature rs; secp256k1_ecdsa_signature s; a=now();
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&rs,sig65[i]+1,(sig65[i][0]-27)&3);
    secp256k1_ecdsa_recoverable_signature_convert(ctx,&s,&rs); secp256k1_ecdsa_verify(ctx,&s,msg[i],&pub[i]); t[i]=now()-a; }
  double sum=0; for(int i=0;i<N;i++) sum+=t[i]; qsort(t,N,sizeof(double),cmp);
  printf("%-28s pk=%5d sig=%5d | keygen %8s    | sign %8.1f us | recover median %6.1f us  mean %7.1f us | ok=%d/%d | plain verify median %.1f us\n",
    "secp256k1 (libsecp256k1)", 33, 65, "-", sg, t[N/2], tot/N, ok, 3*N, t[N/2]);
  return 0;
}
