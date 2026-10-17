/* WASM entry points for ML-DSA-44 verification (FIPS 204, pure mode with context). */
#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "sign.h"

/* Returns 1 if the signature is valid, 0 otherwise. Never traps on bad lengths. */
__attribute__((export_name("mldsa44_verify")))
int32_t mldsa44_verify(const uint8_t *sig, uint32_t siglen,
                       const uint8_t *msg, uint32_t msglen,
                       const uint8_t *ctx, uint32_t ctxlen,
                       const uint8_t *pk, uint32_t pklen) {
  if (siglen != CRYPTO_BYTES || pklen != CRYPTO_PUBLICKEYBYTES || ctxlen > 255) return 0;
  return crypto_sign_verify(sig, siglen, msg, msglen, ctx, ctxlen, pk) == 0 ? 1 : 0;
}

/* (signature bytes << 16) | public key bytes, so callers can assert the parameter set. */
__attribute__((export_name("mldsa44_sizes")))
uint32_t mldsa44_sizes(void) { return ((uint32_t)CRYPTO_BYTES << 16) | (uint32_t)CRYPTO_PUBLICKEYBYTES; }
