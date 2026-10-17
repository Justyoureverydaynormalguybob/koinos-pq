/* Freestanding support for the wasm32 build: no libc is linked. */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *restrict d, const void *restrict s, size_t n) {
  uint8_t *dp = d; const uint8_t *sp = s;
  while (n--) *dp++ = *sp++;
  return d;
}
void *memmove(void *d, const void *s, size_t n) {
  uint8_t *dp = d; const uint8_t *sp = s;
  if (dp < sp) { while (n--) *dp++ = *sp++; }
  else { dp += n; sp += n; while (n--) *--dp = *--sp; }
  return d;
}
void *memset(void *d, int c, size_t n) {
  uint8_t *dp = d;
  while (n--) *dp++ = (uint8_t)c;
  return d;
}
int memcmp(const void *a, const void *b, size_t n) {
  const uint8_t *x = a, *y = b;
  for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}
/* Signing and key generation are not compiled in; if anything ever reaches
   randombytes() the module traps rather than returning weak randomness. */
void randombytes(uint8_t *out, size_t outlen) { (void)out; (void)outlen; __builtin_trap(); }
