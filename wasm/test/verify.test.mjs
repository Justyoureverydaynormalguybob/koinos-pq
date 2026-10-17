// Tests wasm/dilithium.wasm: (1) NIST ACVP ML-DSA-44 sigVer vectors, (2) cross-check with @noble/post-quantum.
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import assert from "node:assert/strict";

const here = new URL(".", import.meta.url).pathname;
const bytes = readFileSync(here + "../dilithium.wasm");
const memory = new WebAssembly.Memory({ initial: 64 });
const { instance } = await WebAssembly.instantiate(bytes, { env: { memory } });
const { mldsa44_verify, mldsa44_sizes } = instance.exports;
const sizes = mldsa44_sizes();
assert.equal(sizes >>> 16, 2420, "signature size");
assert.equal(sizes & 0xffff, 1312, "public key size");

// scratch region well below the module's own data at 2 MiB
const OFF = { sig: 0x1000, pk: 0x2000, msg: 0x3000, ctx: 0x8000 };
function put(off, u8) { new Uint8Array(memory.buffer, off, u8.length).set(u8); return off; }
function verify(sig, msg, ctx, pk) {
  return mldsa44_verify(put(OFF.sig, sig), sig.length, put(OFF.msg, msg), msg.length,
                        put(OFF.ctx, ctx), ctx.length, put(OFF.pk, pk), pk.length) === 1;
}
const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));

// 1. NIST vectors
const acvp = JSON.parse(readFileSync(here + "acvp-mldsa44-sigver.json", "utf8"));
let pass = 0;
for (const t of acvp.tests) {
  const got = verify(hex(t.signature), hex(t.message), hex(t.context), hex(t.pk));
  assert.equal(got, t.testPassed, `ACVP tcId ${t.tcId} (${t.reason})`);
  pass++;
}
console.log(`ACVP ML-DSA-44 sigVer: ${pass}/${acvp.tests.length} vectors agree (incl. ${acvp.tests.filter(t=>!t.testPassed).length} must-reject cases)`);

// 2. noble cross-check: noble signs, wasm verifies; plus tamper cases
const CTX = new TextEncoder().encode("koinos/pqwallet/1");
let n = 0, t0 = performance.now();
for (let i = 0; i < 25; i++) {
  const seed = randomBytes(32);
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const msg = i % 2 ? randomBytes(34) : randomBytes(1 + (i * 37) % 300); // 34 = Koinos tx id multihash length
  const sig = ml_dsa44.sign(msg, secretKey, { context: CTX });
  assert.equal(ml_dsa44.verify(sig, msg, publicKey, { context: CTX }), true);
  assert.equal(verify(sig, msg, CTX, publicKey), true, "valid sig must verify");
  const badSig = Uint8Array.from(sig); badSig[100] ^= 1;
  assert.equal(verify(badSig, msg, CTX, publicKey), false, "flipped sig bit must fail");
  const badMsg = Uint8Array.from(msg); badMsg[0] ^= 1;
  assert.equal(verify(sig, badMsg, CTX, publicKey), false, "changed message must fail");
  assert.equal(verify(sig, msg, new TextEncoder().encode("other"), publicKey), false, "wrong context must fail");
  const other = ml_dsa44.keygen(randomBytes(32)).publicKey;
  assert.equal(verify(sig, msg, CTX, other), false, "wrong key must fail");
  assert.equal(verify(sig.subarray(0, 2419), msg, CTX, publicKey), false, "short sig must fail");
  assert.equal(verify(sig, msg, CTX, publicKey.subarray(0, 1311)), false, "short pk must fail");
  n++;
}
// 3. wasm verifies something noble rejects? (determinism): same inputs twice
console.log(`noble cross-check: ${n} keypairs, 7 assertions each, all agree`);
let reps = 200; const seed = randomBytes(32); const k = ml_dsa44.keygen(seed); const m = randomBytes(34); const s = ml_dsa44.sign(m, k.secretKey, { context: CTX });
t0 = performance.now(); for (let i = 0; i < reps; i++) verify(s, m, CTX, k.publicKey);
console.log(`wasm verify avg (node JIT): ${((performance.now() - t0) / reps).toFixed(3)} ms`);
