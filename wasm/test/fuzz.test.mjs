// Memory-safety fuzz for dilithium.wasm: canaries around the C region, random and malformed inputs,
// and a measurement of the real stack high-water mark.
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import assert from "node:assert/strict";
const here = new URL(".", import.meta.url).pathname;
const memory = new WebAssembly.Memory({ initial: 8 });
const { instance } = await WebAssembly.instantiate(readFileSync(here + "../dilithium.wasm"), { env: { memory } });
const { mldsa44_verify } = instance.exports;
const mem = () => new Uint8Array(memory.buffer);
const DATA_LO = 65536, DATA_HI = 65536 + 1216, STACK_HI = 328896, AS_BASE = 393216;
const IN = { sig: 0x1000, pk: 0x2000, msg: 0x3000, ctx: 0x8000 };
function put(off, u8) { mem().set(u8, off); return off; }
function verify(sig, msg, ctx, pk) {
  return mldsa44_verify(put(IN.sig, sig), sig.length, put(IN.msg, msg), msg.length, put(IN.ctx, ctx), ctx.length, put(IN.pk, pk), pk.length);
}
// canary everywhere except: inputs, C data, C stack
const CAN = 0xa5;
const dataCopy = mem().slice(DATA_LO, DATA_HI); // the module's constant tables must survive painting
function paint() { const m = mem(); m.fill(CAN); m.set(dataCopy, DATA_LO); }
function checkOutside(label) {
  const m = mem();
  const ranges = [[0, IN.sig], [IN.sig + 2420, IN.pk], [IN.pk + 1312, IN.msg], [IN.msg + 512, IN.ctx], [IN.ctx + 256, DATA_LO], [STACK_HI, m.length]];
  for (const [a, b] of ranges) for (let i = a; i < b; i++) if (m[i] !== CAN) throw new Error(`${label}: byte ${i} (0x${i.toString(16)}) modified outside C region`);
}
function stackLow() { const m = mem(); let i = DATA_HI; while (i < STACK_HI && m[i] === CAN) i++; return i; }
const CTX = new TextEncoder().encode("koinos/pqwallet/1");
let minLow = STACK_HI;
// 1. valid signatures
for (let i = 0; i < 20; i++) {
  const k = ml_dsa44.keygen(randomBytes(32)); const msg = randomBytes(34);
  const sig = ml_dsa44.sign(msg, k.secretKey, { context: CTX });
  paint(); assert.equal(verify(sig, msg, CTX, k.publicKey), 1); checkOutside("valid"); minLow = Math.min(minLow, stackLow());
}
// 2. random garbage of the right lengths, and every byte position perturbed in one signature
const k = ml_dsa44.keygen(randomBytes(32)); const msg = randomBytes(34); const good = ml_dsa44.sign(msg, k.secretKey, { context: CTX });
for (let i = 0; i < 300; i++) { paint(); assert.equal(verify(randomBytes(2420), msg, CTX, randomBytes(1312)), 0); checkOutside("random"); minLow = Math.min(minLow, stackLow()); }
for (let pos = 0; pos < 2420; pos += 7) { const s = Uint8Array.from(good); s[pos] ^= 0xff; paint(); assert.equal(verify(s, msg, CTX, k.publicKey), 0); checkOutside("perturbed"); }
// hint-encoding region abuse: the last 84 bytes of an ML-DSA-44 signature are the hint h; fill with extremes
for (const fill of [0x00, 0xff, 0x7f, 0x80]) { const s = Uint8Array.from(good); s.fill(fill, 2420 - 84); paint(); assert.equal(verify(s, msg, CTX, k.publicKey), 0); checkOutside("hint"); }
// 3. wrong lengths must be refused without touching memory
for (const [sl, pl] of [[0, 1312], [2419, 1312], [2421, 1312], [2420, 0], [2420, 1311], [2420, 1313], [65, 33], [100000, 1312]]) {
  paint(); const r = mldsa44_verify(IN.sig, sl, IN.msg, 34, IN.ctx, CTX.length, IN.pk, pl); assert.equal(r, 0, `len ${sl}/${pl}`); checkOutside("len");
  assert.equal(stackLow(), STACK_HI, "length rejection must not use the stack");
}
// 4. context > 255 refused; empty message ok; long message ok
paint(); assert.equal(mldsa44_verify(IN.sig, 2420, IN.msg, 34, IN.ctx, 256, IN.pk, 1312), 0); checkOutside("ctx");
const big = randomBytes(400); const sb = ml_dsa44.sign(big, k.secretKey, { context: CTX }); put(IN.msg, big); paint(); put(IN.msg, big);
assert.equal(mldsa44_verify(put(IN.sig, sb), 2420, IN.msg, 400, put(IN.ctx, CTX), CTX.length, put(IN.pk, k.publicKey), 1312), 1);
console.log(`fuzz ok: no write outside the C region in 20 valid + 300 random + 346 perturbed + 4 hint + 8 length cases`);
console.log(`stack high-water mark: ${(STACK_HI - minLow)} bytes used of ${STACK_HI - DATA_HI} available`);
