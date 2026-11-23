// Adversarial false-accept test for dilithium.wasm, the one trust anchor of the PQ wallet.
//
// Memory safety is covered by fuzz.test.mjs; this file targets the opposite failure: the verifier
// returning 1 (valid) for anything that is NOT a genuine ML-DSA-44 signature over the given
// (msg, ctx, pk). Each such acceptance would let an outsider move an account without its key.
// The independent @noble/post-quantum implementation is the oracle: for every input, our wasm
// result must equal noble's, and must never be 1 for a tampered artifact. One (ours=1, noble=0)
// fails the run. Mirrors the on-chain attack classes: context confusion (tx vs proof-of-possession),
// tx-id substitution, key replay, and signature-encoding slack.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import assert from "node:assert/strict";

const here = fileURLToPath(new URL("./", import.meta.url));
const memory = new WebAssembly.Memory({ initial: 8 });
const { instance } = await WebAssembly.instantiate(readFileSync(here + "../dilithium.wasm"), { env: { memory } });
const { mldsa44_verify } = instance.exports;
const mem = () => new Uint8Array(memory.buffer);
const IN = { sig: 0x1000, pk: 0x2000, msg: 0x3000, ctx: 0x8000 };
const put = (off, u8) => { mem().set(u8, off); return off; };
function ours(sig, msg, ctx, pk) {
  return mldsa44_verify(put(IN.sig, sig), sig.length, put(IN.msg, msg), msg.length,
                        put(IN.ctx, ctx), ctx.length, put(IN.pk, pk), pk.length);
}
const enc = (s) => new TextEncoder().encode(s);
const CTX  = enc("koinos/pqwallet/1");       // transaction-authorization context
const CTXP = enc("koinos/pqwallet/1/pop");   // proof-of-possession context
function nobleOk(sig, msg, ctx, pk) {
  try { return ml_dsa44.verify(sig, msg, pk, { context: ctx }) ? 1 : 0; } catch { return 0; }
}

let checks = 0, falseAccept = 0, diverge = 0;
// An input expected invalid: must be 0, and must match noble.
function reject(label, sig, msg, ctx, pk) {
  checks++;
  const o = ours(sig, msg, ctx, pk), n = nobleOk(sig, msg, ctx, pk);
  if (o === 1) { falseAccept++; console.log(`FALSE-ACCEPT [${label}] ours=1 noble=${n}`); }
  else if (o !== n) { diverge++; console.log(`DIVERGE [${label}] ours=${o} noble=${n}`); }
}
// An input of unknown validity: only require our wasm to agree with noble.
function agree(label, sig, msg, ctx, pk) {
  checks++;
  const o = ours(sig, msg, ctx, pk), n = nobleOk(sig, msg, ctx, pk);
  if (o !== n) { if (o === 1) falseAccept++; else diverge++; console.log(`DIVERGE [${label}] ours=${o} noble=${n}`); }
}

// genuine artifacts
const keys = [], msgs = [];
for (let i = 0; i < 12; i++) keys.push(ml_dsa44.keygen(randomBytes(32)));
for (let i = 0; i < 12; i++) msgs.push(randomBytes(34)); // koinos tx id = 34-byte sha2-256 multihash
const k0 = keys[0], m0 = msgs[0];
const sigTx  = ml_dsa44.sign(m0, k0.secretKey, { context: CTX });
const popMsg = k0.publicKey.slice(0, 25);
const sigPop = ml_dsa44.sign(popMsg, k0.secretKey, { context: CTXP });
assert.equal(ours(sigTx, m0, CTX, k0.publicKey), 1, "a genuine signature must verify");

// A. context confusion — a proof-of-possession sig must never authorize a transaction, and vice versa
reject("ctx: tx-sig under POP ctx",  sigTx, m0, CTXP, k0.publicKey);
reject("ctx: pop-sig under TX ctx",  sigPop, popMsg, CTX, k0.publicKey);
reject("ctx: empty ctx",             sigTx, m0, new Uint8Array(0), k0.publicKey);
reject("ctx: truncated ctx",         sigTx, m0, CTX.slice(0, CTX.length - 1), k0.publicKey);
reject("ctx: ctx + NUL byte",        sigTx, m0, Uint8Array.from([...CTX, 0]), k0.publicKey);

// B. message (tx-id) substitution
for (let j = 1; j < msgs.length; j++) reject(`msg-swap ${j}`, sigTx, msgs[j], CTX, k0.publicKey);
reject("msg: 1-bit flip", sigTx, (() => { const m = Uint8Array.from(m0); m[7] ^= 1; return m; })(), CTX, k0.publicKey);
reject("msg: empty", sigTx, new Uint8Array(0), CTX, k0.publicKey);

// C. key (account) substitution / replay
for (let j = 1; j < keys.length; j++) reject(`key-swap ${j}`, sigTx, m0, CTX, keys[j].publicKey);
reject("key: 1-bit flip", sigTx, m0, CTX, (() => { const p = Uint8Array.from(k0.publicKey); p[100] ^= 1; return p; })());

// D. degenerate / crafted signatures
reject("sig: all zero", new Uint8Array(2420), m0, CTX, k0.publicKey);
reject("sig: all 0xff", new Uint8Array(2420).fill(0xff), m0, CTX, k0.publicKey);

// E. encoding-slack probe across challenge (c~), z, and hint regions
for (const [lo, hi, step, name] of [[0, 32, 1, "ctilde"], [32, 2420 - 84, 11, "z"], [2420 - 84, 2420, 1, "hint"]]) {
  for (let pos = lo; pos < hi; pos += step) for (const x of [0x01, 0x80, 0xff]) {
    const s = Uint8Array.from(sigTx); s[pos] ^= x;
    agree(`mut-${name}@${pos}^${x.toString(16)}`, s, m0, CTX, k0.publicKey);
  }
}

// F. broad differential: random multi-bit mutations of a valid signature
for (let i = 0; i < 4000; i++) {
  const s = Uint8Array.from(sigTx);
  const n = 1 + (Math.random() * 6 | 0);
  for (let f = 0; f < n; f++) s[(Math.random() * 2420) | 0] ^= (1 << ((Math.random() * 8) | 0));
  agree(`randmut#${i}`, s, m0, CTX, k0.publicKey);
}

// G. fresh valid signatures across many keys (positive agreement)
for (let i = 0; i < 25; i++) {
  const k = keys[i % keys.length], m = randomBytes(34);
  agree(`valid#${i}`, ml_dsa44.sign(m, k.secretKey, { context: CTX }), m, CTX, k.publicKey);
}

const bad = falseAccept + diverge;
assert.equal(falseAccept, 0, `${falseAccept} false-accept(s): the verifier accepted a non-signature`);
assert.equal(diverge, 0, `${diverge} result(s) disagreed with the noble reference`);
console.log(`adv-verify ok: ${checks} checks, 0 false-accepts, 0 divergences from noble ` +
            `(context confusion, tx-id swap, key replay, degenerate sigs, 4000 random + structured mutations)`);
