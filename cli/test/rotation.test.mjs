// Tests cli/rotation.mjs: what happens to the seeds in the key file around a key rotation.
// The one property that matters most: no sequence of events removes a seed from the key file.
// Runs offline (no node is contacted): node cli/test/rotation.test.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { Provider } from "koilib";
import { settle, startRotation, headerNonce, pendingRecord, allSeeds } from "../rotation.mjs";
import { keyOfSeed, keyFile, saveKeys, loadKeys, usePassphrase, hex } from "../lib.mjs";

const NOW = "2026-11-27T12:00:00.000Z";
const seed = () => hex(randomBytes(32));
// a transaction header nonce exactly as koilib builds it (getNextNonce = account nonce + 1)
async function nonceB64(lastUsed) {
  const p = new Provider(["http://127.0.0.1:1"]);
  p.getNonce = async () => lastUsed;
  return p.getNextNonce("x");
}
const txAt = async (lastUsed, id = "0x1220" + hex(randomBytes(32))) => ({ id, header: { payer: "1Account", nonce: await nonceB64(lastUsed), rc_limit: "1" }, operations: [], signatures: ["sig"] });
const pqOf = (seedHex, extra = {}) => { const k = keyOfSeed(seedHex); return { scheme: "ML-DSA-44", seedHex, publicKeyHex: k.hex, publicKeySha256: k.sha256, ...extra }; };
const run = (pq, onchainSeed, accountNonce) => settle(pq, { onchainKeyHex: onchainSeed ? keyOfSeed(onchainSeed).hex : "", accountNonce, keyOf: keyOfSeed, now: NOW });
const holdsAll = (before, after) => { for (const s of allSeeds(before)) assert.ok(allSeeds(after).includes(s), "a seed was lost"); };

// 1. the nonce is read back from a header exactly as koilib wrote it
for (const n of [0, 1, 126, 127, 128, 300, 16383, 16384, 2 ** 32, 2 ** 40]) {
  assert.equal(headerNonce(await nonceB64(n)), BigInt(n) + 1n, `nonce after ${n}`);
}
assert.throws(() => headerNonce(""), /nonce/);
assert.throws(() => headerNonce(Buffer.from([0x28, 0x80]).toString("base64url")), /cut short/);
assert.throws(() => headerNonce(Buffer.from([0x2a, 0x01, 0x01]).toString("base64url")), /varint/);

// 2. the reviewed failure: the run ended before the rotation was in a block, the user runs register again.
//    The on-chain key is still the current seed's. The old code deleted the pending seed here.
{
  const A = seed(), B = seed();
  const tx = await txAt(7); // account nonce 7, so the rotation carries nonce 8
  const pq = startRotation(pqOf(A), B, tx, NOW);
  assert.deepEqual({ id: pq.pendingTx.id, nonce: pq.pendingTx.nonce }, { id: tx.id, nonce: "8" });
  assert.deepEqual(pq.pendingTx.tx, tx, "the signed transaction itself is kept, to be sent again");

  const waiting = run(pq, A, 7);
  assert.equal(waiting.action, "waiting");
  assert.equal(waiting.pq, pq, "nothing changes while the rotation can still land");
  assert.equal(waiting.pq.pendingSeedHex, B);

  // ... and then it lands after all: the pending seed is the account's key and is still there
  const landedLater = run(waiting.pq, B, 8);
  assert.equal(landedLater.action, "promoted");
  assert.equal(landedLater.pq.seedHex, B);
  assert.equal(landedLater.pq.previousSeedHex, A);
  assert.equal(landedLater.pq.publicKeyHex, keyOfSeed(B).hex);
  assert.equal(landedLater.pq.pendingSeedHex, undefined);
  assert.equal(landedLater.pq.pendingTx, undefined);
  holdsAll(pq, landedLater.pq);
  assert.equal(run(landedLater.pq, B, 8).action, "none");
  assert.throws(() => startRotation(pq, seed(), tx), /already pending/);
}

// 3. the nonce was used by another transaction and the key did not change: the rotation is dead,
//    and its seed is kept in the list all the same
{
  const A = seed(), B = seed();
  const pq = startRotation(pqOf(A), B, await txAt(7), NOW);
  const dead = run(pq, A, 8);
  assert.equal(dead.action, "retired");
  assert.equal(dead.pq.seedHex, A);
  assert.equal(dead.pq.pendingSeedHex, undefined);
  assert.equal(dead.pq.retiredSeeds.length, 1);
  assert.equal(dead.pq.retiredSeeds[0].seedHex, B);
  assert.equal(dead.pq.retiredSeeds[0].publicKeySha256, keyOfSeed(B).sha256);
  assert.equal(dead.pq.retiredSeeds[0].retiredAt, NOW);
  assert.match(dead.pq.retiredSeeds[0].reason, /nonce 8 was used/);
  holdsAll(pq, dead.pq);

  // a node that lied about the nonce cannot cost the account: if B is the key after all, B comes back
  const back = run(dead.pq, B, 9);
  assert.equal(back.action, "restored");
  assert.equal(back.pq.seedHex, B);
  assert.equal(back.pq.previousSeedHex, A);
  assert.equal(back.pq.retiredSeeds, undefined, "a seed is listed in one place only");
  holdsAll(dead.pq, back.pq);
}

// 4. a key file written by the older tool: a pending seed with no transaction record
{
  const A = seed(), B = seed();
  const old = pqOf(A, { pendingSeedHex: B, pendingSince: "2026-10-17T10:00:00.000Z" });
  const r = run(old, A, 3);
  assert.equal(r.action, "retired");
  assert.equal(r.pq.retiredSeeds[0].seedHex, B);
  assert.match(r.pq.retiredSeeds[0].reason, /older version/);
  holdsAll(old, r.pq);
  assert.equal(run(r.pq, B, 4).pq.seedHex, B, "and it is found again if that rotation lands");
  assert.equal(run(old, B, 4).action, "promoted", "landed before the next run: promoted as before");
}

// 5. rotating twice: the seed before the previous one moves to the list, it is not overwritten
{
  const A = seed(), B = seed(), C = seed();
  let pq = run(startRotation(pqOf(A), B, await txAt(1), NOW), B, 2).pq;
  pq = startRotation(pq, C, await txAt(2), NOW);
  const r = run(pq, C, 3);
  assert.equal(r.action, "promoted");
  assert.deepEqual([r.pq.seedHex, r.pq.previousSeedHex, r.pq.retiredSeeds.map((x) => x.seedHex)], [C, B, [A]]);
  // the chain shows the oldest key again (say a restore from backup elsewhere): A comes back from the list
  const back = run(r.pq, A, 4);
  assert.equal(back.action, "restored");
  assert.equal(back.pq.seedHex, A);
  holdsAll(r.pq, back.pq);
}

// 6. a key that belongs to no seed in the file: stop, change nothing
{
  const A = seed(), B = seed();
  const pq = startRotation(pqOf(A), B, await txAt(7), NOW);
  const r = run(pq, seed(), 9);
  assert.equal(r.action, "unknown");
  assert.equal(r.pq, pq);
  assert.equal(run(pqOf(A), null, 0).action, "none", "no key registered and nothing pending");
  assert.equal(run(pq, null, 0).action, "unknown", "no key registered but a pending seed: left alone");
  assert.equal(run(pq, null, 0).pq, pq);
}

// 7. a pending rotation signed by a key the chain no longer has: kept, and the on-chain seed made current
{
  const A = seed(), B = seed(), P = seed();
  let pq = run(startRotation(pqOf(A), B, await txAt(1), NOW), B, 2).pq; // current B, previous A
  pq = startRotation(pq, P, await txAt(2), NOW);
  const r = run(pq, A, 5);
  assert.equal(r.action, "restored");
  assert.equal(r.pq.seedHex, A);
  holdsAll(pq, r.pq);
  assert.ok(allSeeds(r.pq).includes(P) && allSeeds(r.pq).includes(B));
}

// 8. no sequence of chain answers loses a seed (800 random walks over rotations, landings, lies)
{
  let steps = 0;
  for (let w = 0; w < 800; w++) {
    let pq = pqOf(seed());
    const ever = new Set(allSeeds(pq));
    let nonce = 0;
    for (let i = 0; i < 8; i++) {
      const roll = randomBytes(1)[0] % 6;
      if (roll === 0 && !pq.pendingSeedHex) {
        const s = seed(); ever.add(s);
        pq = startRotation(pq, s, await txAt(nonce), NOW);
      } else if (roll === 1 && !pq.pendingSeedHex) {
        const s = seed(); ever.add(s); // an older tool's pending seed, no record
        pq = { ...pq, pendingSeedHex: s, pendingSince: NOW };
      } else {
        const all = [...ever];
        const onchain = roll === 5 ? seed() : all[randomBytes(1)[0] % all.length]; // any seed ever held, or a stranger
        nonce += randomBytes(1)[0] % 3;
        pq = run(pq, onchain, nonce).pq;
      }
      for (const s of ever) assert.ok(allSeeds(pq).includes(s), `walk ${w} step ${i}: a seed was lost`);
      assert.equal(new Set(allSeeds(pq)).size, [pq.seedHex, pq.pendingSeedHex, pq.previousSeedHex, ...(pq.retiredSeeds || []).map((r) => r.seedHex)].filter(Boolean).length, "a seed is listed twice");
      assert.equal(pq.publicKeyHex, keyOfSeed(pq.seedHex).hex, "publicKeyHex belongs to the current seed");
      steps++;
    }
  }
  console.log(`rotation: ${steps} random steps, no seed lost`);
}

// 9. in an encrypted key file the kept seeds are inside the encrypted part, and survive a round trip
{
  const net = `selftest-${process.pid}`;
  const f = keyFile(net);
  try {
    const A = seed(), B = seed(), C = seed();
    const tx = await txAt(4);
    const pq = { ...startRotation(pqOf(A), B, tx, NOW), retiredSeeds: [{ seedHex: C, publicKeySha256: keyOfSeed(C).sha256, retiredAt: NOW, reason: "test" }] };
    usePassphrase(net, "correct horse battery staple");
    saveKeys(net, { network: net, account: { address: "1Account", wif: "5Kwif" }, pq });
    const raw = readFileSync(f, "utf8");
    for (const secret of [A, B, C, "5Kwif"]) assert.ok(!raw.includes(secret), "a secret is readable in the encrypted key file");
    assert.ok(raw.includes(tx.id), "the pending transaction id stays readable");
    const back = await loadKeys(net);
    assert.deepEqual(back.pq, pq);
  } finally {
    if (existsSync(f)) rmSync(f);
  }
}
assert.deepEqual(Object.keys(pendingRecord(await txAt(0))), ["id", "nonce", "payer", "tx"]);
console.log("rotation: all checks passed");
