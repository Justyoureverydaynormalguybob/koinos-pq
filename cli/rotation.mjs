// Key rotation bookkeeping for the key file. Pure functions: no network, no file access.
//
// The rule everything here follows: A SEED IS NEVER DELETED. A signed rotation stays valid until
// its nonce is used, so "the on-chain key is still the old one" does not mean the rotation failed;
// it can land minutes or days later (a node may even hold it back on purpose). If the tool had
// thrown the new seed away by then, the account would answer to a key nobody has, and after `lock`
// nothing can undo that. So:
//
//  * a rotation's seed is saved as pendingSeedHex together with the signed transaction, its id and
//    its nonce (pendingTx), before anything is broadcast;
//  * while the account's nonce is below that nonce the rotation is still open ("waiting"): the same
//    signed bytes are sent again, never a new transaction;
//  * once the nonce has been used, the on-chain key decides: it is the pending key (the rotation
//    landed) or it is not (the rotation can never land any more);
//  * a seed that is no longer current or pending moves to pq.retiredSeeds, with a date and a reason;
//  * if the on-chain key ever turns out to belong to a kept seed, that seed is made current again.
//
// pq fields used here: seedHex, publicKeyHex, publicKeySha256, previousSeedHex?, rotatedAt?,
// pendingSeedHex?, pendingSince?, pendingTx? { id, nonce, payer, tx }, retiredSeeds? [{ seedHex,
// publicKeySha256, retiredAt, reason }].

/** The nonce in a transaction header: base64url of a value_type message holding one varint. */
export function headerNonce(nonceB64url) {
  const b = Buffer.from(String(nonceB64url), "base64url");
  if (b.length < 2 || (b[0] & 7) !== 0) throw new Error("transaction nonce is not a varint value");
  let v = 0n, shift = 0n, i = 1;
  for (;;) {
    if (i >= b.length) throw new Error("transaction nonce is cut short");
    const c = b[i++];
    v |= BigInt(c & 0x7f) << shift;
    shift += 7n;
    if (c < 0x80) break;
    if (shift > 63n) throw new Error("transaction nonce is too long");
  }
  if (i !== b.length) throw new Error("transaction nonce has trailing bytes");
  return v;
}

/** What to record next to pendingSeedHex for a signed rotation transaction. */
export function pendingRecord(tx) {
  return { id: tx.id, nonce: headerNonce(tx.header.nonce).toString(), payer: tx.header.payer, tx };
}

/** Every seed the key file holds, in a fixed order, without duplicates. */
export function allSeeds(pq) {
  const out = [];
  const add = (s) => { if (s && !out.includes(s)) out.push(s); };
  add(pq.seedHex); add(pq.pendingSeedHex); add(pq.previousSeedHex);
  for (const r of pq.retiredSeeds || []) add(r && r.seedHex);
  return out;
}

function retire(pq, seedHex, reason, { keyOf, now }) {
  if (!seedHex) return pq;
  const list = [...(pq.retiredSeeds || [])];
  if (seedHex !== pq.seedHex && seedHex !== pq.previousSeedHex && !list.some((r) => r.seedHex === seedHex)) {
    list.push({ seedHex, publicKeySha256: keyOf(seedHex).sha256, retiredAt: now, reason });
  }
  return { ...pq, retiredSeeds: list };
}
function dropPendingFields(pq) {
  const { pendingSeedHex, pendingSince, pendingTx, ...rest } = pq;
  return rest;
}
/** `seedHex` becomes current; the seed it replaces becomes previousSeedHex; nothing is lost. */
function makeCurrent(pq, seedHex, why, env) {
  const { keyOf, now } = env;
  const old = { current: pq.seedHex, previous: pq.previousSeedHex };
  const key = keyOf(seedHex);
  let next = { ...pq, seedHex, publicKeyHex: key.hex, publicKeySha256: key.sha256, previousSeedHex: old.current, rotatedAt: now };
  // the seed that was "previous" has nowhere left to sit: keep it in the list
  if (old.previous && old.previous !== seedHex) next = retire(next, old.previous, `was the previous seed when ${why}`, env);
  // a seed is listed in one place only
  next.retiredSeeds = (next.retiredSeeds || []).filter((r) => r.seedHex !== seedHex && r.seedHex !== next.previousSeedHex);
  if (!next.retiredSeeds.length) delete next.retiredSeeds;
  if (next.previousSeedHex === seedHex) delete next.previousSeedHex;
  return next;
}

/**
 * Brings the key file's pq section in line with the chain. Returns { pq, action, message }.
 *
 *   onchainKeyHex  the registered ML-DSA-44 public key as hex, "" when none is registered
 *   accountNonce   the account's nonce as the chain reports it (the last nonce used)
 *   keyOf(seedHex) -> { hex, sha256 } of that seed's public key
 *   now            ISO date string
 *
 * action:
 *   "none"      nothing pending, on-chain key is the current seed's (or no key is registered yet)
 *   "promoted"  the pending rotation landed: the pending seed is now current
 *   "waiting"   the pending rotation can still land: resend the SAME signed transaction, change nothing
 *   "retired"   the pending rotation can never land (its nonce was used, or there is no record of it and
 *               the chain still has the current key): its seed moved to retiredSeeds
 *   "restored"  the on-chain key belongs to a kept seed (previous or retired): it is current again
 *   "unknown"   the on-chain key belongs to no seed in the file: nothing changed, stop
 * The returned pq always holds every seed the given pq held.
 */
export function settle(pq, { onchainKeyHex, accountNonce, keyOf, now = new Date().toISOString() }) {
  const env = { keyOf, now };
  const onchain = String(onchainKeyHex || "").toLowerCase();
  const is = (seedHex) => !!seedHex && !!onchain && keyOf(seedHex).hex.toLowerCase() === onchain;
  const pending = pq.pendingSeedHex;
  const rec = pq.pendingTx && pq.pendingTx.nonce !== undefined ? pq.pendingTx : null;
  const done = (next, action, message) => check(pq, { pq: next, action, message });

  if (!onchain) {
    // No key registered: a rotation cannot have been sent (register refuses to rotate then).
    return done(pq, pending ? "unknown" : "none",
      pending ? "the key file has a pending seed but the account has no key registered; nothing was changed" : "");
  }
  if (is(pending)) {
    const next = makeCurrent(dropPendingFields(pq), pending, "a rotation landed", env);
    return done(next, "promoted", `the pending rotation is on chain: the pending seed (key sha256 ${keyOf(pending).sha256}) is now current`);
  }
  if (is(pq.seedHex)) {
    if (!pending) return done(pq, "none", "");
    if (rec) {
      const used = BigInt(accountNonce) >= BigInt(rec.nonce);
      if (!used) {
        return done(pq, "waiting",
          `a rotation (tx ${rec.id}, nonce ${rec.nonce}) is not on chain yet and can still land: the account's nonce is ${accountNonce}`);
      }
      const next = retire(dropPendingFields(pq), pending,
        `rotation tx ${rec.id} can never land: nonce ${rec.nonce} was used and the on-chain key stayed the same`, env);
      return done(next, "retired",
        `the pending rotation can no longer land (nonce ${rec.nonce} was used, the on-chain key did not change); its seed was moved to retiredSeeds, not deleted`);
    }
    const next = retire(dropPendingFields(pq), pending,
      `rotation started ${pq.pendingSince || "earlier"} by an older version of this tool, which kept no record of its transaction; the on-chain key was still the current seed's when this was written`, env);
    return done(next, "retired",
      "a pending seed without a transaction record (from an older version of this tool) was moved to retiredSeeds, not deleted; if its rotation still lands, the next `register` makes it current again");
  }
  const kept = [pq.previousSeedHex, ...(pq.retiredSeeds || []).map((r) => r.seedHex)].find(is);
  if (kept) {
    let next = dropPendingFields(pq);
    // a pending rotation was signed by a key the chain no longer has, so it cannot be authorised
    if (pending) next = retire(next, pending, `rotation ${rec ? `tx ${rec.id} ` : ""}was signed by a key that is no longer the on-chain key`, env);
    next = makeCurrent(next, kept, "a kept seed turned out to be the on-chain key", env);
    return done(next, "restored", `the on-chain key belongs to a kept seed (key sha256 ${keyOf(kept).sha256}), which is now current again`);
  }
  return done(pq, "unknown", "the on-chain key belongs to no seed in the key file; nothing was changed");
}

/** Refuses to hand back a pq section that lost a seed. A bug here must fail loudly, not quietly. */
function check(before, result) {
  const after = allSeeds(result.pq);
  for (const s of allSeeds(before)) {
    if (!after.includes(s)) throw new Error("internal error: a seed would have been dropped from the key file; nothing was changed");
  }
  return result;
}

/** pq with a new rotation recorded as pending (seed and signed transaction together). */
export function startRotation(pq, newSeedHex, tx, now = new Date().toISOString()) {
  if (pq.pendingSeedHex) throw new Error("a rotation is already pending; settle it first");
  return { ...pq, pendingSeedHex: newSeedHex, pendingSince: now, pendingTx: pendingRecord(tx) };
}
