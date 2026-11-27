// Registers the ML-DSA-44 public key on the contract, with a proof of possession (the new key
// signs the account address). Authorised by the secp256k1 key the first time (bootstrap), or by
// the current ML-DSA key afterwards.
//
// --rotate generates a fresh seed, builds and signs the rotation, and writes the seed AND the
// signed transaction (id, nonce) to the key file as pending BEFORE anything is broadcast. The new
// seed becomes current only when the chain shows its key.
//
// A seed is never deleted. A signed rotation stays valid until its nonce is used, so a run that
// ended before the transaction was in a block (a timeout, Ctrl-C) may still land later. The next
// run therefore looks at the account's nonce and the on-chain key (cli/rotation.mjs):
//   nonce not used yet      the rotation is still open: the SAME signed bytes are sent again
//   nonce used, new key     the rotation landed: the pending seed becomes current
//   nonce used, old key     the rotation can never land: its seed moves to retiredSeeds (kept)
// and if the on-chain key ever belongs to a kept seed, that seed is made current again.
//
// Exit 0: done. Exit 1: refused or an error. Exit 3: a rotation is still open; run this again.
import { randomBytes } from "node:crypto";
import { network, loadKeys, saveKeys, pqContract, pqKeysFromSeed, keyOfSeed, Signer, waitMined, buildTransaction, submitOnce, pqSignTxId, pqProofOfPossession, b64url, hex, sha256, utils, contractMetadata, sleep } from "./lib.mjs";
import { settle, startRotation } from "./rotation.mjs";

const net = network();
let k = await loadKeys(net.name);
const address = k.account.address;
const c = pqContract(net, address);
const rotate = process.argv.includes("--rotate");
const first = (e) => String((e && e.message) || e).split("\n")[0].slice(0, 200);

/** The nonce is read BEFORE the key: if a rotation lands in between, it reads as "still open", never as "dead". */
async function chainState() {
  const accountNonce = await net.provider.getNonce(address);
  const info = (await c.functions.get_info()).result;
  const onchainKeyHex = info.key_registered ? hex(utils.decodeBase64url((await c.functions.get_public_key()).result.value)) : "";
  return { info, onchainKeyHex, accountNonce };
}
/** Applies what the chain says to the key file. Saves only when something moved; never removes a seed. */
async function settleWithChain() {
  const st = await chainState();
  const r = settle(k.pq, { onchainKeyHex: st.onchainKeyHex, accountNonce: st.accountNonce, keyOf: keyOfSeed });
  if (r.pq !== k.pq) { k = { ...k, pq: r.pq }; saveKeys(net.name, k); }
  if (r.message) console.log(r.message);
  return { ...st, action: r.action };
}
/**
 * Waits until the account's nonce has reached `nonce`, that is until the rotation's transaction, or
 * another one with the same nonce, is in a block. This is the test that matters (after it the
 * on-chain key decides), and unlike looking for the transaction in new blocks it also works when
 * the transaction was mined before this run started.
 */
async function waitNonceUsed(nonce, timeoutMs = Number(process.env.KOINOS_PQ_WAIT_MS) || 120000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    try { if (BigInt(await net.provider.getNonce(address)) >= BigInt(nonce)) return true; } catch { /* the node did not answer: keep waiting */ }
    if (Date.now() >= end) return false;
    await sleep(Math.min(3000, Math.max(200, timeoutMs / 10)));
  }
}
function stillOpen(rec, why) {
  console.error(`the rotation is still open${why ? ` (${why})` : ""}.`);
  console.error(`Its seed is kept in the key file as pendingSeedHex. Transaction ${rec.id} stays valid until nonce ${rec.nonce} of this account is used.`);
  console.error("Run `npm run register` again later: it sends the same signed transaction again and finishes the rotation when it is in a block.");
  console.error("To cancel it instead, send any other transaction from this account (for example a small `npm run send`); that uses the nonce, and the next `register` moves the unused seed to retiredSeeds.");
  process.exit(3);
}

// ---- settle a rotation that an earlier run left open ----
let st = await settleWithChain();
if (st.action === "unknown") {
  console.error("stopping: the registered key matches no seed in the key file (current, pending, previous or retired). Nothing was sent and nothing was changed.");
  process.exit(1);
}
if (st.action === "waiting") {
  const rec = k.pq.pendingTx;
  if (!rec.tx) stillOpen(rec, "the key file has no copy of the signed transaction to send again");
  console.log("sending the same signed transaction again (never a new one)");
  try {
    await submitOnce(net, rec.tx);
  } catch (e) {
    // A node that already holds it may refuse the copy; that is not a verdict on the rotation.
    console.log(`the node did not take it this time: ${first(e)}`);
  }
  console.log(`waiting for nonce ${rec.nonce} to be used`);
  if (!(await waitNonceUsed(rec.nonce))) stillOpen(rec, `nonce ${rec.nonce} is still unused`);
  st = await settleWithChain();
  if (st.action === "waiting") stillOpen(rec, "the node does not show it yet");
}
if (st.action !== "none") {
  // Something was settled. Stop here even with --rotate, so that an interrupted `register --rotate`
  // run a second time finishes that one rotation instead of stacking another on top of it.
  await lockReminder();
  if (rotate) console.log("no new rotation was started; run `npm run register -- --rotate` again if you still want one");
  process.exit(0);
}

// ---- register (first time, or again), or rotate ----
const info = st.info;
if (rotate && !info.key_registered) { console.error("nothing to rotate: no key registered yet"); process.exit(1); }
const current = pqKeysFromSeed(k.pq.seedHex);
const newSeedHex = rotate ? hex(randomBytes(32)) : k.pq.seedHex;
const next = pqKeysFromSeed(newSeedHex);
const proof = pqProofOfPossession(address, next.secretKey);

const { operation } = await c.functions.set_public_key(
  { public_key: utils.encodeBase64url(next.publicKey), proof: utils.encodeBase64url(proof) },
  { onlyOperation: true }
);
const tx = await buildTransaction(net, address, [operation], process.env.RC_LIMIT);
if (!info.key_registered) {
  console.log("no key registered yet: bootstrapping with the secp256k1 signature");
  const signer = Signer.fromWif(k.account.wif);
  tx.signatures = (await signer.signTransaction(tx)).signatures;
} else {
  console.log(rotate ? "rotating to a fresh key, authorised by the current ML-DSA-44 key" : "re-registering the same key, authorised by the current ML-DSA-44 key");
  tx.signatures = [b64url(pqSignTxId(tx.id, current.secretKey))];
}
if (rotate) {
  // Seed and signed transaction go into the key file together, and are read back, before the
  // transaction leaves this machine.
  k = { ...k, pq: startRotation(k.pq, newSeedHex, tx) };
  saveKeys(net.name, k);
  const back = await loadKeys(net.name);
  if (back.pq.pendingSeedHex !== newSeedHex || !back.pq.pendingTx || back.pq.pendingTx.id !== tx.id) {
    console.error("the key file did not read back with the new seed in it; nothing was sent");
    process.exit(1);
  }
  console.log(`new seed saved as pendingSeedHex (key sha256 ${hex(sha256(next.publicKey))}) with its transaction ${tx.id}, nonce ${k.pq.pendingTx.nonce}; sending it`);
}
if (!rotate) {
  const { receipt } = await submitOnce(net, tx);
  if (receipt) {
    console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
    console.log(`mined in block ${await waitMined(net, tx.id)}`);
  }
} else {
  const rec = k.pq.pendingTx;
  try {
    const { receipt } = await submitOnce(net, tx);
    if (receipt) console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
  } catch (e) {
    // Refused or unanswered: either way the signed transaction exists and may still land.
    stillOpen(rec, first(e));
  }
  console.log(`waiting for nonce ${rec.nonce} to be used`);
  if (!(await waitNonceUsed(rec.nonce))) stillOpen(rec, `nonce ${rec.nonce} is still unused`);
  // The chain decides, not the fact that the transaction was in a block (it can be there reverted).
  st = await settleWithChain();
  if (st.action === "waiting") stillOpen(rec, "the node does not show it yet");
  if (st.action !== "promoted") {
    console.error("the rotation did not take effect; the key file was brought in line with the chain (see above) and no seed was deleted");
    process.exit(1);
  }
  console.log("key file updated: the new seed is current, the one before it is kept as previousSeedHex");
}
console.log(`registered ML-DSA-44 key sha256 ${hex(sha256(next.publicKey))}`);
await lockReminder();

/** Until upload authority is the contract's, the secp256k1 key can still replace the contract. */
async function lockReminder() {
  const m = await contractMetadata(net, address).catch(() => null);
  if (m && !m.authorizes_upload_contract) {
    console.warn("WARNING: this account is NOT locked. Its old secp256k1 key can still replace the contract, and with it the ML-DSA-44 key just registered.");
    console.warn("         The public key of that secp256k1 key is on the chain. Run `npm run lock` now unless this is a test account you mean to leave open.");
  }
}
