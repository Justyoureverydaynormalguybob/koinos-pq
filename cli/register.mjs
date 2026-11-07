// Registers the ML-DSA-44 public key on the contract, with a proof of possession (the new key
// signs the account address). Authorised by the secp256k1 key the first time (bootstrap), or by
// the current ML-DSA key afterwards.
//
// --rotate generates a fresh seed, writes it to the key file as pendingSeedHex BEFORE anything is
// broadcast, registers its key under the current key's authority, and only then makes it current
// (old seed kept as previousSeedHex until you delete it). If the process dies in between, the next
// run compares the on-chain key with the current and pending seeds and finishes or discards the
// rotation. Without the pending step a mined rotation whose seed was never written would have
// locked the account out for good: after `lock` there is no secp256k1 fallback.
import { randomBytes } from "node:crypto";
import { network, loadKeys, saveKeys, pqContract, pqKeysFromSeed, Signer, waitMined, buildTransaction, submitOnce, pqSignTxId, pqProofOfPossession, b64url, hex, sha256, utils } from "./lib.mjs";

const net = network();
let k = await loadKeys(net.name);
const address = k.account.address;
const c = pqContract(net, address);
const info = (await c.functions.get_info()).result;
const rotate = process.argv.includes("--rotate");
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));

// ---- finish or discard a rotation that was interrupted ----
if (k.pq.pendingSeedHex) {
  const onchain = info.key_registered ? utils.decodeBase64url((await c.functions.get_public_key()).result.value) : new Uint8Array(0);
  const pending = pqKeysFromSeed(k.pq.pendingSeedHex);
  if (same(onchain, pending.publicKey)) {
    k = promote(k, k.pq.pendingSeedHex);
    saveKeys(net.name, k);
    console.log(`finished an interrupted rotation: the pending seed is the on-chain key (${hex(sha256(pending.publicKey))}) and is now current`);
    if (!rotate) process.exit(0);
  } else if (same(onchain, pqKeysFromSeed(k.pq.seedHex).publicKey)) {
    const { pendingSeedHex, pendingSince, ...pq } = k.pq;
    k = { ...k, pq };
    saveKeys(net.name, k);
    console.log("dropped a pending seed whose rotation never reached the chain");
  } else {
    console.error("the key file has a pending seed, and the on-chain key matches neither it nor the current seed; stopping");
    process.exit(1);
  }
}

const current = pqKeysFromSeed(k.pq.seedHex);
if (rotate && !info.key_registered) { console.error("nothing to rotate: no key registered yet"); process.exit(1); }
const newSeedHex = rotate ? hex(randomBytes(32)) : k.pq.seedHex;
const next = pqKeysFromSeed(newSeedHex);
if (rotate) {
  k = { ...k, pq: { ...k.pq, pendingSeedHex: newSeedHex, pendingSince: new Date().toISOString() } };
  saveKeys(net.name, k);
  console.log(`new seed saved as pendingSeedHex (key sha256 ${hex(sha256(next.publicKey))}); registering it`);
}
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
const { receipt } = await submitOnce(net, tx);
if (receipt) console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
console.log(`mined in block ${await waitMined(net, tx.id)}`);
if (rotate) {
  saveKeys(net.name, promote(k, newSeedHex));
  console.log("key file updated: the new seed is current, the previous one is kept as previousSeedHex");
}
console.log(`registered ML-DSA-44 key sha256 ${hex(sha256(next.publicKey))}`);

/** The key file with `seedHex` made current and any pending seed cleared. */
function promote(keys, seedHex) {
  const pk = pqKeysFromSeed(seedHex).publicKey;
  const { pendingSeedHex, pendingSince, ...pq } = keys.pq;
  return { ...keys, pq: { ...pq, seedHex, publicKeyHex: hex(pk), publicKeySha256: hex(sha256(pk)), previousSeedHex: keys.pq.seedHex, rotatedAt: new Date().toISOString() } };
}
