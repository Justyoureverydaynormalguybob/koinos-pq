// Registers the ML-DSA-44 public key on the contract, with a proof of possession (the new key
// signs the account address). Authorised by the secp256k1 key the first time (bootstrap), or by
// the current ML-DSA key afterwards. --rotate generates a fresh seed, registers its key under the
// current key's authority, and only then replaces the seed in the key file (old seed kept as
// previousSeedHex until you delete it).
import { randomBytes } from "node:crypto";
import { network, loadKeys, saveKeys, pqContract, pqKeysFromSeed, Signer, waitMined, buildTransaction, submit, pqSignTxId, pqProofOfPossession, b64url, hex, sha256, utils } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const address = k.account.address;
const current = pqKeysFromSeed(k.pq.seedHex);
const c = pqContract(net, address);
const info = (await c.functions.get_info()).result;
const rotate = process.argv.includes("--rotate");
if (rotate && !info.key_registered) { console.error("nothing to rotate: no key registered yet"); process.exit(1); }
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
const { receipt } = await submit(net, tx);
console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
console.log(`mined in block ${await waitMined(net, tx.id)}`);
if (rotate) {
  saveKeys(net.name, { ...k, pq: { ...k.pq, seedHex: newSeedHex, publicKeyHex: hex(next.publicKey), publicKeySha256: hex(sha256(next.publicKey)), previousSeedHex: k.pq.seedHex, rotatedAt: new Date().toISOString() } });
  console.log("key file updated with the new seed (previous seed kept as previousSeedHex)");
}
console.log(`registered ML-DSA-44 key sha256 ${hex(sha256(next.publicKey))}`);
