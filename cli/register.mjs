// Registers the ML-DSA-44 public key on the contract. Authorised by the secp256k1 key the first
// time (bootstrap), or by the current ML-DSA key when rotating (pass --rotate-from-current).
import { network, loadKeys, pqContract, pqKeysFromSeed, Signer, waitMined, buildTransaction, submit, pqSignTxId, b64url, hex, sha256, utils } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const address = k.account.address;
const pq = pqKeysFromSeed(k.pq.seedHex);
const c = pqContract(net, address);
const info = (await c.functions.get_info()).result;
const { operation } = await c.functions.set_public_key({ public_key: utils.encodeBase64url(pq.publicKey) }, { onlyOperation: true });

const tx = await buildTransaction(net, address, [operation], process.env.RC_LIMIT);
if (!info.key_registered) {
  console.log("no key registered yet: bootstrapping with the secp256k1 signature");
  const signer = Signer.fromWif(k.account.wif);
  const signed = await signer.signTransaction(tx);
  tx.signatures = signed.signatures;
} else {
  console.log("rotating: signing with the current ML-DSA-44 key");
  tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
}
const { receipt } = await submit(net, tx);
console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
console.log(`mined in block ${await waitMined(net, tx.id)}`);
console.log(`registered ML-DSA-44 key sha256 ${hex(sha256(pq.publicKey))}`);
