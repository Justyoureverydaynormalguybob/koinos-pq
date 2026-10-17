// Sends tKOIN from the PQ account using ONLY an ML-DSA-44 signature (no secp256k1 anywhere).
// Usage: node cli/send.mjs <to-address> <amount-in-KOIN>  [--bad-sig | --no-sig | --ecdsa]
// The flags are negative tests: they must be rejected by the chain.
import { network, loadKeys, koinContract, pqKeysFromSeed, buildTransaction, submit, pqSignTxId, pqVerifyTxId, b64url, waitMined, Signer, fmtKoin, balance } from "./lib.mjs";

const [to, amount] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!to || !amount) { console.error("usage: node cli/send.mjs <to> <amount KOIN> [--bad-sig|--no-sig|--ecdsa]"); process.exit(2); }
const mode = process.argv.find((a) => a.startsWith("--")) || "--ok";
const net = network();
const k = loadKeys(net.name);
const from = k.account.address;
const pq = pqKeysFromSeed(k.pq.seedHex);
const value = String(Math.round(Number(amount) * 1e8));
const koin = koinContract(net);
const { operation } = await koin.functions.transfer({ from, to, value }, { onlyOperation: true });
const tx = await buildTransaction(net, from, [operation], process.env.RC_LIMIT);

if (mode === "--ok" || mode === "--bad-sig") {
  const sig = pqSignTxId(tx.id, pq.secretKey);
  if (!pqVerifyTxId(tx.id, sig, pq.publicKey)) throw new Error("local verify failed");
  if (mode === "--bad-sig") sig[10] ^= 1;
  tx.signatures = [b64url(sig)];
} else if (mode === "--ecdsa") {
  const signer = Signer.fromWif(k.account.wif);
  tx.signatures = (await signer.signTransaction(tx)).signatures;
} else if (mode === "--no-sig") {
  tx.signatures = [];
}
console.log(`${mode}: sending ${fmtKoin(value)} ${from} -> ${to}; tx ${tx.id}; ${tx.signatures.length} signature(s), ${tx.signatures.length ? Buffer.from(tx.signatures[0], "base64").length : 0} bytes`);
const before = await balance(net, from);
try {
  const { receipt } = await submit(net, tx);
  console.log(`accepted by mempool; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}; network ${receipt.network_bandwidth_used}`);
  const block = await waitMined(net, tx.id);
  console.log(`mined in block ${block}; balance ${fmtKoin(before)} -> ${fmtKoin(await balance(net, from))}`);
  if (mode !== "--ok") { console.error("NEGATIVE TEST FAILED: the chain accepted a transaction it should have rejected"); process.exit(1); }
} catch (e) {
  const msg = (e && e.message) || String(e);
  if (mode === "--ok") { console.error("rejected:", msg); process.exit(1); }
  console.log(`rejected as expected: ${msg.split("\n")[0].slice(0, 200)}`);
}
