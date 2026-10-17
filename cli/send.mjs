// Sends tKOIN from the PQ account using ONLY an ML-DSA-44 signature (no secp256k1 anywhere).
// Usage: node cli/send.mjs <to-address> <amount-in-KOIN>  [--bad-sig | --no-sig | --ecdsa | --native | --native-bad-sig]
// Default and --native must succeed; the other flags are negative tests that the chain must reject.
//   default         contract route: the account at k.account.address runs pqwallet, signature = raw 2420 bytes
//   --native        native route (koinos-chain fork, phase B1): the account is the ML-DSA key's own address,
//                   signature entry = 0x01 || public key || signature over the tx id with context "koinos/tx/1"
import { network, loadKeys, koinContract, pqKeysFromSeed, buildTransaction, submit, pqSignTxId, pqVerifyTxId, pqSignTxIdNative, pqAddress, nativeEntry, b64url, waitMined, Signer, fmtKoin, balance } from "./lib.mjs";

const [to, amount] = process.argv.slice(2).filter((a) => !a.startsWith("--"));
if (!to || !amount) { console.error("usage: node cli/send.mjs <to> <amount KOIN> [--bad-sig|--no-sig|--ecdsa|--native|--native-bad-sig]"); process.exit(2); }
const mode = process.argv.find((a) => a.startsWith("--")) || "--ok";
const nativeMode = mode.startsWith("--native");
const expectOk = mode === "--ok" || mode === "--native";
const net = network();
const k = loadKeys(net.name);
const pq = pqKeysFromSeed(k.pq.seedHex);
const from = nativeMode ? pqAddress(pq.publicKey) : k.account.address;
const value = String(Math.round(Number(amount) * 1e8));
const koin = koinContract(net);
const { operation } = await koin.functions.transfer({ from, to, value }, { onlyOperation: true });
const tx = await buildTransaction(net, from, [operation], process.env.RC_LIMIT);

if (nativeMode) {
  const sig = pqSignTxIdNative(tx.id, pq.secretKey);
  if (mode === "--native-bad-sig") sig[10] ^= 1;
  tx.signatures = [b64url(nativeEntry(pq.publicKey, sig))];
} else if (mode === "--ok" || mode === "--bad-sig") {
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
  if (!expectOk) { console.error("NEGATIVE TEST FAILED: the chain accepted a transaction it should have rejected"); process.exit(1); }
} catch (e) {
  const msg = (e && e.message) || String(e);
  if (expectOk) { console.error("rejected:", msg); process.exit(1); }
  console.log(`rejected as expected: ${msg.split("\n")[0].slice(0, 200)}`);
}
