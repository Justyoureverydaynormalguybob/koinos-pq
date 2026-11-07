// Re-uploads a contract whose authority this post-quantum account holds (its `authorize`
// delegates to this account, e.g. KoinosProof after scripts/pq-handover.mjs). The account pays
// and signs with ML-DSA-44 only; no secp256k1 key is involved.
//
//   node cli/upload-for.mjs <contract address> <wasm file> <abi json file> [--sha256 <hex of the wasm>]
//
// The upload keeps all three authority overrides switched on (call, transaction, upload), so the
// contract stays governed by this account. Because the NEW code's own authorize() then decides who
// controls the contract, uploading the wrong file hands it over for good. So: the wasm must be a
// valid module, the ABI must parse, and the sha256 of the wasm must either be given with --sha256
// or be confirmed at the prompt by typing its first 8 characters. Nothing is sent without one of
// the two. Waits until the new code hash is on chain.
import { readFileSync } from "node:fs";
import {
  network, loadKeys, pqKeysFromSeed, buildTransaction, submitOnce, pqSignTxId, b64url,
  contractMetadata, hex, sha256, utils, askLine, sleep,
} from "./lib.mjs";

const args = process.argv.slice(2);
const flagAt = args.indexOf("--sha256");
const expected = flagAt >= 0 ? (args[flagAt + 1] || "").toLowerCase().replace(/^0x/, "") : null;
const [contract, wasmFile, abiFile] = flagAt >= 0 ? args.filter((_, i) => i !== flagAt && i !== flagAt + 1) : args;
if (!contract || !wasmFile || !abiFile || (expected !== null && !/^[0-9a-f]{64}$/.test(expected))) {
  console.error("usage: node cli/upload-for.mjs <contract address> <wasm> <abi json> [--sha256 <64 hex chars>]");
  process.exit(1);
}
const net = network();
const k = await loadKeys(net.name);
const pq = pqKeysFromSeed(k.pq.seedHex);
const bytes = new Uint8Array(readFileSync(wasmFile));
const abiText = readFileSync(abiFile, "utf8");
const digest = hex(sha256(bytes));
const want = "1220" + digest;

// What is about to govern the contract: a real module (this catches a wrong or damaged file, not
// post-MVP features, which the chain's VM refuses at upload), a real ABI, and the expected hash.
if (!WebAssembly.validate(bytes)) { console.error(`${wasmFile} is not a valid WebAssembly module`); process.exit(1); }
let abi = null;
try { abi = JSON.parse(abiText); } catch { /* reported below */ }
if (!abi || typeof abi.methods !== "object" || !Object.keys(abi.methods).length) { console.error(`${abiFile} is not a Koinos ABI (no methods)`); process.exit(1); }
if (expected && expected !== digest) { console.error(`sha256 of ${wasmFile} is ${digest}, not ${expected}; refusing`); process.exit(1); }

const before = await contractMetadata(net, contract);
console.log(`${net.name}: ${contract} runs ${before && before.hash}`);
console.log(`new code: ${wasmFile} (${bytes.length} bytes, sha256 ${digest}), ${Object.keys(abi.methods).length} ABI methods, uploaded and paid by ${k.account.address}`);
if (!before || !before.authorizes_upload_contract) {
  console.error("that contract does not override upload authority, so this account cannot upload it");
  process.exit(1);
}
if (before.hash === want) { console.log("that exact code is already on chain; nothing to do"); process.exit(0); }
if (!expected) {
  const typed = (await askLine(`type the first 8 characters of the sha256 (${digest.slice(0, 8)}) to upload, anything else to stop: `)).trim().toLowerCase();
  if (typed !== digest.slice(0, 8)) { console.log("stopped; nothing was sent"); process.exit(1); }
}

const operation = {
  upload_contract: {
    contract_id: contract,
    bytecode: utils.encodeBase64url(bytes),
    abi: abiText,
    authorizes_call_contract: true,
    authorizes_transaction_application: true,
    authorizes_upload_contract: true,
  },
};
// A contract upload can need more than buildTransaction's 20 KOIN default cap (KoinosProof on
// mainnet: ~29 KOIN of mana), so allow 90% of the account's mana unless RC_LIMIT is set.
const build = async () => {
  const avail = BigInt(await net.provider.getAccountRc(k.account.address));
  const tx = await buildTransaction(net, k.account.address, [operation], process.env.RC_LIMIT || String((avail * 9n) / 10n));
  tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
  return tx;
};
// submitOnce resubmits the same signed bytes on a transport error and checks the chain for the
// id before giving up, so the upload cannot be sent twice; it rebuilds only on a clear refusal.
const { receipt, tx } = await submitOnce(net, await build(), { rebuild: build });
if (receipt) console.log(`tx ${tx.id} accepted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
for (let i = 0; i < 24; i++) {
  await sleep(15000);
  const now = await contractMetadata(net, contract);
  if (now && now.hash === want) {
    console.log(`done: ${contract} now runs ${want} (overrides call=${now.authorizes_call_contract} tx=${now.authorizes_transaction_application} upload=${now.authorizes_upload_contract})`);
    process.exit(0);
  }
}
console.error(`the new code is not on chain after 6 minutes; check transaction ${tx.id} before retrying`);
process.exit(1);
