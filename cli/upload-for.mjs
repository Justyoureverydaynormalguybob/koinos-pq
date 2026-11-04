// Re-uploads a contract whose authority this post-quantum account holds (its `authorize`
// delegates to this account, e.g. KoinosProof after scripts/pq-handover.mjs). The account pays
// and signs with ML-DSA-44 only; no secp256k1 key is involved.
//
//   node cli/upload-for.mjs <contract address> <wasm file> <abi json file> [--keep-flags]
//
// The upload keeps all three authority overrides switched on (call, transaction, upload), so the
// contract stays governed by this account. Waits until the new code hash is on chain.
import { readFileSync } from "node:fs";
import {
  network, loadKeys, pqKeysFromSeed, buildTransaction, submit, pqSignTxId, b64url,
  contractMetadata, hex, sha256, utils,
} from "./lib.mjs";

const [contract, wasmFile, abiFile] = process.argv.slice(2);
if (!contract || !wasmFile || !abiFile) {
  console.error("usage: node cli/upload-for.mjs <contract address> <wasm> <abi json>");
  process.exit(1);
}
const net = network();
const k = loadKeys(net.name);
const pq = pqKeysFromSeed(k.pq.seedHex);
const bytes = new Uint8Array(readFileSync(wasmFile));
const abiText = readFileSync(abiFile, "utf8");
const want = "1220" + hex(sha256(bytes));

const before = await contractMetadata(net, contract);
console.log(`${net.name}: ${contract} runs ${before && before.hash}; uploading ${want} as ${k.account.address}`);
if (!before || !before.authorizes_upload_contract) {
  console.error("that contract does not override upload authority, so this account cannot upload it");
  process.exit(1);
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let attempt = 0; ; attempt++) {
  try {
    // A contract upload can need more than buildTransaction's 20 KOIN default cap (KoinosProof
    // on mainnet: ~29 KOIN of mana), so allow 90% of the account's mana unless RC_LIMIT is set.
    const avail = BigInt(await net.provider.getAccountRc(k.account.address));
    const tx = await buildTransaction(net, k.account.address, [operation], process.env.RC_LIMIT || String((avail * 9n) / 10n));
    tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
    const { receipt } = await submit(net, tx);
    console.log(`tx ${tx.id} accepted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
    break;
  } catch (e) {
    // The mempool keeps a just-applied transaction's rc reserved for a while.
    if (/insufficient pending account resources/.test(e.message) && attempt < 16) {
      console.log("mempool still holding this account's last transaction; waiting 30 s");
      await sleep(30000);
      continue;
    }
    throw e;
  }
}
for (let i = 0; i < 24; i++) {
  await sleep(15000);
  const now = await contractMetadata(net, contract);
  if (now && now.hash === want) {
    console.log(`done: ${contract} now runs ${want} (overrides call=${now.authorizes_call_contract} tx=${now.authorizes_transaction_application} upload=${now.authorizes_upload_contract})`);
    process.exit(0);
  }
}
console.error("the new code is not on chain after 6 minutes; check the transaction");
process.exit(1);
