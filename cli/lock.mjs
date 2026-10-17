// Final step: re-upload with upload authority also governed by the contract, authorised by the
// ML-DSA-44 key. After this, no secp256k1 key can touch the account at all.
import { readFileSync } from "node:fs";
import { network, loadKeys, saveKeys, pqContract, pqKeysFromSeed, wasmPath, loadAbi, buildTransaction, submit, pqSignTxId, b64url, waitMined, utils } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const address = k.account.address;
const pq = pqKeysFromSeed(k.pq.seedHex);
const c = pqContract(net, address);
const info = (await c.functions.get_info()).result;
if (!info.key_registered) { console.error("register the ML-DSA key first"); process.exit(1); }
const bytecode = new Uint8Array(readFileSync(wasmPath));
const operation = {
  upload_contract: {
    contract_id: address,
    bytecode: utils.encodeBase64url(bytecode),
    abi: JSON.stringify(loadAbi()),
    authorizes_call_contract: true,
    authorizes_transaction_application: true,
    authorizes_upload_contract: true,
  },
};
const tx = await buildTransaction(net, address, [operation], process.env.RC_LIMIT);
tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
const { receipt } = await submit(net, tx);
console.log(`tx ${tx.id} submitted; rc_used ${receipt.rc_used}; compute ${receipt.compute_bandwidth_used}`);
console.log(`mined in block ${await waitMined(net, tx.id)}`);
saveKeys(net.name, { ...k, lockedUpload: true, lockTx: tx.id });
console.log("done: call, transaction and upload authority are all governed by the ML-DSA-44 key");
