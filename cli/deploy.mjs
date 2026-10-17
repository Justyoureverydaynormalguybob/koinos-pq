// Uploads the Pqwallet contract to the account address, signed by the account's secp256k1 key.
// Overrides call-contract and transaction-application authority. Upload authority stays with the
// secp256k1 key until you run lock.mjs, so a bad contract can still be replaced during testing.
import { readFileSync } from "node:fs";
import { network, loadKeys, saveKeys, pqContract, wasmPath, loadAbi, Signer, waitMined, balance, fmtKoin } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const signer = Signer.fromWif(k.account.wif);
signer.provider = net.provider;
const address = signer.getAddress();
const lock = process.argv.includes("--lock");
console.log(`uploading pqwallet to ${address} on ${net.name} (balance ${fmtKoin(await balance(net, address))})`);
const contract = pqContract(net, address, signer);
contract.bytecode = new Uint8Array(readFileSync(wasmPath));
const { transaction, receipt } = await contract.deploy({
  abi: JSON.stringify(loadAbi()),
  authorizesCallContract: true,
  authorizesTransactionApplication: true,
  authorizesUploadContract: lock,
  rcLimit: process.env.RC_LIMIT || undefined,
});
console.log(`tx ${transaction.id} submitted; rc_used ${receipt.rc_used}`);
const block = await waitMined(net, transaction.id);
console.log(`mined in block ${block}`);
saveKeys(net.name, { ...k, contractId: address, deployedTx: transaction.id, lockedUpload: lock });
console.log(lock ? "upload authority is now also governed by the contract" : "upload authority still secp256k1 (run lock.mjs after testing)");
