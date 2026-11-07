// Shows the account's balance, mana, contract state and PQ key status.
import { network, loadKeys, balance, mana, fmtKoin, pqContract, pqKeysFromSeed, hex, sha256, utils, contractMetadata } from "./lib.mjs";
const net = network();
const k = await loadKeys(net.name);
const a = k.account.address;
console.log(`network   ${net.name}`);
console.log(`account   ${a}`);
console.log(`balance   ${fmtKoin(await balance(net, a))}`);
console.log(`mana      ${fmtKoin(await mana(net, a))}`);
if (k.pq.pendingSeedHex) console.log(`pending   a key rotation started ${k.pq.pendingSince || "earlier"} was not finished; run: npm run register`);
const m = await contractMetadata(net, a).catch(() => null);
if (!m) { console.log("contract  none uploaded yet"); process.exit(0); }
console.log(`contract  uploaded; overrides: call=${!!m.authorizes_call_contract} tx=${!!m.authorizes_transaction_application} upload=${!!m.authorizes_upload_contract}`);
const c = pqContract(net, a);
const info = (await c.functions.get_info()).result;
console.log(`scheme    ${info.scheme}; key registered: ${!!info.key_registered}`);
if (info.key_registered) {
  const onchainBytes = utils.decodeBase64url((await c.functions.get_public_key()).result.value);
  const matches = (seedHex) => !!seedHex && Buffer.from(onchainBytes).equals(Buffer.from(pqKeysFromSeed(seedHex).publicKey));
  const verdict = matches(k.pq.seedHex) ? "(matches local seed)"
    : matches(k.pq.pendingSeedHex) ? "(matches the PENDING seed; run npm run register to make it current)"
    : "(DOES NOT MATCH local seed!)";
  console.log(`on-chain key sha256 ${hex(sha256(onchainBytes))} ${verdict}`);
}
