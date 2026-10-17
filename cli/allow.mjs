// Allows or forbids a contract (e.g. a DEX) to act for this account from inside a nested call.
// Usage: node cli/allow.mjs <contract-address> on|off
import { network, loadKeys, pqContract, pqKeysFromSeed, buildTransaction, submit, pqSignTxId, b64url, waitMined } from "./lib.mjs";
const [contract, state] = process.argv.slice(2);
if (!contract || !["on", "off"].includes(state)) { console.error("usage: node cli/allow.mjs <contract-address> on|off"); process.exit(2); }
const net = network();
const k = loadKeys(net.name);
const pq = pqKeysFromSeed(k.pq.seedHex);
const c = pqContract(net, k.account.address);
const { operation } = await c.functions.set_allowed_caller({ contract, allowed: state === "on" }, { onlyOperation: true });
const tx = await buildTransaction(net, k.account.address, [operation], process.env.RC_LIMIT);
tx.signatures = [b64url(pqSignTxId(tx.id, pq.secretKey))];
const { receipt } = await submit(net, tx);
console.log(`tx ${tx.id}; rc_used ${receipt.rc_used}; mined in block ${await waitMined(net, tx.id)}`);
const r = (await c.functions.get_allowed_caller({ contract })).result; // koilib omits a false bool
console.log(`${contract} nested-call authority: ${r && r.value ? "allowed" : "not allowed"}`);
