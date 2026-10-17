// Moves tKOIN from a funded testnet key into the PQ account (so the faucet only ever needs to
// feed one address). Source key: FUND_WIF env, or the koinky-kit testnet issuer key if present.
// Usage: node cli/fund.mjs [amount KOIN, default 20]
import { readFileSync, existsSync } from "node:fs";
import { network, loadKeys, koinContract, Signer, balance, fmtKoin, waitMined } from "./lib.mjs";

const net = network();
const k = loadKeys(net.name);
const amount = Number(process.argv[2] || "20");
let wif = process.env.FUND_WIF;
if (!wif) {
  const f = `${process.env.HOME}/koinky-kit/.keys.${net.name}.json`;
  if (existsSync(f)) wif = JSON.parse(readFileSync(f, "utf8")).issuer.wif;
}
if (!wif) { console.error("set FUND_WIF to a funded key"); process.exit(1); }
const src = Signer.fromWif(wif);
src.provider = net.provider;
const have = await balance(net, src.getAddress());
console.log(`source ${src.getAddress()} has ${fmtKoin(have)}; sending ${amount} to ${k.account.address}`);
if (have < BigInt(Math.round(amount * 1e8))) { console.error("source has too little; use the faucet first"); process.exit(1); }
const koin = koinContract(net, src);
const { transaction, receipt } = await koin.functions.transfer({ from: src.getAddress(), to: k.account.address, value: String(Math.round(amount * 1e8)) });
console.log(`tx ${transaction.id}; rc_used ${receipt.rc_used}`);
console.log(`mined in block ${await waitMined(net, transaction.id)}; PQ account now ${fmtKoin(await balance(net, k.account.address))}`);
