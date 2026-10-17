// Shared helpers for the koinos-pq CLI (testnet by default).
import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { createHash } from "node:crypto";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { Provider, Signer, Contract, Transaction, utils } from "koilib";

export const NETWORKS = {
  testnet: {
    rpc: ["https://testnet.koinosfoundation.org/jsonrpc"],
    rest: "https://testnet.koinosfoundation.org/v1",
    koin: "1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju", // tKOIN
    explorer: "https://harbinger.koinosblocks.com",
  },
  mainnet: {
    rpc: ["https://api.koinos.io/jsonrpc"],
    rest: "https://api.koinos.io/v1",
    koin: "15DJN4a8SgrbGhhGksSBASiSYjGnMU8dGL",
    explorer: "https://koinosblocks.com",
  },
};
export const CONTEXT = new TextEncoder().encode("koinos/pqwallet/1");
export const PK_BYTES = 1312, SIG_BYTES = 2420;

export function network(name = process.env.KOINOS_NETWORK || "testnet") {
  const n = NETWORKS[name];
  if (!n) throw new Error(`unknown network ${name}`);
  return { name, ...n, provider: new Provider(n.rpc) };
}

export const sha256 = (u8) => Uint8Array.from(createHash("sha256").update(u8).digest());
export const hex = (u8) => Buffer.from(u8).toString("hex");
export const fromHex = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));

export function keyFile(net) { return new URL(`../.keys.${net}.json`, import.meta.url).pathname; }

/** Loads the key file: { account: {wif,address}, pq: {seedHex, publicKeyHex}, contractId? } */
export function loadKeys(net) {
  const f = keyFile(net);
  if (!existsSync(f)) throw new Error(`no key file ${f}; run: node cli/keys.mjs`);
  return JSON.parse(readFileSync(f, "utf8"));
}
export function saveKeys(net, obj) {
  const f = keyFile(net);
  writeFileSync(f, JSON.stringify(obj, null, 2));
  chmodSync(f, 0o600);
  return f;
}

/** ML-DSA-44 keys from a 32-byte seed (deterministic, FIPS 204 KeyGen_internal). */
export function pqKeysFromSeed(seedHex) {
  const seed = fromHex(seedHex);
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const k = ml_dsa44.keygen(seed);
  if (k.publicKey.length !== PK_BYTES) throw new Error("unexpected public key size");
  return k;
}

/** Signs a Koinos transaction id (34-byte multihash) with ML-DSA-44 under our context. */
export function pqSignTxId(txIdHex, secretKey) {
  const id = fromHex(txIdHex);
  if (id.length !== 34 || id[0] !== 0x12 || id[1] !== 0x20) throw new Error("tx id is not a sha2-256 multihash");
  return ml_dsa44.sign(id, secretKey, { context: CONTEXT });
}
export function pqVerifyTxId(txIdHex, sig, publicKey) {
  return ml_dsa44.verify(sig, fromHex(txIdHex), publicKey, { context: CONTEXT });
}

export const abiPath = new URL("../contract/abi/pqwallet.abi", import.meta.url).pathname;
export const wasmPath = new URL("../contract/build/release/pqwallet.wasm", import.meta.url).pathname;
export function loadAbi() { return JSON.parse(readFileSync(abiPath, "utf8")); }

export function pqContract(net, address, signer) {
  return new Contract({ id: address, abi: loadAbi(), provider: net.provider, signer });
}
export function koinContract(net, signer) {
  return new Contract({ id: net.koin, abi: utils.tokenAbi, provider: net.provider, signer });
}

export async function restGet(net, path) {
  const r = await fetch(`${net.rest}${path}`);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status} ${await r.text()}`);
  return r.json();
}
export async function balance(net, address) {
  const j = await restGet(net, `/account/${address}/balance/${net.koin}`);
  return BigInt(j.value || "0");
}
export async function mana(net, address) {
  const j = await restGet(net, `/account/${address}/mana`);
  return BigInt(j.value || "0");
}
export const fmtKoin = (v) => `${(Number(v) / 1e8).toFixed(8)} KOIN`;

/**
 * Builds an unsigned transaction for `payer` with the given operations, lets the caller
 * add signatures, then submits. The id is sha2-256 of the header, as koilib computes it.
 */
export async function buildTransaction(net, payer, operations, rcLimit) {
  const tx = { header: { payer }, operations, signatures: [] };
  if (rcLimit) tx.header.rc_limit = String(rcLimit);
  await Transaction.prepareTransaction(tx, net.provider, payer);
  return tx; // tx.id is "0x1220..." hex
}
export async function submit(net, tx) {
  const { receipt, transaction } = await net.provider.sendTransaction(tx);
  return { receipt, transaction };
}
export async function waitMined(net, txId, timeoutMs = 90000) {
  return net.provider.wait(txId, "byBlock", timeoutMs);
}
export function b64url(u8) { return utils.encodeBase64url(u8); }
export { Signer, Contract, Transaction, utils };
