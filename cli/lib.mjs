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
export const CONTEXT_POP = new TextEncoder().encode("koinos/pqwallet/1/pop");
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
  writeFileSync(f, JSON.stringify(obj, null, 2), { mode: 0o600 }); // created 0600, no window
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
/** Proof of possession for set_public_key: the NEW key signs the account's 25-byte address. */
export function pqProofOfPossession(address, newSecretKey) {
  return ml_dsa44.sign(utils.decodeBase58(address), newSecretKey, { context: CONTEXT_POP });
}

export const abiPath = new URL("../dist/pqwallet.abi", import.meta.url).pathname;
export const wasmPath = new URL("../dist/pqwallet.wasm", import.meta.url).pathname;
const sumsPath = new URL("../dist/SHA256SUMS", import.meta.url).pathname;

/** The bytecode that gets uploaded, after checking it against dist/SHA256SUMS. */
export function loadBytecode() {
  const bytes = new Uint8Array(readFileSync(wasmPath));
  const line = readFileSync(sumsPath, "utf8").split("\n").find((l) => /\s\*?pqwallet\.wasm$/.test(l));
  if (!line) throw new Error("dist/SHA256SUMS has no entry for pqwallet.wasm");
  const got = hex(sha256(bytes));
  if (!line.startsWith(got)) throw new Error(`dist/pqwallet.wasm sha256 ${got} does not match dist/SHA256SUMS; run npm run build`);
  return { bytes, sha256: got };
}

/** A funded key for sponsored operations: FUND_WIF, or (testnet only) the koinky-kit issuer. */
export function fundingWif(net) {
  if (process.env.FUND_WIF) return process.env.FUND_WIF;
  if (net.name !== "testnet") throw new Error("set FUND_WIF explicitly on " + net.name);
  const f = `${process.env.HOME}/koinky-kit/.keys.testnet.json`;
  if (existsSync(f)) return JSON.parse(readFileSync(f, "utf8")).issuer.wif;
  throw new Error("set FUND_WIF to a funded testnet key");
}
/** The Koinos ABI file uses kebab-case keys; koilib wants entry_point (number) and read_only. */
export function loadAbi() {
  const abi = JSON.parse(readFileSync(abiPath, "utf8"));
  for (const m of Object.values(abi.methods)) {
    if (m["entry-point"] !== undefined && m.entry_point === undefined) m.entry_point = Number(m["entry-point"]);
    if (m["read-only"] !== undefined && m.read_only === undefined) m.read_only = m["read-only"];
  }
  return abi;
}

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
/** Balance in base units (1e-8 KOIN) via the token contract; the REST endpoint reports whole KOIN. */
export async function balance(net, address) {
  const { result } = await koinContract(net).functions.balanceOf({ owner: address });
  return BigInt((result && result.value) || "0");
}
/** Available mana in base units. */
export async function mana(net, address) {
  return BigInt(await net.provider.getAccountRc(address));
}
export const fmtKoin = (v) => `${(Number(v) / 1e8).toFixed(8)} KOIN`;

/**
 * Builds an unsigned transaction for `payer` with the given operations, lets the caller
 * add signatures, then submits. The id is sha2-256 of the header, as koilib computes it.
 */
export async function buildTransaction(net, payer, operations, rcLimit) {
  const tx = { header: { payer }, operations, signatures: [] };
  if (!rcLimit) {
    // Not the whole mana: the mempool reserves each pending tx's rc_limit, and asking for
    // everything fails with "insufficient pending account resources" if anything is pending.
    const avail = BigInt(await net.provider.getAccountRc(payer));
    const cap = 20n * 100000000n; // 20 KOIN of mana is plenty for any single pqwallet tx
    rcLimit = avail / 2n < cap ? avail / 2n : cap;
  }
  tx.header.rc_limit = String(rcLimit);
  await Transaction.prepareTransaction(tx, net.provider, payer);
  return tx; // tx.id is "0x1220..." hex
}
export async function submit(net, tx) {
  const { receipt, transaction } = await net.provider.sendTransaction(tx);
  return { receipt, transaction };
}
export async function waitMined(net, txId, timeoutMs = 120000) {
  const r = await net.provider.wait(txId, "byBlock", timeoutMs);
  return typeof r === "object" && r !== null ? (r.blockNumber ?? r.blockId ?? JSON.stringify(r)) : r;
}
export function b64url(u8) { return utils.encodeBase64url(u8); }

/** Reads the chain's contract_metadata_object for an address (authority override flags). */
export async function contractMetadata(net, address) {
  const addr = utils.decodeBase58(address);
  const args = new Uint8Array([0x0a, addr.length, ...addr]);
  const r = await net.provider.call("chain.invoke_system_call", { name: "get_contract_metadata", args: utils.encodeBase64url(args) });
  if (!r || !r.value) return null;
  const b = utils.decodeBase64url(r.value);
  // get_contract_metadata_result { contract_metadata_object value = 1 }; object fields:
  // 1 hash, 2 system, 3 authorizes_call_contract, 4 authorizes_transaction_application, 5 authorizes_upload_contract
  const varint = (i) => { let s = 0, v = 0; for (;;) { const c = b[i++]; v |= (c & 0x7f) << s; s += 7; if (c < 0x80) return [v, i]; } };
  let i = 0, out = { hash: null, authorizes_call_contract: false, authorizes_transaction_application: false, authorizes_upload_contract: false };
  const [tag0, i0] = varint(i); if (tag0 >>> 3 !== 1) return null;
  const [len, i1] = varint(i0); i = i1; const end = i + len;
  while (i < end) {
    const [tag, j] = varint(i); const f = tag >>> 3, wt = tag & 7; i = j;
    if (wt === 2) { const [l, k] = varint(i); i = k; if (f === 1) out.hash = utils.toHexString(b.slice(i, i + l)); i += l; }
    else { const [v, k] = varint(i); i = k; if (f === 3) out.authorizes_call_contract = !!v; if (f === 4) out.authorizes_transaction_application = !!v; if (f === 5) out.authorizes_upload_contract = !!v; }
  }
  return out;
}
export { Signer, Contract, Transaction, utils };
