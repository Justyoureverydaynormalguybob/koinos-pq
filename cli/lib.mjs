// Shared helpers for the koinos-pq CLI (testnet by default).
import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";
import { createInterface } from "node:readline";
import { execFileSync } from "node:child_process";
import { userInfo } from "node:os";
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
    // Second node: api.koinos.io intermittently answers "rpc failed, AMQP connection is not open"
    // (2026-11-04); network() moves on to the next node when one errors.
    rpc: ["https://api.koinos.io/jsonrpc", "https://api.koinosblocks.com/"],
    rest: "https://api.koinos.io/v1",
    // KOIN moved to this contract (VHP: 12Y5vW6gk8GceH53YfRkRre2Rrcsgw7Naq). The original
    // 15DJN4a8SgrbGhhGksSBASiSYjGnMU8dGL still answers name/symbol but every state read on it fails
    // with "user code cannot access system space" (checked 2026-10-18).
    koin: "19GYjDBVXU7keLbYvMLazsGQn3GTWHjHkK",
    explorer: "https://koinosscan.com",
  },
  // Private devnet running the koinos-chain fork (devnet/docker-compose.yml). KOIN is the local-koinos
  // testnet build uploaded by devnet/run.mjs to the address of its dev key; blocks are produced on demand.
  devnet: {
    rpc: [process.env.KOINOS_RPC || "http://127.0.0.1:8080/"],
    rest: null,
    koin: "1BRmrUgtSQVUggoeE9weG4f7nidyydnYfQ",
    explorer: null,
  },
};
export const CONTEXT = new TextEncoder().encode("koinos/pqwallet/1");
export const CONTEXT_POP = new TextEncoder().encode("koinos/pqwallet/1/pop");
/** Native path (koinos-chain fork, phase B1): a different context so the two can never be confused. */
export const CONTEXT_NATIVE = new TextEncoder().encode("koinos/tx/1");
export const PK_BYTES = 1312, SIG_BYTES = 2420;
export const NATIVE_TAG = 0x01, NATIVE_ENTRY_BYTES = 1 + PK_BYTES + SIG_BYTES; // 3733

export function network(name = process.env.KOINOS_NETWORK || "testnet") {
  const n = NETWORKS[name];
  if (!n) throw new Error(`unknown network ${name}`);
  return { name, ...n, provider: failoverProvider(n.rpc) };
}

/** koilib's Provider gives up on the first error by default; this tries each node once per call. */
function failoverProvider(nodes) {
  const p = new Provider(nodes);
  let tries = 0;
  p.onError = (e, current, next) => {
    tries += 1;
    if (tries >= nodes.length) { tries = 0; return true; }
    console.warn(`${current} failed (${String(e.message || e).slice(0, 100)}); trying ${next}`);
    return false;
  };
  const call = p.call.bind(p);
  p.call = (method, params) => { tries = 0; return call(method, params); };
  return p;
}

export const sha256 = (u8) => Uint8Array.from(createHash("sha256").update(u8).digest());
export const hex = (u8) => Buffer.from(u8).toString("hex");
export const fromHex = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex"));
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// Key file
//
// { network, createdAt, account: {address, wif}, pq: {scheme, seedHex, publicKeyHex, publicKeySha256,
//   previousSeedHex?, pendingSeedHex?, pendingSince?}, contractId?, deployedTx?, lockedUpload? }
//
// With a passphrase the secret fields (SECRET_PATHS) are moved into `encrypted`, an scrypt +
// AES-256-GCM blob, and everything else stays readable, so the address and public key can be
// checked without the passphrase. A plain-text file still loads, with a warning.
// ---------------------------------------------------------------------------------------------
const SECRET_PATHS = [["account", "wif"], ["pq", "seedHex"], ["pq", "previousSeedHex"], ["pq", "pendingSeedHex"]];
const KDF = { N: 1 << 17, r: 8, p: 1 }; // about a second on a laptop, 128 MiB
const KDF_MAX_N = 1 << 20; // refuse absurd parameters from a tampered file
const passphrases = new Map(); // network -> passphrase in use by this process ("" = plain text)

export function keyFile(net) { return fileURLToPath(new URL(`../.keys.${net}.json`, import.meta.url)); }

/** Reads a passphrase without echo, or KOINOS_PQ_PASSPHRASE when it is set (for scripts). */
export async function askPassphrase(label) {
  if (process.env.KOINOS_PQ_PASSPHRASE !== undefined) return process.env.KOINOS_PQ_PASSPHRASE;
  if (!process.stdin.isTTY) throw new Error("a passphrase is needed: run in a terminal or set KOINOS_PQ_PASSPHRASE");
  return readHidden(label);
}
function readHidden(label) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(label);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let buf = "";
    const done = (fn) => { stdin.setRawMode(false); stdin.pause(); stdin.off("data", onData); process.stderr.write("\n"); fn(); };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return done(() => resolve(buf));
        if (ch === "\u0003") return done(() => reject(new Error("cancelled")));
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else if (ch >= " ") buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}
/** A visible prompt, for confirmations. Refuses without a terminal rather than assuming "yes". */
export async function askLine(label) {
  if (!process.stdin.isTTY) throw new Error(`confirmation needed (${label.trim()}) but there is no terminal`);
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try { return await new Promise((r) => rl.question(label, r)); } finally { rl.close(); }
}

const getPath = (o, p) => p.reduce((v, k) => (v == null ? undefined : v[k]), o);
function splitSecrets(obj) {
  const pub = structuredClone(obj), sec = {};
  for (const p of SECRET_PATHS) {
    const v = getPath(obj, p);
    if (v === undefined) continue;
    let s = sec; for (const k of p.slice(0, -1)) s = s[k] ??= {}; s[p.at(-1)] = v;
    let o = pub; for (const k of p.slice(0, -1)) o = o[k]; delete o[p.at(-1)];
  }
  return { pub, sec };
}
function mergeSecrets(pub, sec) {
  const out = structuredClone(pub);
  for (const p of SECRET_PATHS) {
    const v = getPath(sec, p);
    if (v === undefined) continue;
    let o = out; for (const k of p.slice(0, -1)) o = o[k] ??= {}; o[p.at(-1)] = v;
  }
  return out;
}
function encryptSecrets(sec, passphrase) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = scryptSync(passphrase.normalize("NFKC"), salt, 32, { ...KDF, maxmem: 256 * KDF.N * KDF.r });
  const c = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(JSON.stringify(sec), "utf8"), c.final()]);
  return { v: 1, kdf: "scrypt", N: KDF.N, r: KDF.r, p: KDF.p, salt: hex(salt), cipher: "aes-256-gcm", iv: hex(iv), tag: hex(c.getAuthTag()), data: hex(data) };
}
function decryptSecrets(enc, passphrase) {
  if (enc.v !== 1 || enc.kdf !== "scrypt" || enc.cipher !== "aes-256-gcm") throw new Error("unknown key file encryption format");
  if (!(enc.N > 0 && enc.N <= KDF_MAX_N && enc.r > 0 && enc.r <= 32 && enc.p > 0 && enc.p <= 16)) throw new Error("key file has unreasonable scrypt parameters");
  const key = scryptSync(passphrase.normalize("NFKC"), fromHex(enc.salt), 32, { N: enc.N, r: enc.r, p: enc.p, maxmem: 256 * enc.N * enc.r });
  const d = createDecipheriv("aes-256-gcm", key, fromHex(enc.iv));
  d.setAuthTag(fromHex(enc.tag));
  try { return JSON.parse(Buffer.concat([d.update(fromHex(enc.data)), d.final()]).toString("utf8")); }
  catch { throw new Error("wrong passphrase (or the key file is damaged)"); }
}

/** Loads the key file, asking for the passphrase when it is encrypted. */
export async function loadKeys(net) {
  const f = keyFile(net);
  if (!existsSync(f)) throw new Error(`no key file ${f}; run: node cli/keys.mjs`);
  const raw = JSON.parse(readFileSync(f, "utf8"));
  if (!raw.encrypted) {
    if (!passphrases.has(net) && net !== "devnet") console.warn(`warning: ${f} holds the seed and WIF in plain text; run: npm run encrypt-keys`);
    passphrases.set(net, "");
    return raw;
  }
  let pw = passphrases.get(net);
  if (!pw) pw = await askPassphrase(`passphrase for ${f}: `);
  const sec = decryptSecrets(raw.encrypted, pw);
  passphrases.set(net, pw);
  const { encrypted, ...pub } = raw;
  return mergeSecrets(pub, sec);
}
/** Sets the passphrase saveKeys() uses for this network ("" = plain text). */
export function usePassphrase(net, pw) { passphrases.set(net, pw); }
/** Writes the key file, owner-only, encrypted when a passphrase is in use for this network. */
export function saveKeys(net, obj) {
  const f = keyFile(net);
  const pw = passphrases.get(net) || "";
  const { encrypted: _old, ...plain } = obj; // never carry a stale blob along
  let out = plain;
  if (pw) {
    const { pub, sec } = splitSecrets(plain);
    out = { ...pub, encrypted: encryptSecrets(sec, pw) };
  }
  writeFileSync(f, JSON.stringify(out, null, 2), { mode: 0o600 }); // created 0600, no window
  restrictToOwner(f);
  if (!pw && net !== "devnet") console.warn(`warning: ${f} holds the seed and WIF in plain text; run: npm run encrypt-keys`);
  return f;
}
/** 0600 means nothing on Windows (only a read-only bit exists), so there the ACL is cut to the owner. */
function restrictToOwner(f) {
  if (process.platform !== "win32") { chmodSync(f, 0o600); return; }
  try {
    const me = userInfo().username.toLowerCase();
    const icacls = (...a) => execFileSync("icacls", [f, ...a], { stdio: ["ignore", "pipe", "ignore"] }).toString();
    // Entries are printed as "<identity>:(perms)"; the first line starts with the path.
    const entries = () => icacls().split(/\r?\n/).map((l) => l.replace(f, "").trim()).filter((l) => /:\(/.test(l));
    const identity = (e) => e.slice(0, e.lastIndexOf(":("));
    icacls("/inheritance:r", "/grant:r", `${me}:F`);
    // Some folders give new files explicit (not inherited) entries, which /inheritance:r leaves alone.
    for (const id of entries().map(identity)) {
      if (id.split("\\").pop().toLowerCase() !== me) icacls("/remove", id);
    }
    const left = entries();
    if (left.length !== 1) console.warn(`warning: ${f} is still readable by: ${left.join(", ")}`);
  } catch { console.warn(`warning: could not restrict ${f} to the current user (icacls failed)`); }
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
/** Native path: the address of an ML-DSA-44 public key is derived exactly like a secp256k1 key's. */
export function pqAddress(publicKey) {
  return utils.bitcoinAddress(publicKey); // base58check( 0x00 || ripemd160( sha256( pk ) ) )
}
/** Native path: signature over the tx id with the chain's context, and the 3733-byte entry around it. */
export function pqSignTxIdNative(txIdHex, secretKey) {
  const id = fromHex(txIdHex);
  if (id.length !== 34 || id[0] !== 0x12 || id[1] !== 0x20) throw new Error("tx id is not a sha2-256 multihash");
  return ml_dsa44.sign(id, secretKey, { context: CONTEXT_NATIVE });
}
export function nativeEntry(publicKey, signature) {
  if (publicKey.length !== PK_BYTES || signature.length !== SIG_BYTES) throw new Error("bad key or signature size");
  return Uint8Array.from([NATIVE_TAG, ...publicKey, ...signature]);
}
/** Proof of possession for set_public_key: the NEW key signs the account's 25-byte address. */
export function pqProofOfPossession(address, newSecretKey) {
  return ml_dsa44.sign(utils.decodeBase58(address), newSecretKey, { context: CONTEXT_POP });
}

export const abiPath = fileURLToPath(new URL("../dist/pqwallet.abi", import.meta.url));
export const wasmPath = fileURLToPath(new URL("../dist/pqwallet.wasm", import.meta.url));
const sumsPath = fileURLToPath(new URL("../dist/SHA256SUMS", import.meta.url));

/** The bytecode that gets uploaded, after checking it against dist/SHA256SUMS. */
export function loadBytecode() {
  const bytes = new Uint8Array(readFileSync(wasmPath));
  // \r?\n: a Windows checkout has CRLF line endings, and "$" would not match before the \r.
  const line = readFileSync(sumsPath, "utf8").split(/\r?\n/).find((l) => /\s\*?pqwallet\.wasm$/.test(l));
  if (!line) throw new Error("dist/SHA256SUMS has no entry for pqwallet.wasm");
  const got = hex(sha256(bytes));
  if (!line.startsWith(got)) throw new Error(`dist/pqwallet.wasm sha256 ${got} does not match dist/SHA256SUMS; run npm run build`);
  return { bytes, sha256: got };
}

/** A funded key for sponsored operations: always FUND_WIF, never a key file found on disk. */
export function fundingWif(net) {
  if (process.env.FUND_WIF) return process.env.FUND_WIF;
  throw new Error(`set FUND_WIF to a funded ${net.name} key`);
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
/** True when a transaction with this id is in a block (the transaction store knows it). */
export async function landed(net, txId) {
  try {
    const r = await net.provider.getTransactionsById([txId]);
    return !!(r && r.transactions && r.transactions.length);
  } catch { return false; }
}
/**
 * Submits a signed transaction and, when the node does not give a clear answer, keeps the SAME
 * signed bytes rather than signing a new transaction. A transport error ("AMQP connection is not
 * open", a bad JSON body, a timeout) can arrive after the node has accepted the transaction, and a
 * fresh transaction with the next nonce would then be a second payment.
 *  - "insufficient pending account resources": refused before acceptance because the mempool still
 *    reserves this account's last transaction. Wait, then resubmit; `rebuild()` (fresh nonce and
 *    rc_limit) is used only while no ambiguous error has been seen.
 *  - ambiguous transport error: wait, look for the id on chain; found means done, else resubmit.
 *  - anything else: a refusal that will not change; thrown, after one last look for the id.
 * Returns { receipt, tx }; receipt is null when the transaction was found on chain after an error.
 */
export async function submitOnce(net, tx, { rebuild, retries = 16, delayMs = 30000, log = console.log } = {}) {
  let ambiguousSeen = false;
  for (let attempt = 0; ; attempt++) {
    try {
      const { receipt } = await submit(net, tx);
      return { receipt, tx };
    } catch (e) {
      const msg = String((e && e.message) || e);
      const busy = /insufficient pending account resources/i.test(msg);
      const ambiguous = /AMQP|invalid json|unexpected token|unexpected end of json|fetch failed|ECONN|ETIMEDOUT|timed? ?out|socket hang up|\b50[234]\b/i.test(msg);
      if (ambiguous) ambiguousSeen = true;
      if (!busy && !ambiguous) {
        if (ambiguousSeen && await landed(net, tx.id)) { log(`tx ${tx.id} is on chain; the earlier error was only transport`); return { receipt: null, tx }; }
        throw e;
      }
      if (attempt >= retries) throw e;
      log(`  ${msg.split("\n")[0].slice(0, 80)}; ${ambiguous ? "checking the chain, then " : ""}resubmitting in ${delayMs / 1000} s`);
      await sleep(delayMs);
      if (ambiguousSeen && await landed(net, tx.id)) { log(`tx ${tx.id} was accepted despite the error`); return { receipt: null, tx }; }
      if (busy && !ambiguousSeen && rebuild) tx = await rebuild();
    }
  }
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
