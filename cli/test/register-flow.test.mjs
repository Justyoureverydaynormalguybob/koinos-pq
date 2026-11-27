// Runs cli/register.mjs itself against a made-up node on 127.0.0.1, with a key file in a temporary
// folder (KOINOS_PQ_KEY_FILE). No chain is contacted and no real key file is touched.
//
// The case this exists for (review of 2026-11-27, item 1): `register --rotate` ends before its
// transaction is in a block, and the user runs `register` again. The old code deleted the new seed
// at that point, and the rotation could still land.
// Offline: node cli/test/register-flow.test.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Provider, Signer, utils } from "koilib";
import { loadAbi, keyOfSeed, hex } from "../lib.mjs";
import { allSeeds } from "../rotation.mjs";

const script = fileURLToPath(new URL("../register.mjs", import.meta.url));
const abi = loadAbi();
const entry = (name) => abi.methods[name].entry_point;
const b64 = (bytes) => utils.encodeBase64url(Uint8Array.from(bytes));
const varint = (n) => { const out = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v); return out; };
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
async function encodeNonce(n) { // exactly as a node reports "last nonce used = n"
  const p = new Provider(["http://127.0.0.1:1"]); p.getNonce = async () => n - 1;
  return p.getNextNonce("x");
}
/** The public key inside a set_public_key operation: protobuf field 1 of its arguments. */
function keyInOperation(op) {
  const a = utils.decodeBase64url(op.call_contract.args);
  assert.equal(a[0], 0x0a);
  let i = 1, len = 0, shift = 0;
  for (;;) { const c = a[i++]; len |= (c & 0x7f) << shift; shift += 7; if (c < 0x80) break; }
  return hex(a.slice(i, i + len));
}

/** A node with one account. `chain` is its state; `onSubmit(tx, chain)` decides what a submission does. */
async function node(chain, onSubmit) {
  const submitted = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const { id, method, params } = JSON.parse(body);
      const send = (o) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id, ...o })); };
      if (method === "chain.get_account_nonce") return send({ result: { nonce: await encodeNonce(chain.nonce) } });
      if (method === "chain.get_account_rc") return send({ result: { rc: "5000000000" } });
      if (method === "chain.get_chain_id") return send({ result: { chain_id: "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==" } });
      if (method === "chain.read_contract") {
        if (params.entry_point === entry("get_info")) return send({ result: { result: chain.keyHex ? b64([0x28, 0x01]) : "" } });
        if (params.entry_point === entry("get_public_key")) { const k = fromHex(chain.keyHex); return send({ result: { result: b64([0x0a, ...varint(k.length), ...k]) } }); }
      }
      if (method === "chain.invoke_system_call") {
        // contract metadata: call and transaction overrides on, upload override as chain.locked says
        const meta = [0x18, 1, 0x20, 1, 0x28, chain.locked ? 1 : 0];
        return send({ result: { value: b64([0x0a, meta.length, ...meta]) } });
      }
      if (method === "transaction_store.get_transactions_by_id") return send({ result: { transactions: [] } });
      if (method === "chain.submit_transaction") {
        submitted.push(params.transaction);
        const answer = onSubmit(params.transaction, chain);
        return send(answer || { result: { receipt: { id: params.transaction.id, rc_used: "1", compute_bandwidth_used: "1", network_bandwidth_used: "1" } } });
      }
      send({ error: { code: -32601, message: `method not found: ${method}` } });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { port: server.address().port, submitted, close: () => new Promise((r) => server.close(r)) };
}
const mine = (tx, chain) => { chain.nonce += 1; chain.keyHex = keyInOperation(tx.operations[0]); };      // in the next block
const holdBack = () => {};                                                                             // accepted, never mined
const refuse = () => ({ error: { code: -32603, message: "insufficient rc", data: JSON.stringify({ code: -1 }) } });

const dir = mkdtempSync(join(tmpdir(), "pq-register-"));
const keyPath = join(dir, "keys.json");
async function register(port, ...args) {
  const child = spawn(process.execPath, [script, ...args], {
    env: { ...process.env, KOINOS_NETWORK: "devnet", KOINOS_RPC: `http://127.0.0.1:${port}/`, KOINOS_PQ_KEY_FILE: keyPath, KOINOS_PQ_WAIT_MS: "1500", RC_LIMIT: "100000000" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => (out += d)); child.stderr.on("data", (d) => (out += d));
  const code = await new Promise((r) => child.on("close", r));
  return { code, out };
}
const keys = () => JSON.parse(readFileSync(keyPath, "utf8"));
const account = Signer.fromSeed(hex(randomBytes(32)));
function freshKeyFile() {
  const seedHex = hex(randomBytes(32)), k = keyOfSeed(seedHex);
  writeFileSync(keyPath, JSON.stringify({ network: "devnet", account: { address: account.getAddress(), wif: account.getPrivateKey("wif") }, pq: { scheme: "ML-DSA-44", seedHex, publicKeyHex: k.hex, publicKeySha256: k.sha256 } }));
  return seedHex;
}

try {
  // ---- 1. a rotation that goes straight through ----
  {
    const A = freshKeyFile();
    const chain = { nonce: 4, keyHex: keyOfSeed(A).hex, locked: true };
    const n = await node(chain, mine);
    const r = await register(n.port, "--rotate");
    await n.close();
    assert.equal(r.code, 0, r.out);
    assert.equal(n.submitted.length, 1);
    const pq = keys().pq;
    assert.equal(keyOfSeed(pq.seedHex).hex, chain.keyHex, "the key file's current seed is the on-chain key");
    assert.equal(pq.previousSeedHex, A);
    assert.equal(pq.pendingSeedHex, undefined);
    assert.doesNotMatch(r.out, /NOT locked/);
  }

  // ---- 2. the reviewed case: the node takes the rotation and holds it back ----
  {
    const A = freshKeyFile();
    const chain = { nonce: 7, keyHex: keyOfSeed(A).hex, locked: true };
    let n = await node(chain, holdBack);
    const first = await register(n.port, "--rotate");
    await n.close();
    assert.equal(first.code, 3, first.out);
    assert.match(first.out, /the rotation is still open/);
    const after1 = keys().pq;
    const B = after1.pendingSeedHex;
    assert.ok(B && B !== A, "the new seed is in the key file");
    assert.equal(after1.pendingTx.nonce, "8");
    const sent = n.submitted[0];
    assert.deepEqual(after1.pendingTx.tx, sent, "the key file holds the very transaction that was sent");
    assert.equal(keyInOperation(sent.operations[0]), keyOfSeed(B).hex);

    // the user runs register again, the node still holds it back: the seed must still be there
    // (the old code deleted it here), and the SAME signed transaction is sent, not a new one
    n = await node(chain, holdBack);
    const second = await register(n.port);
    await n.close();
    assert.equal(second.code, 3, second.out);
    assert.match(second.out, /can still land/);
    assert.equal(n.submitted.length, 1);
    assert.deepEqual(n.submitted[0], sent, "the same signed bytes, not a new transaction");
    assert.deepEqual(keys().pq, after1, "the key file is unchanged while the rotation is open");

    // even `register --rotate` does not start a second rotation on top of it
    n = await node(chain, holdBack);
    const third = await register(n.port, "--rotate");
    await n.close();
    assert.equal(third.code, 3, third.out);
    assert.deepEqual(n.submitted[0], sent);
    assert.equal(keys().pq.pendingSeedHex, B);

    // later the held transaction lands by itself: the account now answers to B, and B is still here
    chain.nonce = 8; chain.keyHex = keyOfSeed(B).hex;
    n = await node(chain, holdBack);
    const fourth = await register(n.port);
    await n.close();
    assert.equal(fourth.code, 0, fourth.out);
    assert.equal(n.submitted.length, 0, "nothing needs sending any more");
    assert.match(fourth.out, /the pending rotation is on chain/);
    assert.deepEqual([keys().pq.seedHex, keys().pq.previousSeedHex, keys().pq.pendingSeedHex], [B, A, undefined]);
  }

  // ---- 3. the node refuses the rotation outright; run again when it accepts: same bytes, then done ----
  {
    const A = freshKeyFile();
    const chain = { nonce: 2, keyHex: keyOfSeed(A).hex, locked: false };
    let n = await node(chain, refuse);
    const first = await register(n.port, "--rotate");
    await n.close();
    assert.equal(first.code, 3, first.out);
    assert.match(first.out, /insufficient rc/);
    const B = keys().pq.pendingSeedHex, sent = n.submitted[0];
    assert.ok(B);
    n = await node(chain, mine);
    const second = await register(n.port);
    await n.close();
    assert.equal(second.code, 0, second.out);
    assert.deepEqual(n.submitted, [sent]);
    assert.equal(chain.keyHex, keyOfSeed(B).hex);
    assert.equal(keys().pq.seedHex, B);
    assert.match(second.out, /WARNING: this account is NOT locked/, "an account whose upload authority is still secp256k1 is told so");
  }

  // ---- 4. the rotation's nonce was used by another transaction: the seed is kept in the list ----
  {
    const A = freshKeyFile();
    const chain = { nonce: 5, keyHex: keyOfSeed(A).hex, locked: true };
    let n = await node(chain, holdBack);
    await register(n.port, "--rotate");
    await n.close();
    const B = keys().pq.pendingSeedHex;
    chain.nonce = 6; // another transaction of the account took nonce 6; the key is still A's
    n = await node(chain, mine);
    const r = await register(n.port, "--rotate");
    await n.close();
    assert.equal(r.code, 0, r.out);
    assert.equal(n.submitted.length, 0, "no new rotation is started in the same run");
    assert.match(r.out, /moved to retiredSeeds, not deleted/);
    const pq = keys().pq;
    assert.equal(pq.seedHex, A);
    assert.equal(pq.pendingSeedHex, undefined);
    assert.deepEqual(pq.retiredSeeds.map((x) => x.seedHex), [B]);

    // a lying node: the "dead" rotation is the on-chain key after all. B comes back from the list.
    chain.nonce = 7; chain.keyHex = keyOfSeed(B).hex;
    n = await node(chain, mine);
    const back = await register(n.port);
    await n.close();
    assert.equal(back.code, 0, back.out);
    assert.equal(keys().pq.seedHex, B);
    assert.ok(allSeeds(keys().pq).includes(A));
  }

  // ---- 5. a key on chain that no seed in the file belongs to: nothing sent, nothing changed ----
  {
    freshKeyFile();
    const before = readFileSync(keyPath, "utf8");
    const chain = { nonce: 1, keyHex: keyOfSeed(hex(randomBytes(32))).hex, locked: true };
    const n = await node(chain, mine);
    const r = await register(n.port, "--rotate");
    await n.close();
    assert.equal(r.code, 1, r.out);
    assert.equal(n.submitted.length, 0);
    assert.equal(readFileSync(keyPath, "utf8"), before);
  }
  console.log("register flow: straight rotation, held-back rotation run again (seed kept, same bytes resent), refused then accepted, nonce taken (seed kept), unknown key");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
