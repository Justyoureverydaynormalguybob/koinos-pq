// Tests how cli/attack-outsider.mjs judges a run, against a made-up node on this machine. No chain
// is contacted and no transaction leaves the machine: the "node" is an HTTP server on 127.0.0.1.
//   a node that refuses every case with the chain's own texts        -> exit 0
//   a node that answers some submissions with an error page          -> exit 2 (the reviewed fault: was 0)
//   a node whose connection drops on every submission                -> exit 2
//   a node that refuses, but always at the payer check               -> exit 2 (cases 10 to 12 not exercised)
//   a node that accepts one transaction                              -> exit 1
//   a node that is not there at all                                  -> exit 2
// Offline: node cli/test/attack-judge.test.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Provider, Signer, utils } from "koilib";
import { loadAbi, NETWORKS } from "../lib.mjs";

const VICTIM = "1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t";
const script = fileURLToPath(new URL("../attack-outsider.mjs", import.meta.url));
const attackerWif = Signer.fromSeed(randomBytes(32).toString("hex")).getPrivateKey("wif");
const abi = loadAbi();
const entry = (name) => abi.methods[name].entry_point;
const b64 = (bytes) => utils.encodeBase64url(Uint8Array.from(bytes));
const varint = (n) => { const out = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v); return out; };
// the nonce exactly as a node encodes it, taken from koilib
const p0 = new Provider(["http://127.0.0.1:1"]); p0.getNonce = async () => -1;
const NONCE0 = await p0.getNextNonce("x");
const KEY = Uint8Array.from(randomBytes(1312));

function readContract({ contract_id, entry_point }) {
  if (contract_id === NETWORKS.devnet.koin) return { result: b64([0x08, ...varint(6700000000n)]) }; // balance_of: 67 KOIN
  if (entry_point === entry("get_public_key")) return { result: b64([0x0a, ...varint(KEY.length), ...KEY]) };
  if (entry_point === entry("get_info")) return { result: b64([0x28, 0x01]) }; // key_registered
  if (entry_point === entry("get_allowed_caller")) return { result: "" };
  throw new Error("unexpected read");
}
const rpcError = (message, data) => ({ error: { code: -32603, message, data: JSON.stringify(data) } });
/** What the real chain answered in the recorded runs, by the shape of the transaction. */
function chainVerdict(tx) {
  if (tx.header.payer === VICTIM) {
    if (!tx.signatures || !tx.signatures.length) return rpcError("missing expected field in transaction: signature_data", { code: -1002, field: "signature_data" });
    if (tx.signatures.length >= 7) return rpcError("return buffer is not large enough", { code: -1, logs: [] });
    return rpcError(`account ${VICTIM} has not authorized transaction`, { account: VICTIM, code: -200, logs: [] });
  }
  const to = tx.operations[0].call_contract.contract_id;
  if (to === NETWORKS.devnet.koin) return rpcError("account 'from' has not authorized transfer", { code: 1, logs: [] });
  return rpcError("not authorized", { code: 1, logs: [] });
}

async function run(mode) {
  let submissions = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { id, method, params } = JSON.parse(body);
      const send = (o) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id, ...o })); };
      if (method === "chain.get_account_rc") return send({ result: { rc: "5000000000" } });
      if (method === "chain.get_account_nonce") return send({ result: { nonce: NONCE0 } });
      if (method === "chain.get_chain_id") return send({ result: { chain_id: "EiBZK_GGVP0H_fXVAM3j6EAuz3-B-l3ejxRSewi7qIBfSA==" } });
      if (method === "chain.read_contract") return send({ result: readContract(params) });
      if (method === "chain.submit_transaction") {
        submissions++;
        const tx = params.transaction;
        if (mode === "error-page" && submissions % 2 === 0) { res.statusCode = 502; res.setHeader("content-type", "text/html"); return res.end("<html><body><h1>502 Bad Gateway</h1></body></html>"); }
        if (mode === "drops") return req.socket.destroy();
        if (mode === "amqp") return send({ error: { code: -32603, message: "rpc failed, AMQP connection is not open" } });
        if (mode === "payer-only" && tx.header.payer !== VICTIM) return send(rpcError(`account ${VICTIM} has not authorized transaction`, { account: VICTIM, code: -200, logs: [] }));
        if (mode === "accepts-one" && submissions === 3) return send({ result: { receipt: { id: tx.id, payer: tx.header.payer, rc_used: "1", reverted: false, logs: [] } } });
        return send(chainVerdict(tx));
      }
      send({ error: { code: -32601, message: `method not found: ${method}` } });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = mode === "no-node" ? 9 : server.address().port;
  const child = spawn(process.execPath, [script, VICTIM], {
    env: { ...process.env, KOINOS_NETWORK: "devnet", KOINOS_RPC: `http://127.0.0.1:${port}/`, ATTACKER_WIF: attackerWif },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => (out += d)); child.stderr.on("data", (d) => (out += d));
  const code = await new Promise((r) => child.on("close", r));
  await new Promise((r) => server.close(r));
  return { code, out, submissions };
}

const good = await run("refuses");
assert.equal(good.code, 0, good.out);
assert.equal(good.submissions, 11, "cases 1 to 6, 8a, 8b, 10, 11, 12 (the devnet has no history API and no PoB)");
assert.match(good.out, /11 refused where aimed, 0 refused somewhere else, 0 accepted or changed, 0 without a verdict/);
assert.match(good.out, /payer check: 1, 2, 3, 5, 6, 8a\n/);
assert.match(good.out, /chain's basic check: 4\n/);
assert.match(good.out, /contract buffer: 8b\n/);
assert.match(good.out, /set_public_key \/ set_allowed_caller: 11, 12\n/);
assert.match(good.out, /token asks the account \(signature rule\): 10\n/);
assert.match(good.out, /nested-caller rule\): not reached in this run/);
assert.match(good.out, /7 drain carrying a real signature.*skipped/);

for (const mode of ["error-page", "drops", "amqp"]) {
  const r = await run(mode);
  assert.equal(r.code, 2, `${mode}: a node that does not answer must not read as a pass\n${r.out}`);
  assert.match(r.out, /no verdict/);
  assert.doesNotMatch(r.out, / 0 without a verdict/);
}
const payerOnly = await run("payer-only");
assert.equal(payerOnly.code, 2, payerOnly.out);
assert.match(payerOnly.out, /3 refused somewhere else/);
assert.match(payerOnly.out, /\[~\] 11 .*not by the set_public_key \/ set_allowed_caller it is aimed at/);

const broken = await run("accepts-one");
assert.equal(broken.code, 1, broken.out);
assert.match(broken.out, /ACCEPTED/);

const none = await run("no-node");
assert.equal(none.code, 2, none.out);
assert.equal(none.submissions, 0);
console.log("attack judge: refused=0, error page / dropped connection / AMQP / wrong check / no node=2, accepted=1");
