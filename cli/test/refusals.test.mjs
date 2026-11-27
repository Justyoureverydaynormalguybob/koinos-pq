// Tests cli/refusals.mjs: only the chain's own refusal texts count as "refused".
// Offline: node cli/test/refusals.test.mjs
import assert from "node:assert/strict";
import { refusedBy, errorText, CHECKS } from "../refusals.mjs";

const V = "1FqXVbjZnMo2cUNj56LNCrc8R22RWDmq1t";
const err = (o) => new Error(typeof o === "string" ? o : JSON.stringify(o));

// refusals, as recorded in docs/testnet-run.txt, docs/devnet-run.txt and docs/SECURITY.md
const yes = [
  [{ error: `account ${V} has not authorized transaction`, account: V, code: -200, logs: [] }, "payer"],
  [{ error: "missing expected field in transaction: signature_data", code: -1002, field: "signature_data" }, "nosig"],
  [{ error: "return buffer is not large enough", code: -1, logs: [] }, "buffer"],
  [{ error: "not authorized", code: 1, logs: [] }, "contract"],
  [{ error: "set_public_key must be a direct transaction operation", code: 1 }, "direct"],
  [{ error: "set_allowed_caller must be a direct transaction operation", code: 1 }, "direct"],
  [{ error: "account 'from' has not authorized transfer", code: 1, logs: [] }, "token"],
  [{ error: "account 'from' has not authorized burn", code: 1, logs: [] }, "nested"],
  [`account ${V} has not authorized transaction`, "payer"], // plain text, not JSON
];
for (const [e, want] of yes) assert.equal(refusedBy(err(e), V), want, JSON.stringify(e));

// everything a node says when it has NOT judged the attack: never a refusal
const no = [
  "fetch failed",
  "rpc failed, AMQP connection is not open",
  "<html><head><title>502 Bad Gateway</title></head><body>502 Bad Gateway</body></html>",
  "Unexpected token '<', \"<html>\" is not valid JSON",
  "request to https://testnet.koinosfoundation.org/jsonrpc failed, reason: socket hang up",
  "The operation was aborted due to timeout",
  { error: "insufficient rc", code: -1 },
  { error: "insufficient pending account resources", code: -1 },
  { error: "invalid nonce", code: -1 },
  { error: "unexpected signature length", code: -202 }, // the chain's default rule, not this account's contract
  { error: "transaction expected", code: -1 },
  { error: "unknown error", code: -1 },
  { error: "rc limit exceeded" },
  // the payer check failing for SOMEONE ELSE (the attacker's own paying account) says nothing about the victim
  { error: "account 1BRmrUgtSQVUggoeE9weG4f7nidyydnYfQ has not authorized transaction", code: -200 },
  { error: "the transaction was not authorized by the mempool" },
  { error: "account 'from' has not authorized transfer of this size, maybe" },
  "",
];
for (const e of no) assert.equal(refusedBy(err(e), V), null, JSON.stringify(e));

// the old pattern counted all of these as refusals; that was the reviewed fault
const OLD = /return buffer|authoriz|signature|insufficient|revert|invalid|failed|exception|denied|not allowed|unknown|expected|nonce|rc/i;
assert.ok(no.filter((e) => OLD.test(typeof e === "string" ? e : JSON.stringify(e))).length >= 12);

assert.equal(errorText(err({ error: { message: " not authorized " } })), "not authorized");
for (const c of Object.values(CHECKS)) assert.ok(c.name && c.what && typeof c.match === "function");
console.log(`refusals: ${yes.length} refusal texts recognised, ${no.length} non-answers kept apart`);
