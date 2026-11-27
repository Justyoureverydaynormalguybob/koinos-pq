// What counts as the chain REFUSING a transaction, for cli/attack-outsider.mjs.
//
// Only the texts below count. Each is the wording of one specific check, so a match says both "the
// chain judged this and said no" and "this is the check that said it". Everything else (a network
// error, an HTML error page, "AMQP connection is not open", not enough mana, a wrong nonce) is NO
// VERDICT: it proves nothing about the account, and the run must not pass on it.
//
// The texts come from recorded runs (docs/testnet-run.txt, docs/devnet-run.txt, docs/SECURITY.md)
// and from the contract source. A node that words a refusal differently shows up as "no verdict"
// with its text printed; add the text here once it has been read and understood.
export const CHECKS = {
  payer: {
    name: "payer check",
    what: "the chain asked the account's authorize() whether the transaction is the account's, and the signature rule said no (cases stop here before any operation runs)",
    // {"error":"account 1Fq… has not authorized transaction","account":"1Fq…","code":-200}
    match: (text, victim) => { const m = /^account (\S+) has not authorized transaction$/.exec(text); return !!m && m[1] === victim; },
  },
  nosig: {
    name: "chain's basic check",
    what: "a transaction with no signature at all is turned away before any authority is asked",
    match: (text) => /^missing expected field in transaction: signature_data$/.test(text),
  },
  buffer: {
    name: "contract buffer",
    what: "more signature bytes than the contract's 16 KiB system-call buffer holds: authorize() fails closed",
    match: (text) => /return buffer is not large enough/.test(text),
  },
  contract: {
    name: "set_public_key / set_allowed_caller",
    what: "the operation ran inside the account contract, and its own signature rule refused it",
    match: (text) => /^not authorized$/.test(text),
  },
  direct: {
    name: "direct-operation rule",
    what: "set_public_key / set_allowed_caller were reached from inside another contract and refused",
    match: (text) => /^set_(public_key|allowed_caller) must be a direct transaction operation$/.test(text),
  },
  token: {
    name: "token asks the account (signature rule)",
    what: "the token contract asked the account's authorize() for a transfer placed directly in the transaction",
    match: (text) => /^account 'from' has not authorized transfer$/.test(text),
  },
  nested: {
    name: "token asks the account (nested-caller rule)",
    what: "the token contract was called by another contract (PoB); the account's authorize() refuses a caller that is not on its allowed list",
    match: (text) => /^account 'from' has not authorized burn$/.test(text),
  },
};

/** The node's own error text: koilib throws the JSON-RPC error body as the message. */
export function errorText(e) {
  const raw = String((e && e.message) || e).trim();
  try {
    const j = JSON.parse(raw);
    if (j && typeof j.error === "string") return j.error.trim();
    if (j && j.error && typeof j.error.message === "string") return j.error.message.trim();
  } catch { /* not JSON: use the text as it is */ }
  return raw;
}

/** The key in CHECKS whose wording this error carries, or null when it is not a refusal we know. */
export function refusedBy(e, victim) {
  const text = errorText(e);
  for (const [key, c] of Object.entries(CHECKS)) if (c.match(text, victim)) return key;
  return null;
}
