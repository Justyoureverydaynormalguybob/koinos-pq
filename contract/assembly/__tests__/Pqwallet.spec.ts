import { Base58, Base64, MockVM, System, authority, chain, protocol } from "@koinos/sdk-as";
import { pqwallet } from "../proto/pqwallet";
import { Pqwallet, PK_BYTES, SIG_BYTES, SYSTEM_BUFFER_BYTES } from "../Pqwallet";
import * as F from "./fixtures";

// The account under test IS the legacy fixture address, so the secp256k1 fallback can match.
const CONTRACT_ID = Base58.decode(F.LEGACY_ADDRESS);

function tx(idB64: string, sigsB64: string[]): void {
  const sigs = new Array<Uint8Array>();
  for (let i = 0; i < sigsB64.length; i++) sigs.push(Base64.decode(sigsB64[i]));
  MockVM.setTransaction(new protocol.transaction(Base64.decode(idB64), null, [], sigs));
}

function tamper(b64: string, at: i32): string {
  const b = Base64.decode(b64);
  b[at] = b[at] ^ 1;
  return Base64.encode(b);
}

function authorize(c: Pqwallet, type: authority.authorization_type = authority.authorization_type.transaction_application): bool {
  return c.authorize(new authority.authorize_arguments(type, null)).value;
}

function expectFail(fn: () => void, message: string): void {
  MockVM.commitTransaction();
  expect(fn).toThrow();
  const raw = MockVM.getErrorMessage();
  const got: string = raw == null ? "" : raw!;
  expect(got.includes(message)).toBe(true, "expected error containing '" + message + "' but got '" + got + "'");
}

function registerA(c: Pqwallet): void {
  tx(F.TX_ID, [F.LEGACY_SIG]);
  c.set_public_key(new pqwallet.set_public_key_arguments(Base64.decode(F.PK_A)));
}

describe("pqwallet", () => {
  beforeEach(() => {
    MockVM.reset();
    MockVM.setContractId(CONTRACT_ID);
    MockVM.setEntryPoint(0);
    MockVM.setCaller(new chain.caller_data(new Uint8Array(0), chain.privilege.kernel_mode));
    MockVM.setContractMetadata(new chain.contract_metadata_object(new Uint8Array(0), false, true, true, false));
    MockVM.setHeadInfo(new chain.head_info(null, 1_700_000_000_000, 0));
  });

  it("enlarges the SDK system-call buffer at module start (1312-byte args, 2420-byte sigs)", () => {
    expect(System.getSystemBufferSize()).toBe(SYSTEM_BUFFER_BYTES);
  });

  it("reports the scheme and no key at first", () => {
    const c = new Pqwallet();
    const info = c.get_info(new pqwallet.get_info_arguments());
    expect(info.public_key_bytes).toBe(<u32>PK_BYTES);
    expect(info.signature_bytes).toBe(<u32>SIG_BYTES);
    expect(info.key_registered).toBe(false);
    expect(c.get_public_key(new pqwallet.get_public_key_arguments()).value!.length).toBe(0);
  });

  it("before a key is registered, falls back to the chain's secp256k1 rule", () => {
    const c = new Pqwallet();
    tx(F.TX_ID, [F.LEGACY_SIG]);
    expect(authorize(c)).toBe(true, "owner's secp256k1 signature");
    expect(authorize(c, authority.authorization_type.contract_call)).toBe(true);
    expect(authorize(c, authority.authorization_type.contract_upload)).toBe(true);
    tx(F.TX_ID, [F.STRANGER_SIG]);
    expect(authorize(c)).toBe(false, "someone else's secp256k1 signature");
    tx(F.TX_ID, [F.SIG_A_TX]);
    expect(authorize(c)).toBe(false, "ML-DSA signature before any key is registered");
    tx(F.TX_ID, []);
    expect(authorize(c)).toBe(false, "no signatures at all");
  });

  it("set_public_key checks length and authority", () => {
    const c = new Pqwallet();
    tx(F.TX_ID, [F.LEGACY_SIG]);
    expectFail(() => {
      const c2 = new Pqwallet();
      c2.set_public_key(new pqwallet.set_public_key_arguments(new Uint8Array(100)));
    }, "1312 bytes");
    tx(F.TX_ID, [F.STRANGER_SIG]);
    expectFail(() => {
      const c2 = new Pqwallet();
      c2.set_public_key(new pqwallet.set_public_key_arguments(Base64.decode(F.PK_A)));
    }, "not authorized");
    expect(c.get_info(new pqwallet.get_info_arguments()).key_registered).toBe(false);
  });

  it("registers an ML-DSA-44 key with the legacy signature and emits an event", () => {
    const c = new Pqwallet();
    registerA(c);
    const info = c.get_info(new pqwallet.get_info_arguments());
    expect(info.key_registered).toBe(true);
    expect(Base64.encode(c.get_public_key(new pqwallet.get_public_key_arguments()).value!)).toBe(F.PK_A);
    expect(MockVM.getEvents().length).toBe(1);
    expect(MockVM.getEvents()[0].name).toBe("pqwallet.key_set");
  });

  it("after registration only a valid ML-DSA-44 signature over the tx id authorises", () => {
    const c = new Pqwallet();
    registerA(c);
    tx(F.TX_ID, [F.LEGACY_SIG]);
    expect(authorize(c)).toBe(false, "secp256k1 no longer counts");
    tx(F.TX_ID, [F.SIG_A_TX]);
    expect(authorize(c)).toBe(true, "correct key, correct tx, correct context");
    expect(authorize(c, authority.authorization_type.contract_call)).toBe(true);
    expect(authorize(c, authority.authorization_type.contract_upload)).toBe(true);
    tx(F.TX_ID, [F.LEGACY_SIG, F.SIG_A_TX]);
    expect(authorize(c)).toBe(true, "ML-DSA signature anywhere in the list");
    tx(F.TX_ID, [F.SIG_B_TX]);
    expect(authorize(c)).toBe(false, "wrong key");
    tx(F.TX_ID, [F.SIG_A_TX2]);
    expect(authorize(c)).toBe(false, "signature over a different tx id (replay)");
    tx(F.TX_ID_2, [F.SIG_A_TX]);
    expect(authorize(c)).toBe(false, "same signature presented on a different tx");
    tx(F.TX_ID, [F.SIG_A_NOCTX]);
    expect(authorize(c)).toBe(false, "wrong domain-separation context");
    tx(F.TX_ID, [tamper(F.SIG_A_TX, 7)]);
    expect(authorize(c)).toBe(false, "one flipped bit in the signature");
    tx(F.TX_ID, [tamper(F.SIG_A_TX, 2419)]);
    expect(authorize(c)).toBe(false, "flipped bit in the last byte");
    tx(F.TX_ID, [Base64.encode(Base64.decode(F.SIG_A_TX).slice(0, 2419))]);
    expect(authorize(c)).toBe(false, "truncated signature");
    tx(F.TX_ID, []);
    expect(authorize(c)).toBe(false, "no signatures");
  });

  it("counts successful verifications", () => {
    const c = new Pqwallet();
    registerA(c);
    tx(F.TX_ID, [F.SIG_A_TX]);
    expect(authorize(c)).toBe(true);
    expect(authorize(c)).toBe(true);
    tx(F.TX_ID, [F.SIG_B_TX]);
    expect(authorize(c)).toBe(false);
    expect(c.get_info(new pqwallet.get_info_arguments()).verifications).toBe(2);
  });

  it("rotates to a new key only with the current key's signature", () => {
    const c = new Pqwallet();
    registerA(c);
    tx(F.TX_ID, [F.LEGACY_SIG]);
    expectFail(() => {
      const c2 = new Pqwallet();
      c2.set_public_key(new pqwallet.set_public_key_arguments(Base64.decode(F.PK_B)));
    }, "not authorized");
    tx(F.TX_ID, [F.SIG_A_TX]);
    c.set_public_key(new pqwallet.set_public_key_arguments(Base64.decode(F.PK_B)));
    tx(F.TX_ID, [F.SIG_B_TX]);
    expect(authorize(c)).toBe(true, "new key works");
    tx(F.TX_ID, [F.SIG_A_TX]);
    expect(authorize(c)).toBe(false, "old key is dead");
  });
});
