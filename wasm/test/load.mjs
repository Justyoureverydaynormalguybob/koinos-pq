// Loads the ML-DSA-44 verifier for the tests, from one of two files:
//   wasm/dilithium.wasm   the verifier on its own (default)
//   dist/pqwallet.wasm    the merged module, the exact bytes that are uploaded to an account
//                         (pass --merged on the command line)
// wasm-merge keeps the verifier's exports (mldsa44_verify, mldsa44_sizes) in the merged module, so the
// same vectors can be run against the function as it sits in the deployed file, at the same addresses.
// The contract's own start code is never run here and its one import, the system call, must not be
// reached by the verifier: if it is, the test fails.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const here = fileURLToPath(new URL("./", import.meta.url));
export const merged = process.argv.includes("--merged");
export const target = merged ? "dist/pqwallet.wasm" : "wasm/dilithium.wasm";

export async function loadVerifier({ pages = 8 } = {}) {
  const bytes = readFileSync(here + (merged ? "../../dist/pqwallet.wasm" : "../dilithium.wasm"));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (!merged) {
    const memory = new WebAssembly.Memory({ initial: pages });
    const { instance } = await WebAssembly.instantiate(bytes, { env: { memory } });
    return { ...instance.exports, memory, sha256 };
  }
  // The file under test must be the one dist/SHA256SUMS names, which is the one the CLI uploads.
  const sums = readFileSync(here + "../../dist/SHA256SUMS", "utf8");
  if (!sums.split(/\r?\n/).some((l) => l.startsWith(sha256) && /\s\*?pqwallet\.wasm$/.test(l))) {
    throw new Error(`dist/pqwallet.wasm (sha256 ${sha256}) is not the file dist/SHA256SUMS names`);
  }
  const { instance } = await WebAssembly.instantiate(bytes, {
    env: { invoke_system_call: () => { throw new Error("the verifier reached the system call"); } },
  });
  const { mldsa44_verify, mldsa44_sizes, memory } = instance.exports;
  if (typeof mldsa44_verify !== "function" || !memory) throw new Error("the merged module does not export the verifier");
  const have = memory.buffer.byteLength / 65536;
  if (have < pages) memory.grow(pages - have);
  return { mldsa44_verify, mldsa44_sizes, memory, sha256 };
}
