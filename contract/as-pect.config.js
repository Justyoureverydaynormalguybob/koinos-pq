import { readFileSync } from "node:fs";
import { MockVM } from "@koinos/mock-vm";

// The test module imports its memory (env.memory) so the ML-DSA verifier can share it,
// exactly as it does on chain after wasm-merge. The verifier's data+stack sit at 64 KiB..330 KiB,
// the AssemblyScript side starts at 384 KiB (memoryBase in asconfig.json).
const dilithiumBytes = readFileSync(new URL("../wasm/dilithium.wasm", import.meta.url));

export default {
  entries: ["assembly/__tests__/**/*.spec.ts"],
  include: ["assembly/__tests__/**/*.include.ts"],
  disclude: [/node_modules/i],
  async instantiate(memory, createImports, instantiate, binary) {
    const want = 128; // pages (8 MiB)
    const have = memory.buffer.byteLength / 65536;
    if (have < want) memory.grow(want - have);
    const dil = await WebAssembly.instantiate(dilithiumBytes, { env: { memory } });
    const mockVM = new MockVM();
    const myImports = {
      wasi_snapshot_preview1: { fd_write: () => {}, proc_exit: () => {} },
      env: { memory, ...mockVM.getImports() },
      dilithium: { mldsa44_verify: dil.instance.exports.mldsa44_verify },
    };
    const instance = instantiate(binary, createImports(myImports));
    instance.then((result) => { mockVM.setInstance(result); });
    return instance;
  },
  coverage: [],
  outputBinary: false,
};
