# V8 ValueDeserializer — WASM Memory handling issues

Two independently reproducible security hardening / robustness findings in V8's
`ValueDeserializer` WASM-memory handling, found by source audit of V8 main
(`c518b1c983fa`, 2026-10-13) and binary-verified with a delegate-bearing
`v8::ValueDeserializer` harness built against a self-compiled d8.

Both findings are in `src/objects/value-serializer.cc`, both are crash-primitives
(renderer DoS class), and both are currently unfixed upstream.

| # | Issue | Root cause | Class |
|---|-------|-----------|-------|
| 1 | [Half-initialized WasmMemoryObject escapes ID map](bug-1-halfinit-wasm-memory/README.md) | register-then-fail + ResetIdMap removal | null backstore deref → renderer crash (deterministic SIGSEGV) |
| 2 | [Missing STACK_CHECK in ReadWasmMemory recursion](bug-2-missing-stack-check/README.md) | ReadWasmMemory calls ReadObjectInternal directly | native stack exhaustion → renderer crash |

## Layout

- `bug-1-halfinit-wasm-memory/` — full writeup (root cause, code quotes, PoC streams, variants)
- `bug-2-missing-stack-check/` — full writeup (incl. 80k/300k differential)
- `harness/` — the C++ reproduction harness + build script + the upstream CL patch discussed
- `logs/` — verbatim run logs, gdb dumps, control runs

## Verification environment

Self-contained d8 debug & release builds of V8 15.7.63-era source with the
targeted serializer CL applied to mirror head state; harness links against the
component build. See each bug's README for exact reproduction steps.
