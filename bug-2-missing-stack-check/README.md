# CRBUG DRAFT 2 — paste into issues.chromium.org (mark as Security)

**Title:**
[serializer] ValueDeserializer::ReadWasmMemory recurses into ReadObjectInternal without a stack check -> attacker-controlled native stack exhaustion

**Component:** Blink>JavaScript>Runtime
**Type/Priority:** Bug-Security (renderer crash), suggest P3/P2
**Labels:** Security_Severity-Low/Medium (suggestion)

---

## Summary

`ValueDeserializer::ReadWasmMemory` calls `ReadObjectInternal()` **directly**, bypassing the dispatcher `ReadObject()` — the only place containing a `STACK_CHECK`. Consequently a `kWasmMemoryTransfer`-nested stream drives unbounded native recursion (`ReadWasmMemory -> ReadObjectInternal -> ReadWasmMemory -> ...`) with ~3 attacker bytes per native frame, producing a native stack-overflow crash instead of a graceful deserialize error.

Verified at V8 main `c518b1c983fa` (2026-10-13).

## Root cause (code)

`src/objects/value-serializer.cc`:

- Guarded path: `ReadObject` at ~:1676 contains `STACK_CHECK(isolate_, return {});` (~:1679).
- Unguarded path: `ReadWasmMemory` (~:2532) calls `ReadObjectInternal()` directly at ~:2569.
- `ReadObjectInternal` has exactly **two** callers: :1681 (guarded) and :2569 (unguarded).
- Every other recursive container reader (`ReadJSObject` ~:1893, sparse array ~:1916, dense array ~:1946, `ReadJSMap` ~:2100, `ReadJSSet` ~:2141, `ReadSharedObject` ~:2617, `ReadHostObject` ~:2652) implements its own or inherits the guarded dispatch — audit table available on request.

## Reproduction (binary-verified)

Stream: `ff 10` + N copies of `6d 00 00` (kWasmMemoryTransfer + zeros) + `42 00` (kArrayBuffer terminator).

Observed on instrumented d8-level harness (attached):

| N | Outcome |
|---|---|
| 80,000  | Graceful failure ("Unable to deserialize cloned data"), exit 0 |
| 300,000 | **SIGSEGV** — repeating `ReadWasmMemory (value-serializer.cc:2569) <-> ReadObjectInternal` frames down to the ~8 MB stack limit (gdb captured) |

N=300k => ~270–900 KB input payload. Attachments: `run_c2_80k.log`, `run_c2_300k.log`, `c2_gdb.txt`.

## Impact

Renderer-process crash (tab/worker DoS) from a moderately-sized serialized byte stream. Delivery constraints match those of the companion report (legacy persisted stores, version skew, second-order/persistence injection) — no pure-web-content trigger was identified because Blink's serializer does not emit `kWasmMemoryTransfer` in the current wire version.

## Suggested fix

Route the recursive descent in `ReadWasmMemory` through `ReadObject()` (or add a local `STACK_CHECK` before calling `ReadObjectInternal`). Regression test mirroring the 80k/300k boundary above in `value-serializer-unittest.cc`.

## Notes

Found by audit of the register/recursion surfaces after examining the `d183128c4965` fix; binary-verified with the attached harness. Companion bug (half-initialized WasmMemoryObject ID-map escape, same function) filed separately.
