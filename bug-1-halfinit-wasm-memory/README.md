# CRBUG DRAFT 1 — paste into issues.chromium.org (mark as Security)

**Title:**
[serializer] ValueDeserializer::ReadWasmMemory registers half-initialized WasmMemoryObject in ID map; reachable via reference -> deterministic renderer crash

**Component:** Blink>JavaScript>Runtime
**Type/Priority:** Bug-Security (renderer crash), suggest P2
**Labels:** Security_Severity-Medium (suggestion), Restrictions: need triage

---

## Summary

In V8's value deserializer, `ValueDeserializer::ReadWasmMemory` allocates a `WasmMemoryObject` with a **null backing store** and registers it into the deserializer's ID map **before** reading the inner `JSArrayBuffer` for the transfer. If that inner read fails, the half-initialized object stays registered and can be surfaced to JavaScript via a later `kObjectReference`. Any JS touch of the object (`.buffer`, `.grow(...)`, instantiation) dereferences the null backing store — a deterministic renderer-process SIGSEGV.

This regressed in `d183128c4965` ("[serializer] Check delegate in ReadWasmMemory; drop ResetIdMap", Aug-Oct 2026, Bug 566727937): that CL correctly added `if (delegate_ == nullptr) return {};`, but **all production Blink deserialization paths run with a delegate** (`blink::V8ScriptValueDeserializer(ForModules)`, third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.cc:191-194), and the same CL removed the `ResetIdMap()` fallback that previously destroyed failed-pass residue.

Verified at V8 main `c518b1c983fa` (latest as of 2026-10-13); the defective shape predates that tip and applies to current Chrome Canary (157.x).

## Root cause (code)

File: `src/objects/value-serializer.cc` (head c518b1c983fa):

```cpp
Maybe<Handle<Object>> ValueDeserializer::ReadWasmMemory() {
  // d183128c4965 guard: only covers delegate_ == nullptr
  if (delegate_ == nullptr) return {};

  ...                                     // page/max_pages validation
  DirectHandle<WasmMemoryObject> result =
      WasmMemoryObject::New(isolate_, MaybeDirectHandle<JSArrayBuffer>{},
                            nullptr, maximum_pages, address_type);   // ~:2561
  AddObjectWithID(id, result);            // ~:2565  <-- registered too early

  if (!ReadObjectInternal().ToHandle(&buffer_object)) return {};  // ~:2569, may fail
  // further failure exits at :2570/:2573 leave the half-built WMO behind
  ...
}
```

With the post-`d183128c4965` removal of `ResetIdMap()` from the version-13 compatibility retry path (~:1662 pre-fix), the registered half-built object survives stream failure, and a subsequent `kObjectReference(0)` on the same deserializer (multi-value `ReadValue`, or the v13 retry pass following an earlier failed stream) materializes it as an ordinary JS-visible `WebAssembly.Memory` whose `managed_backing_store` / `backing_store` shared_ptr is `nullptr`.

## Reproduction (binary-verified)

Minimal harness: subclass `v8::ValueDeserializer::Delegate`, feed the stream:

```
ff 10                     // wire header, version 16
6d 00 00                  // kWasmMemoryTransfer, min=0 pages, max=0 pages
42 00                     // kArrayBuffer non-shared (invalid inner backing) -> fails
5e 00                     // kObjectReference id=0 -> resurfaces the half-built WMO
```

then touch the result from JS (`wmo.buffer`).

Observed on self-built d8-level harness at the pinned head-main revision:

```
Thread 1 "harness" received signal SIGSEGV
RefreshBuffer () at ../../src/wasm/wasm-objects.cc:1034
1034  const SharedFlag bs_shared = backing_store->is_shared();
#1 GetArrayBuffer (wasm-objects.cc:1211)
#2 WebAssemblyMemoryGetBufferImpl (wasm-js.cc:2678)
fault address 0x48  (r13 == 0)              exit 139
```

Variants (all deterministic):
- Inner object = `kSharedArrayBuffer` whose delegate lookup fails (the browser-realistic shape, since browsers always serialize wasm memory via a shared-SAB transfer id): identical SIGSEGV.
- `wmo.grow(0)`: SIGSEGV at `WebAssemblyMemoryGrowImpl` (wasm-js.cc:2645, `backing_store->byte_length()`, fault addr 0x8).

Attachments: `harness.cc` (full repro), `run_c1.log`, `run_c1sab.log`, `run_c1grow.log`, `run_c1ctrl.log` (control: no crash), `c1_gdb.txt`, `RESULTS.txt`.

## Impact

Deterministic renderer-process crash (tab/worker crash). Faulting accesses are null + small constant offsets (0x48 / 0x8); no attacker-controlled pointer arithmetic, no controlled read/write, no info leak observed. Severity class: **renderer DoS**. On our severity expectations this likely maps to Medium-max.

## Delivery surface (honest analysis)

Raw, attacker-supplied deserializer bytes are not directly web-mintable today: Blink writes only wire version 21 and "for storage" serialization rejects SharedArrayBuffer/WebAssembly-memory tags outright, so postMessage/structuredClone/IDB writes from a malicious page produce well-formed output. Realistic exposure:
(1) persisted stores that must remain readable for legacy versions — IndexedDB LevelDB values are never migrated and legacy wire-version-13 entries from ~2021-era Chrome exist on real profile disks; session-history state; persistent-notification payloads;
(2) a previously compromised renderer (post-exploitation persistence via its origin's stores);
(3) local profile tampering / opaque `mojom::IDBValue` byte injection.
Cross-checked against Blink entry points in Chromium 157 tip-of-tree (file list available on request).

## Suggested fix

In `ReadWasmMemory`, defer `AddObjectWithID` until after the inner buffer read and full validation (or un-register on the failure exits), restoring the local invariant "no incomplete WasmMemoryObject in id_map_" that `ResetIdMap` used to enforce globally. Regression test: extend `test/unittests/objects/value-serializer-unittest.cc` with a delegate-bearing deserializer feeding the above stream; assert both `ReadValue` calls fail/return empty and no WMO becomes referenceable.

## Notes

- Related-but-separate missing-stack-check bug in the same function filed separately.
- Full audit provenance available; this was found by source audit at current V8 main and verified with the attached binary harness (debug and release).
