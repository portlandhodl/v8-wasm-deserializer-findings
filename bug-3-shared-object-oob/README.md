# Finding #3 — `SharedObjectConveyor::GetPersisted` DCHECK-only bounds check → OOB read with a real bypass ladder

**State:** NEW, currently unfixed at V8 head (`c518b1c983fa`, 2026-10-13). Binary-verified end-to-end in a sandbox harness. **Important scope note:** on *default Chromium builds* this collapses to a clean `SIGABRT` (see "Mitigation reality" below — this is why it's a hardening report rather than a full exploit writeup).

## The bug (one line)

`ValueDeserializer::ReadSharedSharedObject` passes an attacker-controlled 32-bit `shared_object_id` from the serialized byte stream into `SharedObjectConveyor::GetPersisted`, whose only bounds check is a `DCHECK` — absent from release builds:

```cpp
// src/handles/shared-object-conveyor-handles.h
bool HasPersisted(uint32_t object_id) const {
  return object_id < shared_objects_.size();   // exists but only used in the DCHECK
}

Tagged<HeapObject> GetPersisted(uint32_t object_id) const {
  DCHECK(HasPersisted(object_id));              // ← release: gone
  return *shared_objects_[object_id];            // ← release: OOB read + pointer chase
}
```

`shared_objects_` is `std::vector<Handle<HeapObject>>` (element = 8-byte pointer to a handle slot). `GetPersisted` dereferences the pointer once more through `*location()`, so the read is a two-level indirection: `*(shared_objects_.data() + 8·K)` → pointer `P`, then `*P` → the returned tagged value. That tagged value is handed back as the JS-visible deserialized value.

## Reachability (why it's latent today)

The `kSharedObject` tag only appears in wire-format ≥ 15 streams whose deserializer has a non-null conveyor. In stable Chrome:

- Conveyors only exist when `--harmony-struct` (experimental, flag-gated, not in Blink by default) lets a page create shared JS values (SharedStructType, Atomics.Mutex) AND the stream stays within one renderer process (structuredClone, same-process postMessage, workers/worklets)
- Every mojo/IPC boundary strips the conveyor → the read path fail-closes (`return {}`)
- Persisted stores (IndexedDB, history, notifications) are `for_storage`, which **rejects** conveyor attachment at the serializer

⇒ **No default-configuration web-content reachability.** The bug is latent until `harmony_struct` ships; the missing bounds check needs to already be fixed by then.

## Binary verification (sandbox, deep harness)

All confirmed via the accompanying `harness_sobj.cc` (in this directory) against self-built d8 rel/debug from V8 `c518b1c983fa`:

- **Stage 0 (debug):** huge-K stream aborts with `Fatal error in shared-object-conveyor-handles.h, line 44 — Debug check failed: HasPersisted` — proves the guard is DCHECK-only.
- **Stage 1 (baseline):** public-API path built: serialize a graph containing shared values with a delegate that retains the adopted conveyor, then deserialize mutated bytes against that conveyor. Full setup is pure public V8 API + `--harmony-struct`.
- **Stage 2 (non-hardened build crash):** `HARDENING_MODE_NONE` rebuild → K=0x7fffffff → **SIGSEGV at `vec_begin + 8·K`**, gdb bt #0 `GetPersisted` (#1 `ReadSharedObject` value-serializer.cc:2644). Clean SIGSEGV on the OOB vector load.
- **Stage 3 (infoleak, non-hardened build):** the OOB word surfaced as a **JS `number`** with attacker-transparent semantics:
  - Controlled Smi: `v === 1337` — **20/20** runs with C++ heap spray, **17/20** with pure-JS ArrayBuffer spray
  - Garbage Smi: uncontrolled adjacent-heap qwords leak (`-159172560`) even at zero-spray on some layouts
- **Stage 4 (fake object, non-hardened build):** crafted control-block word = tagged pointer into an in-cage `FixedDoubleArray` containing `[realHeapNumberMap | 0x1337133713371337]` → `''+v === "4.183559446463817e-216"` — **bit-exact fake-object-as-JS-number primitive**.

(Encoding correction vs. initial theory: leaked Smi decodes as `low32(word)>>1`, not `word>>32`. Post-GC the HeapObject-form value dangles as expected; the Smi form survives GC.)

## Mitigation reality — the reason it's "Medium/Low hardening" not "Critical"

Default Chromium/V8 release configs compile with `enable_safe_libcxx=true` → `_LIBCPP_HARDENING_MODE=EXTENSIVE` → `std::vector::operator[]` is **bounds-checked even in release**. On those builds every OOB attempt becomes a clean `SIGABRT` (abort, no data leak) — i.e., the production-browser exposure is DoS-class library abort, not the free read shown above. The full leak/fake-object ladder only materializes on non-hardened STLs (custom embedders, some d8 builds). **VRP classification therefore stays Medium/Low as a hardening gap; a bounty is unlikely** — the report value is getting a real `SBXCHECK`/`CHECK` in before `harmony_struct` ships.

## Suggested fix

Promote the guard to a compiled-in check in release:

```cpp
Tagged<HeapObject> GetPersisted(uint32_t object_id) const {
  SBXCHECK(HasPersisted(object_id));   // or CHECK depending on threat-model intent
  return *shared_objects_[object_id];
}
```

plus a regression test feeding `[0xFF, 0x0F, 0x70, ...]` with an out-of-range id against a delegate-provided conveyor.

## Related reports in this repo

- Issue #1 — incomplete-WasmMemoryObject escape (crash only, no info path)
- Issue #2 — missing `STACK_CHECK` recursion (DoS only)

All three were found in one audit sweep of the same file family; #1/#2 are confirmed-unfixed in head-canary binaries today, #3's DCHECK-only status is confirmed in source at head.
