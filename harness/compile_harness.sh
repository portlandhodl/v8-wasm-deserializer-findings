#!/bin/bash
# Compile PoC harness against sandbox v8 component build.
set -e
V8=/tmp/v8-audit/build/v8
OUT=$V8/out/d
CLANG=$V8/third_party/llvm-build/Release+Asserts/bin/clang++

# Extract the exact -D defines used for d8's own objects, minus frozen strings.
DEFS=$(ninja -C "$OUT" -t commands obj/d8/d8.o | tail -1 | tr ' ' '\n' \
  | grep '^-D' \
  | grep -vE '__DATE__|__TIME__|__TIMESTAMP__|CR_CLANG_REVISION|CR_LIBCXX_REVISION|CR_SYSROOT_KEY' \
  | tr '\n' ' ')

"$CLANG" /tmp/v8-audit/poc/harness.cc \
  -std=c++20 -g -O0 \
  -fno-exceptions -fno-rtti \
  -nostdinc++ \
  -I"$V8/buildtools/third_party/libc++" \
  -isystem"$V8/third_party/libc++/src/include" \
  -isystem"$V8/third_party/libc++abi/src/include" \
  $DEFS \
  -I"$V8/include" -I"$OUT/gen/include" -I"$V8" \
  -L"$OUT" -lv8 -lv8_libplatform -lv8_libbase \
  -Wl,-rpath,"$OUT" \
  "$OUT/libc++.so" \
  -o "$OUT/harness" 2>&1
echo "BUILD_RC=$?"
ls -la "$OUT/harness"
