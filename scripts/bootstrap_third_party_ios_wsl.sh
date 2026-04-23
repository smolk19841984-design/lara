#!/usr/bin/env bash
set -euo pipefail

# Build iOS arm64 static third-party libs into:
#   third_party/build/ios/{lib,include,openssl}
#
# Sources are expected at:
#   third_party/src/openssl
#   third_party/src/curl
#   third_party/src/zstd/lib
#
# This script is intentionally explicit (no hidden downloads).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

THEOS_TC="${THEOS_TC:-/opt/theos/toolchain/linux/iphone}"
CLANG="${CLANG:-$THEOS_TC/bin/clang}"
AR="${AR:-$THEOS_TC/bin/llvm-ar}"
RANLIB="${RANLIB:-$THEOS_TC/bin/llvm-ranlib}"
NM="${NM:-$THEOS_TC/bin/llvm-nm}"

SDK="${SDK:-/opt/theos/sdks/iPhoneOS16.5.sdk}"
MIN_IOS="${MIN_IOS:-14.0}"

PREFIX="$ROOT_DIR/third_party/build/ios"
OPENSSL_PREFIX="$PREFIX/openssl"
OUT_LIB="$PREFIX/lib"
OUT_INC="$PREFIX/include"

OPENSSL_SRC="$ROOT_DIR/third_party/src/openssl"
CURL_SRC="$ROOT_DIR/third_party/src/curl"
ZSTD_SRC="$ROOT_DIR/third_party/src/zstd/lib"

need_file() {
  if [[ ! -f "$1" ]]; then
    echo "ERROR: missing required file: $1" >&2
    exit 1
  fi
}

need_file "$CLANG"
need_file "$AR"
need_file "$OPENSSL_SRC/Configure"
need_file "$CURL_SRC/configure"
need_file "$ZSTD_SRC/Makefile"

mkdir -p "$OUT_LIB" "$OUT_INC" "$OPENSSL_PREFIX"

echo "=== bootstrap third_party (iOS arm64) ==="
echo "  SDK   : $SDK"
echo "  clang : $CLANG"
echo "  out   : $PREFIX"

if [[ ! -d "$SDK" ]]; then
  echo "ERROR: iOS SDK not found: $SDK" >&2
  exit 1
fi

# OpenSSL expects this layout for ios64-cross.
if [[ ! -d "/opt/theos/sdks/SDKs" ]]; then
  echo "ERROR: expected /opt/theos/sdks/SDKs to exist (OpenSSL iOS build)" >&2
  exit 1
fi
if [[ ! -e "/opt/theos/sdks/SDKs/iPhoneOS16.5.sdk" && -d "/opt/theos/sdks/iPhoneOS16.5.sdk" ]]; then
  echo "NOTE: creating compat symlink /opt/theos/sdks/SDKs/iPhoneOS16.5.sdk -> ../iPhoneOS16.5.sdk (needs sudo once)" >&2
  sudo ln -sfn "../iPhoneOS16.5.sdk" "/opt/theos/sdks/SDKs/iPhoneOS16.5.sdk"
fi

# 1) OpenSSL (static)
if [[ ! -f "$OUT_LIB/libssl.a" || ! -f "$OUT_LIB/libcrypto.a" ]]; then
  echo "  [1/3] building openssl..."
  cd "$OPENSSL_SRC"
  make clean >/dev/null 2>&1 || true

  export CROSS_TOP=/opt/theos/sdks
  export CROSS_SDK=iPhoneOS16.5.sdk
  export CC="$CLANG -target arm64-apple-ios$MIN_IOS"
  export AR="$AR"
  export RANLIB="$RANLIB"
  export NM="$NM"
  export CFLAGS="-O2 -fPIC"

  ./Configure ios64-cross no-shared no-dso no-apps no-tests \
    --prefix="$OPENSSL_PREFIX" \
    --openssldir="$OPENSSL_PREFIX/ssl"

  make -j"$(nproc 2>/dev/null || echo 4)" build_libs
  make install_sw

  # Installed libs go under openssl/lib; copy to unified lib dir for our linker line.
  cp -a "$OPENSSL_PREFIX/lib/libssl.a" "$OUT_LIB/libssl.a"
  cp -a "$OPENSSL_PREFIX/lib/libcrypto.a" "$OUT_LIB/libcrypto.a"
  # Headers for -I
  rm -rf "$OUT_INC/openssl" 2>/dev/null || true
  cp -a "$OPENSSL_PREFIX/include/openssl" "$OUT_INC/"
else
  echo "  [1/3] openssl: OK (skipping)"
fi

# 2) curl (static)
if [[ ! -f "$OUT_LIB/libcurl.a" ]]; then
  echo "  [2/3] building curl..."
  cd "$CURL_SRC"
  autoreconf -fi
  rm -rf "$ROOT_DIR/build/wsl/curl_build_ios" && mkdir -p "$ROOT_DIR/build/wsl/curl_build_ios"
  cd "$ROOT_DIR/build/wsl/curl_build_ios"

  export CC="$CLANG"
  export AR="$AR"
  export RANLIB="$RANLIB"
  export CFLAGS="-target arm64-apple-ios$MIN_IOS -isysroot $SDK -O2 -fPIC"
  export CPPFLAGS="-target arm64-apple-ios$MIN_IOS -isysroot $SDK -I$OPENSSL_PREFIX/include"
  export LDFLAGS="-target arm64-apple-ios$MIN_IOS -isysroot $SDK -L$OPENSSL_PREFIX/lib"
  export LIBS="-lz"

  "$CURL_SRC/configure" \
    --host=aarch64-apple-darwin \
    --prefix="$PREFIX" \
    --disable-shared --enable-static \
    --with-openssl="$OPENSSL_PREFIX" \
    --without-libpsl \
    --without-libidn2 --without-brotli --without-zstd --without-nghttp2 \
    --disable-ldap --disable-ldaps \
    --disable-rtsp --disable-dict --disable-telnet --disable-tftp \
    --disable-pop3 --disable-imap --disable-smtp --disable-gopher --disable-mqtt \
    --disable-manual --disable-unix-sockets --disable-alt-svc --disable-hsts

  make -j"$(nproc 2>/dev/null || echo 4)"
  make install
else
  echo "  [2/3] curl: OK (skipping)"
fi

# 3) zstd (static)
if [[ ! -f "$OUT_LIB/libzstd.a" ]]; then
  echo "  [3/3] building zstd (lib)..."
  cd "$ZSTD_SRC"
  make clean >/dev/null 2>&1 || true
  make libzstd.a \
    CC="$CLANG" \
    AR="$AR" \
    RANLIB="$RANLIB" \
    CFLAGS="-target arm64-apple-ios$MIN_IOS -isysroot $SDK -O2 -fPIC" \
    -j"$(nproc 2>/dev/null || echo 4)"

  cp -a libzstd.a "$OUT_LIB/libzstd.a"
  cp -a zstd.h zstd_errors.h "$OUT_INC/" 2>/dev/null || true
else
  echo "  [3/3] zstd: OK (skipping)"
fi

echo "=== bootstrap third_party: OK ==="
ls -la "$OUT_LIB" | head
