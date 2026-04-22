#!/usr/bin/env bash
set -euo pipefail

# Build libintl (gettext) as arm64 iOS dylib using Theos toolchain in WSL
# Usage: bash scripts/build_libintl_wsl.sh [gettext-version]

VER=${1:-0.21}
NAME=gettext-${VER}
TARBALL=${NAME}.tar.xz
URL=https://ftp.gnu.org/gnu/gettext/${TARBALL}

THEOS_TC=${THEOS_TC:-/opt/theos/toolchain/linux/iphone}
CLANG=${THEOS_TC}/bin/clang
SDK_DIR=${SDK_DIR:-/opt/theos/sdks}
# Find latest iPhoneOS SDK directory reliably
SDK=$(find "$SDK_DIR" -maxdepth 1 -type d -name "iPhoneOS*.sdk" 2>/dev/null | sort | tail -n1 || true)
if [ -z "$SDK" ]; then
  echo "ERROR: No iPhoneOS SDK found under $SDK_DIR"
  exit 1
fi
MIN_IOS=${MIN_IOS:-15.0}

if [ ! -x "$CLANG" ]; then
  echo "ERROR: clang not found at $CLANG"
  exit 1
fi
if [ -z "$SDK" ]; then
  echo "ERROR: iOS SDK not found under $SDK_DIR"
  exit 1
fi

WD=$(pwd)
BUILD_DIR=$(mktemp -d /tmp/build-libintl-XXXX)
echo "Building in $BUILD_DIR"
cd "$BUILD_DIR"

echo "Downloading $URL..."
curl -L -o "$TARBALL" "$URL"
tar -xf "$TARBALL"
cd "$NAME"

echo "DEBUG: THEOS_TC=$THEOS_TC"
echo "DEBUG: SDK_DIR=$SDK_DIR"
echo "DEBUG: DETECTED_SDK=$SDK"

export CC="${CLANG} -isysroot ${SDK} -target arm64-apple-ios${MIN_IOS}"
export CFLAGS="-fPIC -O2"
export CPPFLAGS="-isysroot ${SDK} -I${SDK}/usr/include"
export LDFLAGS="-isysroot ${SDK} -Wl,-dead_strip -L${SDK}/usr/lib"
export PKG_CONFIG=""

PREFIX="$BUILD_DIR/install"
mkdir -p "$PREFIX"

echo "Configuring for host=arm-apple-darwin..."
./configure --host=arm-apple-darwin --with-sysroot="$SDK" --enable-shared --disable-static --prefix="$PREFIX" \
  CFLAGS="$CFLAGS" CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" CC="$CC" || true

# Some gettext releases use libtool/autoconf that fail with cross tools; try a fallback configure
if [ $? -ne 0 ]; then
  echo "Configure failed; saving config.log for inspection"
  if [ -f config.log ]; then
    cp config.log "$WD/config-gettext-config.log" || true
  fi
  echo "Attempting fallback configure with static build to gather objects"
  ./configure --host=arm-apple-darwin --with-sysroot="$SDK" --enable-static --disable-shared --prefix="$PREFIX" \
      CFLAGS="$CFLAGS" CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" CC="$CC" || true
fi

echo "Running make..."
make -j$(nproc || echo 2) || true
echo "Installing..."
make install || true

OUTLIB=""
if [ -f "$PREFIX/lib/libintl.8.dylib" ]; then
  OUTLIB="$PREFIX/lib/libintl.8.dylib"
elif [ -f "$PREFIX/lib/libintl.dylib" ]; then
  OUTLIB="$PREFIX/lib/libintl.dylib"
fi

if [ -z "$OUTLIB" ]; then
  echo "Shared lib not produced by configure+make. Attempting to build dylib from object files..."
  # Find .la or .a or object files
  LIBOBJS=$(find . -name "*.la" -o -name "*.a" -o -name "*.o" 2>/dev/null || true)
  # Try to locate .libs or intl/libintl*.so equivalent
  if [ -d .libs ]; then
    OBJDIR=.libs
  else
    OBJDIR=$(pwd)
  fi
  # Collect object files under src/.libs or .
  OBJS=$(find $OBJDIR -name "*.o" -print)
  if [ -z "$OBJS" ]; then
    echo "No object files to link into dylib. Build failed." >&2
    exit 1
  fi
  OUTLIB="$PREFIX/lib/libintl.8.dylib"
  mkdir -p "$(dirname $OUTLIB)"
  echo "Linking dynamic library to $OUTLIB"
  LINKER="${THEOS_TC}/bin/clang -isysroot ${SDK} -target arm64-apple-ios${MIN_IOS}"
  # Link with CoreFoundation framework and libiconv which gettext depends on
  $LINKER -dynamiclib -o "$OUTLIB" $OBJS \
    -isysroot "$SDK" -L"${SDK}/usr/lib" -liconv -framework CoreFoundation \
    -Wl,-dead_strip -install_name @rpath/libintl.8.dylib || true
fi

if [ -f "$OUTLIB" ]; then
  echo "Built: $OUTLIB"
  cp "$OUTLIB" "$WD/" || true
  echo "Copied result to project root: $(basename $OUTLIB)"
  echo "Done."
else
  echo "Failed to produce libintl dylib. Inspect build logs in $BUILD_DIR" >&2
  exit 1
fi

echo "Build directory preserved: $BUILD_DIR"
