#!/usr/bin/env bash
# build_ipa_wsl.sh — сборка jbdc/ в IPA через WSL + Theos toolchain
# Запуск из PowerShell:  wsl bash scripts/build_ipa_wsl.sh
# Или напрямую в WSL:    bash scripts/build_ipa_wsl.sh
set -e
set -u
set -o pipefail

# ─── Пути ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

THEOS_TC="/opt/theos/toolchain/linux/iphone"
CLANG="$THEOS_TC/bin/clang"
LDID="$THEOS_TC/bin/ldid"
SDK="/opt/theos/sdks/iPhoneOS16.5.sdk"

APP_NAME="lara"
BUNDLE_ID="com.ruter.lara"
MIN_IOS="15.0"

BUILD_DIR="$PROJECT_DIR/build/wsl"
PAYLOAD_DIR="$BUILD_DIR/Payload"
APP_DIR="$PAYLOAD_DIR/$APP_NAME.app"
IPA_PATH="$PROJECT_DIR/dist/${APP_NAME}.ipa"

ENTITLEMENTS="${LARA_LDID_ENTITLEMENTS:-$PROJECT_DIR/Config/lara.entitlements}"
LARA_LDID_SIGN="${LARA_LDID_SIGN:-1}"

THIRD_PARTY_BUILD_DIR="$PROJECT_DIR/third_party/build/ios"
THIRD_PARTY_LIB_DIR="$THIRD_PARTY_BUILD_DIR/lib"
THIRD_PARTY_INCLUDE_DIR="$THIRD_PARTY_BUILD_DIR/include"

# ─── Проверки ─────────────────────────────────────────────────────────────────
if [[ ! -f "$CLANG" ]]; then
  echo "ERROR: clang не найден по пути $CLANG" >&2
  exit 1
fi
if [[ ! -d "$SDK" ]]; then
  echo "ERROR: SDK не найден: $SDK" >&2
  # Попробуем найти другой
  FOUND=$(ls /opt/theos/sdks/iPhoneOS*.sdk 2>/dev/null | tail -1 || true)
  if [[ -n "$FOUND" ]]; then
    SDK="$FOUND"
    echo "  Используем: $SDK"
  else
    exit 1
  fi
fi

echo "=== Theos clang build: $APP_NAME ==="
echo "  Toolchain : $THEOS_TC"
echo "  SDK       : $SDK"
echo "  Src       : $PROJECT_DIR (root sources)"

APP_TEMPLATE_DIR="$PROJECT_DIR/lara"
if [[ ! -d "$APP_TEMPLATE_DIR" ]]; then
  APP_TEMPLATE_DIR="$PROJECT_DIR/.upstream_rooootdev_lara/lara"
fi
if [[ ! -f "$APP_TEMPLATE_DIR/Info.plist" ]]; then
  echo "ERROR: App template Info.plist не найден: $APP_TEMPLATE_DIR/Info.plist" >&2
  exit 1
fi

warn_missing_bundle_assets() {
  local app_dir="$1"
  local expected=(
    "assets/bootstrap-ssh-iphoneos-arm64.tar.zst"
    "assets/tools/tar"
    "assets/tools/libiosexec.1.dylib"
    "assets/tools/libintl.8.dylib"
  )
  local missing=()
  local rel
  for rel in "${expected[@]}"; do
    if [[ ! -e "$app_dir/$rel" ]]; then
      missing+=("$rel")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    echo "WARNING: bundled bootstrap/helper payload is incomplete." >&2
    printf '  missing: %s\n' "${missing[@]}" >&2
    echo "  IPA will be much smaller than the old ~25 MB builds and offline/bootstrap helper paths may not work." >&2
  fi
}

require_bundle_assets() {
  local app_dir="$1"
  local required=(
    "assets/bootstrap-ssh-iphoneos-arm64.tar.zst"
    "assets/tools/tar"
    "assets/tools/libiosexec.1.dylib"
    "assets/tools/libintl.8.dylib"
  )
  local missing=()
  local rel
  for rel in "${required[@]}"; do
    if [[ ! -e "$app_dir/$rel" ]]; then
      missing+=("$rel")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    echo "ERROR: bundled bootstrap/helper payload was not copied into the app bundle." >&2
    printf '  missing: %s\n' "${missing[@]}" >&2
    exit 1
  fi
}

sync_bundle_assets() {
  local app_dir="$1"
  rm -rf "$app_dir/assets" "$app_dir/Assets.xcassets" "$app_dir/media.xcassets"
  # Prefer real assets from repo root (developer-provided), fall back to app template.
  if [[ -d "$PROJECT_DIR/assets" ]]; then
    cp -a "$PROJECT_DIR/assets" "$app_dir/"
  elif [[ -d "$APP_TEMPLATE_DIR/assets" ]]; then
    cp -a "$APP_TEMPLATE_DIR/assets" "$app_dir/"
  fi

  # Compatibility: some setups provide bootstrap under a slightly different name.
  if [[ -f "$app_dir/assets/bootstrap-iphoneos-arm64.tar.zst" && ! -f "$app_dir/assets/bootstrap-ssh-iphoneos-arm64.tar.zst" ]]; then
    cp -a "$app_dir/assets/bootstrap-iphoneos-arm64.tar.zst" "$app_dir/assets/bootstrap-ssh-iphoneos-arm64.tar.zst"
  fi

  # Normalize tool layout: allow `assets/tar` to be used as `assets/tools/tar`.
  if [[ -f "$app_dir/assets/tar" && ! -f "$app_dir/assets/tools/tar" ]]; then
    mkdir -p "$app_dir/assets/tools"
    cp -a "$app_dir/assets/tar" "$app_dir/assets/tools/tar"
  fi
  if [[ -d "$APP_TEMPLATE_DIR/other/Assets.xcassets" ]]; then
    cp -a "$APP_TEMPLATE_DIR/other/Assets.xcassets" "$app_dir/"
  fi
  if [[ -d "$APP_TEMPLATE_DIR/other/media.xcassets" ]]; then
    cp -a "$APP_TEMPLATE_DIR/other/media.xcassets" "$app_dir/"
  fi
}

strip_optional_bundle_files() {
  local app_dir="$1"
  rm -f "$app_dir/assets/tools/README_DOPAMINE_ORIGIN.md"
}

build_real_choma_xpf_libs() {
  # Build real libchoma + libxpf from in-tree sources when available.
  if [[ ! -d "$PROJECT_DIR/ChOma" || ! -d "$PROJECT_DIR/XPF" ]]; then
    return 0
  fi

  echo "  third_party: building real ChOma/XPF"

  mkdir -p "$THIRD_PARTY_LIB_DIR" "$THIRD_PARTY_INCLUDE_DIR/choma"

  local objdir="$BUILD_DIR/third_party_real_objs"
  rm -rf "$objdir"
  mkdir -p "$objdir/choma" "$objdir/xpf"

  # ── Headers ────────────────────────────────────────────────────────────────
  # ChOma headers are in ChOma/src/*.h (and include/choma in some layouts).
  cp -a "$PROJECT_DIR/ChOma/src/"*.h "$THIRD_PARTY_INCLUDE_DIR/choma/" 2>/dev/null || true
  if [[ -d "$PROJECT_DIR/ChOma/include/choma" ]]; then
    cp -a "$PROJECT_DIR/ChOma/include/choma/"* "$THIRD_PARTY_INCLUDE_DIR/choma/" 2>/dev/null || true
  fi
  cp -a "$PROJECT_DIR/XPF/src/xpf.h" "$THIRD_PARTY_INCLUDE_DIR/" 2>/dev/null || true

  # ── Build libchoma.a ───────────────────────────────────────────────────────
  local choma_sources=()
  while IFS= read -r -d '' f; do choma_sources+=("$f"); done < <(find "$PROJECT_DIR/ChOma/src" -maxdepth 1 -name "*.c" -print0 | sort -z)
  local choma_objs=()
  for f in "${choma_sources[@]}"; do
    local base
    base="$(basename "$f" .c)"
    local o="$objdir/choma/$base.o"
    choma_objs+=("$o")
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fPIC -fvisibility=hidden \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -I"$PROJECT_DIR/ChOma/src" \
      -c "$f" -o "$o"
  done
  "$THEOS_TC/bin/llvm-ar" rcs "$THIRD_PARTY_LIB_DIR/libchoma.a" "${choma_objs[@]}"

  # ── Build libxpf.a ─────────────────────────────────────────────────────────
  local xpf_sources=()
  while IFS= read -r -d '' f; do xpf_sources+=("$f"); done < <(
    find "$PROJECT_DIR/XPF/src" -maxdepth 1 -name "*.c" ! -name "main.c" -print0 | sort -z
  )
  local xpf_objs=()
  for f in "${xpf_sources[@]}"; do
    local base
    base="$(basename "$f" .c)"
    local o="$objdir/xpf/$base.o"
    xpf_objs+=("$o")
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fPIC -fvisibility=hidden -fblocks \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -I"$PROJECT_DIR/XPF/src" \
      -I"$PROJECT_DIR/XPF/external/ChOma/include" \
      -I"$PROJECT_DIR/stubs" \
      -c "$f" -o "$o"
  done
  "$THEOS_TC/bin/llvm-ar" rcs "$THIRD_PARTY_LIB_DIR/libxpf.a" "${xpf_objs[@]}"
}

prepare_root_assets_layout() {
  # Normalize developer-provided assets in $PROJECT_DIR/assets into the layout
  # expected by the app bundle: assets/tools/* and bootstrap-ssh-*.tar.zst.
  if [[ ! -d "$PROJECT_DIR/assets" ]]; then
    return 0
  fi

  mkdir -p "$PROJECT_DIR/assets/tools"

  if [[ -f "$PROJECT_DIR/assets/tar" && ! -f "$PROJECT_DIR/assets/tools/tar" ]]; then
    cp -a "$PROJECT_DIR/assets/tar" "$PROJECT_DIR/assets/tools/tar"
  fi

  if [[ -f "$PROJECT_DIR/assets/libintl.8.dylib" && ! -f "$PROJECT_DIR/assets/tools/libintl.8.dylib" ]]; then
    cp -a "$PROJECT_DIR/assets/libintl.8.dylib" "$PROJECT_DIR/assets/tools/libintl.8.dylib"
  fi

  # Also accept a prebuilt libintl placed in the repo root.
  if [[ -f "$PROJECT_DIR/libintl.8.dylib" ]]; then
    cp -a "$PROJECT_DIR/libintl.8.dylib" "$PROJECT_DIR/assets/tools/libintl.8.dylib"
  fi

  if [[ -f "$PROJECT_DIR/assets/bootstrap-iphoneos-arm64.tar.zst" && ! -f "$PROJECT_DIR/assets/bootstrap-ssh-iphoneos-arm64.tar.zst" ]]; then
    cp -a "$PROJECT_DIR/assets/bootstrap-iphoneos-arm64.tar.zst" "$PROJECT_DIR/assets/bootstrap-ssh-iphoneos-arm64.tar.zst"
  fi

  if [[ -d "$PROJECT_DIR/assets/libiosexec-1.3.1" && ! -f "$PROJECT_DIR/assets/tools/libiosexec.1.dylib" ]]; then
    echo "  assets    : building libiosexec.1.dylib..."
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -dynamiclib -O2 -fvisibility=hidden \
      -Wl,-dead_strip \
      -Wl,-install_name,@executable_path/../Frameworks/libiosexec.1.dylib \
      -I"$PROJECT_DIR/assets/libiosexec-1.3.1" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/execl.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/execv.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/get_new_argv.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/posix_spawn.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/system.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/utils.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/fake_getgrent.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/fake_getpwent.c" \
      "$PROJECT_DIR/assets/libiosexec-1.3.1/fake_getusershell.c" \
      -o "$PROJECT_DIR/assets/tools/libiosexec.1.dylib"
  fi
}

build_stub_third_party_libs() {
  # Build minimal stub versions of libxpf and libgrabkernel2 when the real
  # third_party artifacts are not present in this checkout.
  local ar_bin="$THEOS_TC/bin/llvm-ar"

  mkdir -p "$THIRD_PARTY_LIB_DIR" "$THIRD_PARTY_INCLUDE_DIR/choma"
  mkdir -p "$THIRD_PARTY_INCLUDE_DIR/curl" "$THIRD_PARTY_INCLUDE_DIR/CommonCrypto"

  # Headers used by the app sources
  cp -a "$PROJECT_DIR/stubs/xpf.h" "$THIRD_PARTY_INCLUDE_DIR/" 2>/dev/null || true
  cp -a "$PROJECT_DIR/stubs/libgrabkernel2.h" "$THIRD_PARTY_INCLUDE_DIR/" 2>/dev/null || true
  cp -a "$PROJECT_DIR/stubs/zstd.h" "$THIRD_PARTY_INCLUDE_DIR/" 2>/dev/null || true
  cp -a "$PROJECT_DIR/stubs/curl/curl.h" "$THIRD_PARTY_INCLUDE_DIR/curl/" 2>/dev/null || true
  cp -a "$PROJECT_DIR/stubs/CommonCrypto/CommonDigest.h" "$THIRD_PARTY_INCLUDE_DIR/CommonCrypto/" 2>/dev/null || true
  cp -a "$PROJECT_DIR/stubs/choma/MachO.h" "$THIRD_PARTY_INCLUDE_DIR/choma/" 2>/dev/null || true

  local objdir="$BUILD_DIR/third_party_stub_objs"
  rm -rf "$objdir"
  mkdir -p "$objdir"

  echo "  third_party: building stub libs (missing only)"

  if [[ ! -f "$THIRD_PARTY_LIB_DIR/libxpf.a" ]]; then
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fno-objc-arc \
      -I"$PROJECT_DIR/stubs" \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -c "$PROJECT_DIR/stubs/xpf_stub.c" \
      -o "$objdir/xpf_stub.o"
    "$ar_bin" rcs "$THIRD_PARTY_LIB_DIR/libxpf.a" "$objdir/xpf_stub.o"
  fi

  if [[ ! -f "$THIRD_PARTY_LIB_DIR/libgrabkernel2.a" ]]; then
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fobjc-arc \
      -I"$PROJECT_DIR/stubs" \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -c "$PROJECT_DIR/stubs/libgrabkernel2_stub.m" \
      -o "$objdir/libgrabkernel2_stub.o"
    "$ar_bin" rcs "$THIRD_PARTY_LIB_DIR/libgrabkernel2.a" "$objdir/libgrabkernel2_stub.o"
  fi

  if [[ ! -f "$THIRD_PARTY_LIB_DIR/libzstd.a" ]]; then
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fno-objc-arc \
      -I"$PROJECT_DIR/stubs" \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -c "$PROJECT_DIR/stubs/zstd_stub.c" \
      -o "$objdir/zstd_stub.o"
    "$ar_bin" rcs "$THIRD_PARTY_LIB_DIR/libzstd.a" "$objdir/zstd_stub.o"
  fi

  if [[ ! -f "$THIRD_PARTY_LIB_DIR/libcurl.a" ]]; then
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fno-objc-arc \
      -I"$PROJECT_DIR/stubs" \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -c "$PROJECT_DIR/stubs/curl/curl_stub.c" \
      -o "$objdir/curl_stub.o"
    "$ar_bin" rcs "$THIRD_PARTY_LIB_DIR/libcurl.a" "$objdir/curl_stub.o"
  fi

  if [[ ! -f "$THIRD_PARTY_LIB_DIR/libcommoncrypto.a" ]]; then
    "$CLANG" -target arm64-apple-ios"$MIN_IOS" -isysroot "$SDK" \
      -O2 -fno-objc-arc \
      -I"$PROJECT_DIR/stubs" \
      -I"$THIRD_PARTY_INCLUDE_DIR" \
      -c "$PROJECT_DIR/stubs/CommonCrypto/commoncrypto_stub.c" \
      -o "$objdir/commoncrypto_stub.o"
    "$ar_bin" rcs "$THIRD_PARTY_LIB_DIR/libcommoncrypto.a" "$objdir/commoncrypto_stub.o"
  fi

  # llvm-ar writes the index; no separate ranlib needed.
}

LIB_DIR=""
LIB_LINK_MODE=""
STATIC_LINK_FLAGS=()
STUB_THIRD_PARTY="0"
build_real_choma_xpf_libs

build_stub_third_party_libs

if [[ -f "$THIRD_PARTY_LIB_DIR/libxpf.a" && -f "$THIRD_PARTY_LIB_DIR/libgrabkernel2.a" && -f "$THIRD_PARTY_LIB_DIR/libzstd.a" && -f "$THIRD_PARTY_LIB_DIR/libcurl.a" && -f "$THIRD_PARTY_LIB_DIR/libcommoncrypto.a" ]]; then
  LIB_DIR="$THIRD_PARTY_LIB_DIR"
  LIB_LINK_MODE="static"
  STATIC_LINK_FLAGS=()
elif [[ -f "$APP_TEMPLATE_DIR/lib/libxpf.dylib" && -f "$APP_TEMPLATE_DIR/lib/libgrabkernel2.dylib" ]]; then
  LIB_DIR="$APP_TEMPLATE_DIR/lib"
  LIB_LINK_MODE="dynamic"
else
  echo "ERROR: Не найдены ни static, ни dynamic iOS библиотеки XPF/libgrabkernel2" >&2
  exit 1
fi

# ─── Чистим старый билд ───────────────────────────────────────────────────────
rm -rf "$BUILD_DIR" "$PROJECT_DIR/dist"
mkdir -p "$APP_DIR/Frameworks"

# ─── Собираем список .m файлов ────────────────────────────────────────────────
# В этом checkout директория jbdc/ не компилируется (часть исходников/зависимостей отсутствует).
# Для получения сборочного IPA собираем основное приложение из корня репозитория.
SOURCES=()
while IFS= read -r -d '' f; do
  SOURCES+=("$f")
done < <(
  find "$PROJECT_DIR" \
    -name "*.m" \
    ! -path "$PROJECT_DIR/jbdc/*" \
    ! -path "$PROJECT_DIR/iPad8,9_Analysis/*" \
    ! -path "$PROJECT_DIR/third_party/*" \
    ! -path "$PROJECT_DIR/wsl_minimal/*" \
    ! -path "$PROJECT_DIR/kexploit/ppl_test.m" \
    ! -path "$PROJECT_DIR/rootless/*" \
    ! -path "$PROJECT_DIR/tools/*" \
    ! -path "$PROJECT_DIR/ChOma/*" \
    ! -path "$PROJECT_DIR/XPF/*" \
    ! -path "$PROJECT_DIR/scripts/*" \
    ! -path "$PROJECT_DIR/stubs/*" \
    -print0 | sort -z
)

echo "  Файлов .m/.c : ${#SOURCES[@]}"

# ─── Компиляция ───────────────────────────────────────────────────────────────
BUILD_LOG="$BUILD_DIR/build.log"
mkdir -p "$BUILD_DIR"

"$CLANG" \
  -target arm64-apple-ios"$MIN_IOS" \
  -isysroot "$SDK" \
  -fobjc-arc \
  -Os \
  -Wno-unused-variable \
  -Wno-deprecated-declarations \
  -include "$PROJECT_DIR/stubs/compat.h" \
  -I"$PROJECT_DIR/stubs" \
  -I"$PROJECT_DIR" \
  -I"$PROJECT_DIR/views" \
  -I"$PROJECT_DIR/funcs" \
  -I"$PROJECT_DIR/kexploit" \
  -I"$PROJECT_DIR/utils" \
  -I"$PROJECT_DIR/TaskRop" \
  -I"$PROJECT_DIR/remote" \
  -I"$APP_TEMPLATE_DIR/headers" \
  -I"$PROJECT_DIR/third_party/build/include" \
  -I"$THIRD_PARTY_INCLUDE_DIR" \
  -framework UIKit \
  -framework Foundation \
  -framework AVFoundation \
  -framework Photos \
  -framework PhotosUI \
  -framework CoreGraphics \
  -framework IOSurface \
  -framework IOKit \
  -framework UniformTypeIdentifiers \
  -framework MobileCoreServices \
  -lcompression \
  -lz \
  "${STATIC_LINK_FLAGS[@]}" \
  -L"$LIB_DIR" \
  -lxpf \
  -lchoma \
  -lgrabkernel2 \
  -lzstd \
  -lcurl \
  -lcommoncrypto \
  -Wl,-rpath,@executable_path/Frameworks \
  -Wl,-dead_strip \
  "${SOURCES[@]}" \
  -o "$APP_DIR/$APP_NAME" 2>&1 | tee "$BUILD_LOG"

if [[ ! -f "$APP_DIR/$APP_NAME" ]]; then
  echo "ERROR: компиляция завершилась неудачей. Лог: $BUILD_LOG" >&2
  exit 1
fi

chmod +x "$APP_DIR/$APP_NAME"
echo "  Бинарник  : OK ($(du -h "$APP_DIR/$APP_NAME" | cut -f1))"

# ─── Info.plist ───────────────────────────────────────────────────────────────
cp "$APP_TEMPLATE_DIR/Info.plist" "$APP_DIR/Info.plist"

PLISTUTIL="$THEOS_TC/bin/plistutil"
if command -v plutil >/dev/null 2>&1; then
  PLIST_CMD="plutil"
else
  PLIST_CMD="$PLISTUTIL"
fi

# Используем python3 как универсальный способ изменить plist на Linux
python3 - <<PYEOF
import plistlib, os
path = "$APP_DIR/Info.plist"
with open(path, "rb") as f:
    pl = plistlib.load(f)
pl["CFBundleExecutable"]       = "$APP_NAME"
pl["CFBundleIdentifier"]       = "$BUNDLE_ID"
pl["CFBundleVersion"]          = "1"
pl["CFBundleShortVersionString"] = "1.0"
pl["MinimumOSVersion"]         = "$MIN_IOS"
pl["UIFileSharingEnabled"]     = True
with open(path, "wb") as f:
    plistlib.dump(pl, f, fmt=plistlib.FMT_XML)
PYEOF

echo "  Info.plist: OK"

# ─── Dylibs ───────────────────────────────────────────────────────────────────
if [[ "$LIB_LINK_MODE" == "dynamic" ]]; then
  cp "$LIB_DIR/libxpf.dylib"         "$APP_DIR/Frameworks/"
  cp "$LIB_DIR/libgrabkernel2.dylib" "$APP_DIR/Frameworks/"

  # Правим install_name в dylibs чтобы они находились по @executable_path/Frameworks
  "$THEOS_TC/bin/install_name_tool" \
    -id "@executable_path/Frameworks/libxpf.dylib" \
    "$APP_DIR/Frameworks/libxpf.dylib" 2>/dev/null || true
  "$THEOS_TC/bin/install_name_tool" \
    -id "@executable_path/Frameworks/libgrabkernel2.dylib" \
    "$APP_DIR/Frameworks/libgrabkernel2.dylib" 2>/dev/null || true
fi

echo "  Frameworks: OK ($LIB_LINK_MODE)"

# ─── Assets ───────────────────────────────────────────────────────────────────
prepare_root_assets_layout
sync_bundle_assets "$APP_DIR"
strip_optional_bundle_files "$APP_DIR"
warn_missing_bundle_assets "$APP_DIR"
if [[ "${LARA_REQUIRE_BUNDLED_ASSETS:-0}" == "1" ]]; then
  require_bundle_assets "$APP_DIR"
fi

# Ensure bundled helper binaries keep executable bits inside IPA payload.
if [[ -d "$APP_DIR/assets/tools" ]]; then
  chmod +x "$APP_DIR/assets/tools/"* 2>/dev/null || true
fi

# ─── App Icon ─────────────────────────────────────────────────────────────────
ICON_DIR="$BUILD_DIR/icons"
if [[ -f "$PROJECT_DIR/scripts/generate_icon.py" ]]; then
  echo "  Иконка    : генерация..."
  python3 "$PROJECT_DIR/scripts/generate_icon.py" "$ICON_DIR" 2>&1 | sed 's/^/    /'
  # Copy all generated PNGs to the .app root
  if [[ -d "$ICON_DIR" ]]; then
    cp "$ICON_DIR"/AppIcon*.png "$APP_DIR/" 2>/dev/null || true
    echo "  Иконка    : OK"
  fi
else
  echo "  Иконка    : SKIP (scripts/generate_icon.py не найден)"
fi

# ─── Подпись ldid ─────────────────────────────────────────────────────────────
if [[ "$LARA_LDID_SIGN" == "1" ]]; then
  if [[ ! -f "$LDID" ]]; then
    echo "ERROR: ldid не найден: $LDID" >&2
    exit 1
  fi
  if [[ ! -f "$ENTITLEMENTS" ]]; then
    echo "ERROR: entitlements не найден: $ENTITLEMENTS" >&2
    exit 1
  fi
  echo "  Подпись   : ldid -S$ENTITLEMENTS"
  "$LDID" -S"$ENTITLEMENTS" "$APP_DIR/$APP_NAME"
  if [[ "$LIB_LINK_MODE" == "dynamic" ]]; then
    "$LDID" -S "$APP_DIR/Frameworks/libxpf.dylib"         || true
    "$LDID" -S "$APP_DIR/Frameworks/libgrabkernel2.dylib" || true
  fi
  if [[ -d "$APP_DIR/assets/tools" ]]; then
    while IFS= read -r -d '' helper; do
      "$LDID" -S"$ENTITLEMENTS" "$helper" || "$LDID" -S "$helper" || true
    done < <(find "$APP_DIR/assets/tools" -maxdepth 1 -type f -print0)
  fi
  strip_optional_bundle_files "$APP_DIR"
  if [[ "${LARA_REQUIRE_BUNDLED_ASSETS:-0}" == "1" ]]; then
    require_bundle_assets "$APP_DIR"
  fi
  echo "  Подпись   : OK"
fi

# ─── Генерация TrustCache (Dopamine-like) ──────────────────────────────────────
# Аналогично процессу сборки Dopamine, подготовим TrustCache для бинарников
# Это критически важно для обхода PPL и возможности запуска загруженных демонов.
echo "  TrustCache: генерация map-файла..."
TC_TOOL="$THEOS_TC/bin/trustcache"
if command -v trustcache >/dev/null 2>&1; then
    TC_TOOL="trustcache"
fi

if [[ -f "$TC_TOOL" ]]; then
    "$TC_TOOL" create "$APP_DIR/assets/trustcache.bin" "$APP_DIR/assets/tools" 2>/dev/null || true
    echo "  TrustCache: OK (сформирован trustcache.bin)"
else
    echo "  TrustCache: утилита trustcache не найдена. Пропуск генерации (Используйте fastSign в рантайме)."
fi

# ─── Сборка create_var_jb_helper ─────────────────────────────────────────────
echo "  Helper    : create_var_jb_helper..."
HELPER_SRC="$PROJECT_DIR/tools/create_var_jb_helper.c"
HELPER_DST="$APP_DIR/assets/tools/create_var_jb_helper"
if [[ -f "$HELPER_SRC" ]]; then
  mkdir -p "$APP_DIR/assets/tools"
  "$CLANG" \
    -target arm64-apple-ios"$MIN_IOS" \
    -isysroot "$SDK" \
    -O2 -Wl,-dead_strip -Wl,-pie \
    "$HELPER_SRC" \
    -o "$HELPER_DST"
  chmod +x "$HELPER_DST"
  if [[ "$LARA_LDID_SIGN" == "1" && -f "$LDID" ]]; then
    "$LDID" -S"$ENTITLEMENTS" "$HELPER_DST" || "$LDID" -S "$HELPER_DST" || true
  fi
  echo "  Helper    : OK ($(du -h "$HELPER_DST" | cut -f1))"
else
  echo "  Helper    : SKIP (исходник $HELPER_SRC не найден)"
fi

# ─── Сборка твиков ──────────────────────────────────────────────────────────────
echo "=== Сборка твиков ==="
TWEAKS_DIR="$APP_DIR/tweaks"
mkdir -p "$TWEAKS_DIR"

# Tweaks removed - not working yet

echo ""
# ─── Упаковываем в IPA ────────────────────────────────────────────────────────
mkdir -p "$PROJECT_DIR/dist"
rm -f "$IPA_PATH"
(cd "$BUILD_DIR" && zip -qr "$IPA_PATH" "Payload")
rm -rf "$PAYLOAD_DIR"

echo "=== Готово ==="
echo "  IPA: $IPA_PATH"
echo "  Размер: $(du -h "$IPA_PATH" | cut -f1)"
