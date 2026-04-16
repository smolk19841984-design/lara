#!/usr/bin/env bash
# build_ipa_wsl.sh — сборка jbdc/ в IPA через WSL + Theos toolchain
# Запуск из PowerShell:  wsl bash scripts/build_ipa_wsl.sh
# Или напрямую в WSL:    bash scripts/build_ipa_wsl.sh
set -euo pipefail

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
echo "  Src       : $PROJECT_DIR/jbdc"

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
  if [[ -d "$APP_TEMPLATE_DIR/assets" ]]; then
    cp -a "$APP_TEMPLATE_DIR/assets" "$app_dir/"
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

LIB_DIR=""
LIB_LINK_MODE=""
STATIC_LINK_FLAGS=()
if [[ -f "$PROJECT_DIR/third_party/build/ios/lib/libxpf.a" && -f "$PROJECT_DIR/third_party/build/ios/lib/libgrabkernel2.a" ]]; then
  LIB_DIR="$PROJECT_DIR/third_party/build/ios/lib"
  LIB_LINK_MODE="static"
  STATIC_LINK_FLAGS=(-framework Security -lcompression -lpartial)
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
SOURCES=()
while IFS= read -r -d '' f; do
  SOURCES+=("$f")
done < <(find "$PROJECT_DIR/jbdc" -name "*.m" ! -name "ppl_test.m" ! -path "*/third_party_bridge/*" -print0 | sort -z)

# ── third_party/darksword-kexploit-fun (Beta вкладка) ──────────────────────
# Все модули third_party портированы в dsfun_all_bridge.m через Lara API.
# Исходные .m/.c файлы third_party НЕ компилируются (конфликты с Lara).
DSFUN_DIR="$PROJECT_DIR/third_party/darksword-kexploit-fun/darksword-kexploit-fun"
DSFUN_SOURCES=()
if [[ -d "$DSFUN_DIR" ]]; then
  # Только bridge — все dsfun_* функции через Lara API
  SOURCES+=("$PROJECT_DIR/jbdc/third_party_bridge/dsfun_all_bridge.m")
  echo "  third_party bridge: 1 (dsfun_all_bridge.m)"
fi

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
  -include "$PROJECT_DIR/jbdc/stubs/compat.h" \
  -I"$PROJECT_DIR/jbdc" \
  -I"$PROJECT_DIR/jbdc/stubs" \
  -I"$PROJECT_DIR/jbdc/views" \
  -I"$PROJECT_DIR/jbdc/funcs" \
  -I"$PROJECT_DIR/jbdc/kexploit" \
  -I"$PROJECT_DIR/jbdc/utils" \
  -I"$PROJECT_DIR/jbdc/third_party_bridge" \
  -I"$PROJECT_DIR/jbdc/TaskRop" \
  -I"$PROJECT_DIR/jbdc/remote" \
  -I"$APP_TEMPLATE_DIR/headers" \
  -I"$PROJECT_DIR/third_party/build/include" \
  -I"$PROJECT_DIR/third_party/build/ios/include" \
  -DDSFUN_EMBEDDED_IN_LARA=1 \
  -I"$DSFUN_DIR/kexploit" \
  -I"$DSFUN_DIR/utils" \
  -I"$DSFUN_DIR/research" \
  -I"$DSFUN_DIR/kpf" \
  -Wl,-u,_DSExploitDidFailNotification \
  -Wl,-exported_symbol,_DSExploitDidFailNotification \
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
  -lz \
  "${STATIC_LINK_FLAGS[@]}" \
  -L"$LIB_DIR" \
  -L"$PROJECT_DIR/third_party/zstd-1.5.5/lib" \
  -lxpf \
  -lgrabkernel2 \
  -lzstd \
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
sync_bundle_assets "$APP_DIR"
strip_optional_bundle_files "$APP_DIR"
warn_missing_bundle_assets "$APP_DIR"
require_bundle_assets "$APP_DIR"

# Ensure bundled helper binaries keep executable bits inside IPA payload.
if [[ -d "$APP_DIR/assets/tools" ]]; then
  chmod +x "$APP_DIR/assets/tools/"* 2>/dev/null || true
fi

# ─── App Icon ─────────────────────────────────────────────────────────────────
ICON_DIR="$BUILD_DIR/icons"
echo "  Иконка    : генерация..."
python3 "$PROJECT_DIR/scripts/generate_icon.py" "$ICON_DIR" 2>&1 | sed 's/^/    /'
# Copy all generated PNGs to the .app root
if [[ -d "$ICON_DIR" ]]; then
  cp "$ICON_DIR"/AppIcon*.png "$APP_DIR/" 2>/dev/null || true
  echo "  Иконка    : OK"
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
  require_bundle_assets "$APP_DIR"
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
