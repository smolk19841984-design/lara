# Сборка IPA (Windows + WSL + Theos)

## Что собираем

Скрипт `scripts/build_ipa_wsl.sh` собирает `dist/lara.ipa` **внутри WSL**, используя Theos toolchain и iOS SDK из `/opt/theos`.

На текущем этапе проект собирается **без Xcode**.

## Требования

### WSL

- WSL2 установлен
- Дистрибутив: `Ubuntu` (или другой Linux, но пути в командах ниже — под Ubuntu)

### Theos toolchain внутри WSL

Скрипт ожидает:

- `/opt/theos/toolchain/linux/iphone/bin/clang`
- `/opt/theos/toolchain/linux/iphone/bin/ldid`
- `/opt/theos/sdks/iPhoneOS16.5.sdk` (если нет — скрипт пытается найти последний `iPhoneOS*.sdk`)

## Entitlements

Скрипт подписывает бинарники через `ldid`.

По умолчанию он берёт entitlements из:

- `Config/lara.entitlements`

или из переменной окружения:

- `LARA_LDID_ENTITLEMENTS`

## Assets (bootstrap/tools)

Скрипт копирует ассеты в app bundle в `Payload/lara.app/assets`.

Обязательные пути в bundle (при `LARA_REQUIRE_BUNDLED_ASSETS=1`):

- `assets/bootstrap-ssh-iphoneos-arm64.tar.zst`
- `assets/tools/tar`
- `assets/tools/libiosexec.1.dylib`
- `assets/tools/libintl.8.dylib`

Нормализация ассетов делается функцией `prepare_root_assets_layout()` в `scripts/build_ipa_wsl.sh`.

Рекомендуемый layout исходников в репо:

- `assets/bootstrap-iphoneos-arm64.tar.zst` (скрипт сделает копию под `bootstrap-ssh-...`)
- `assets/tools/tar`
- `assets/tools/libiosexec.1.dylib`
- `assets/tools/libintl.8.dylib`

Также допускается `libintl.8.dylib` в корне репозитория: `libintl.8.dylib` — скрипт подхватит и скопирует в `assets/tools`.

## Third-party (XPF/ChOma)

Чтобы XPF реально работал (а не stub), в репозитории присутствуют папки:

- `XPF/`
- `ChOma/`

Скрипт `scripts/build_ipa_wsl.sh` собирает их в статические либы:

- `third_party/build/ios/lib/libxpf.a`
- `third_party/build/ios/lib/libchoma.a`

и кладёт заголовки в:

- `third_party/build/ios/include/xpf.h`
- `third_party/build/ios/include/choma/*`

## Real libcurl (вариант B)

Сейчас `libcurl` **реальный** (не stub) и лежит в:

- `third_party/build/ios/lib/libcurl.a`
- headers: `third_party/build/ios/include/curl/*`

В текущей сборке `libcurl` собирается в WSL из исходников `curl` и линкуется со **статическим OpenSSL**, который также собирается в WSL под iOS arm64.

## Real libzstd

`libzstd` используется **внутри приложения** (для in‑process распаковки `.zst`), поэтому он должен быть реальным.

Артефакты:

- `third_party/build/ios/lib/libzstd.a`
- headers: `third_party/build/ios/include/zstd.h`, `third_party/build/ios/include/zstd_errors.h`

### Rebuild zstd (WSL)

```bash
cd /mnt/c/Users/smolk/Documents/GitHub/lara/third_party/src/zstd/lib
make clean || true
make libzstd.a \
  CC=/opt/theos/toolchain/linux/iphone/bin/clang \
  AR=/opt/theos/toolchain/linux/iphone/bin/llvm-ar \
  RANLIB=/opt/theos/toolchain/linux/iphone/bin/llvm-ranlib \
  CFLAGS="-target arm64-apple-ios14.0 -isysroot /opt/theos/sdks/iPhoneOS16.5.sdk -O2 -fPIC"

cp -a libzstd.a /mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/lib/libzstd.a
cp -a zstd.h zstd_errors.h /mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/include/
```

### Где лежат исходники

- `third_party/src/curl/`
- `third_party/src/openssl/`

### Быстрый rebuild OpenSSL + curl (WSL)

Если нужно пересобрать “с нуля” (внутри WSL):

```bash
cd /mnt/c/Users/smolk/Documents/GitHub/lara

# 1) OpenSSL (static, iOS arm64)
cd third_party/src/openssl
make clean || true

# Важно: OpenSSL ios64-cross ожидает sysroot как /opt/theos/sdks/SDKs/<sdk>.sdk.
# Мы создаём совместимый symlink один раз (как root):
#   /opt/theos/sdks/SDKs/iPhoneOS16.5.sdk -> ../iPhoneOS16.5.sdk

export CROSS_TOP=/opt/theos/sdks
export CROSS_SDK=iPhoneOS16.5.sdk
export CC="/opt/theos/toolchain/linux/iphone/bin/clang -target arm64-apple-ios14.0"
export AR=/opt/theos/toolchain/linux/iphone/bin/llvm-ar
export RANLIB=/opt/theos/toolchain/linux/iphone/bin/llvm-ranlib
export NM=/opt/theos/toolchain/linux/iphone/bin/llvm-nm
export CFLAGS="-O2 -fPIC"

./Configure ios64-cross no-shared no-dso no-apps no-tests \
  --prefix=/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/openssl \
  --openssldir=/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/openssl/ssl

make -j4 build_libs
make install_sw

# 2) curl -> libcurl.a (static, iOS arm64)
cd /mnt/c/Users/smolk/Documents/GitHub/lara/third_party/src/curl
autoreconf -fi
rm -rf build-ios && mkdir build-ios && cd build-ios

export CC=/opt/theos/toolchain/linux/iphone/bin/clang
export AR=/opt/theos/toolchain/linux/iphone/bin/llvm-ar
export RANLIB=/opt/theos/toolchain/linux/iphone/bin/llvm-ranlib
export CFLAGS="-target arm64-apple-ios14.0 -isysroot /opt/theos/sdks/iPhoneOS16.5.sdk -O2 -fPIC"
export CPPFLAGS="-target arm64-apple-ios14.0 -isysroot /opt/theos/sdks/iPhoneOS16.5.sdk -I/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/openssl/include"
export LDFLAGS="-target arm64-apple-ios14.0 -isysroot /opt/theos/sdks/iPhoneOS16.5.sdk -L/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/openssl/lib"
export LIBS="-lz"

../configure \
  --host=aarch64-apple-darwin \
  --prefix=/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios \
  --disable-shared --enable-static \
  --with-openssl=/mnt/c/Users/smolk/Documents/GitHub/lara/third_party/build/ios/openssl \
  --without-libpsl \
  --without-libidn2 --without-brotli --without-zstd --without-nghttp2 \
  --disable-ldap --disable-ldaps \
  --disable-rtsp --disable-dict --disable-telnet --disable-tftp \
  --disable-pop3 --disable-imap --disable-smtp --disable-gopher --disable-mqtt \
  --disable-manual --disable-unix-sockets --disable-alt-svc --disable-hsts

make -j4
make install
```

## Команда сборки

Из PowerShell (в корне репозитория):

```powershell
wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/smolk/Documents/GitHub/lara && LARA_REQUIRE_BUNDLED_ASSETS=1 bash scripts/build_ipa_wsl.sh"
```

### Полный “канонический” прогон 21D61 (harness → JSON → header → IPA)

Если нужно **пересобрать** оффсетный канон *перед* сборкой (рекомендуемый поток для iPad8,9 / 21D61), используйте:

```bash
# внутри WSL
cd /mnt/c/Users/smolk/Documents/GitHub/lara
bash scripts/rebuild_21D61_wsl.sh
```

Что делается по цепочке:

- `scripts/offline_ios17_kernelmap.py` → `iPad8,9_Analysis/21D61/verified_offsets.json` (source of truth)
- `scripts/generate_final_kernel_offsets_h.py` → `kexploit/final_kernel_offsets.h` (автоген, не править руками)

Зеркало артефактов (копия канона) лежит в `offset/`.

#### Runtime‑гейты, связанные с оффсетами

- `LARA_ENABLE_AMFI_PATCH=1` — **опционально**; включает регистрацию AMFI‑патча только если `cs_enforcement_disable` в каноне стал `Verified` (иначе остаётся 0 / отключён).

Результат:

- `dist/lara.ipa`

## Где смотреть логи

- `build/wsl/build.log` — stdout/stderr компиляции/линковки (создаётся скриптом).

## Git: что обычно НЕ коммитят

В `.gitignore` намеренно отфильтрованы крупные локальные артефакты, которые **пересобираются** в WSL:

- `third_party/src/`, `third_party/build/`
- очень большие offline‑входы вроде `iPad8,9_Analysis/21D61/kernelcache_decompressed/`
- промежуточные логи `iPad8,9_Analysis/analysis_outputs/`

Каноничные результаты анализа/оффсетов, которые **имеет смысл** хранить в git, — это, например:

- `iPad8,9_Analysis/21D61/verified_offsets.json`
- `kexploit/final_kernel_offsets.h` (если вы коммитите autogen как часть release‑потока)
- `offset/*` (зеркальные копии/артефакты)

