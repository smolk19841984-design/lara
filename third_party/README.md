# third_party (iOS static deps)

This repo **does not** commit large vendored sources/build outputs. They live locally under:

- `third_party/src/` (OpenSSL / curl / zstd sources) — **ignored by git**
- `third_party/build/ios/` (static `.a`, headers, openssl install tree) — **ignored by git**

## What you need for a “real” build

The WSL build expects static libraries in:

- `third_party/build/ios/lib/libssl.a`
- `third_party/build/ios/lib/libcrypto.a`
- `third_party/build/ios/lib/libcurl.a`
- `third_party/build/ios/lib/libzstd.a`

…and real headers in `third_party/build/ios/include/` (notably `curl/*` and `zstd.h`).

## How to build them (WSL)

Run:

```bash
cd /path/to/lara
bash scripts/bootstrap_third_party_ios_wsl.sh
```

Then build IPA as usual:

```bash
LARA_REQUIRE_BUNDLED_ASSETS=1 LARA_STRICT_THIRD_PARTY=1 bash scripts/build_ipa_wsl.sh
```

Notes:

- `LARA_STRICT_THIRD_PARTY=1` makes the build **fail** if `libxpf.a` / `libzstd.a` / `libcurl.a` are still the minimal stub archives.
- `LARA_SKIP_THIRD_PARTY_BOOTSTRAP=1` skips the auto-bootstrap hook inside `scripts/build_ipa_wsl.sh` (faster, but you must already have the `.a` files).

## OpenSSL + Theos SDK symlink

The OpenSSL iOS `ios64-cross` flow typically expects a compatible SDK layout under `/opt/theos/sdks/SDKs/...`.
If your Theos install doesn’t have it yet, you may need a one-time symlink (see the bootstrap script output).
