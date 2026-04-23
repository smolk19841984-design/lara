# lara

iOS jailbreak-related project. This repository’s **authoritative build notes** live in `doc/`.

## Build (IPA)

- **Main doc**: `doc/BUILD_IPA.md`
- **One-shot 21D61 pipeline (WSL)**: `scripts/rebuild_21D61_wsl.sh` (harness → canonical JSON → generated header → IPA)
- If `third_party/build/ios` is empty on a fresh machine, the build can auto-run `scripts/bootstrap_third_party_ios_wsl.sh` (OpenSSL + curl + zstd). Use `LARA_SKIP_THIRD_PARTY_BOOTSTRAP=1` to force fast link-only builds when you already have the `.a` files.
- For release-like builds, use `LARA_STRICT_THIRD_PARTY=1` (fails the build if `libxpf.a` / `libzstd.a` / `libcurl.a` are still the minimal stub archives).

## Kernel offsets (iPad8,9 / 21D61)

- **Canonical JSON**: `iPad8,9_Analysis/21D61/verified_offsets.json`
- **Generated runtime header**: `kexploit/final_kernel_offsets.h` (do not hand-edit; regenerate via `scripts/generate_final_kernel_offsets_h.py`)
- **Evidence / report**: `doc/OFFSETS_21D61_EVIDENCE.md`, `doc/ANALYSIS_21D61_REPORT.md`
