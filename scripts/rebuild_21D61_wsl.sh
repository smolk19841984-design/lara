#!/usr/bin/env bash
set -euo pipefail

# One-command rebuild for iPad8,9 iOS 17.3.1 (21D61):
# - regenerates canonical verified offsets JSON from offline harness (Mach-O derived kernel base)
# - regenerates runtime header from that JSON
# - builds signed IPA via existing WSL pipeline

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 scripts/offline_ios17_kernelmap.py
python3 scripts/generate_final_kernel_offsets_h.py

export LARA_REQUIRE_BUNDLED_ASSETS="${LARA_REQUIRE_BUNDLED_ASSETS:-1}"
export LARA_STRICT_THIRD_PARTY="${LARA_STRICT_THIRD_PARTY:-1}"
bash scripts/build_ipa_wsl.sh

echo ""
echo "[+] Done"
echo "    IPA: $ROOT_DIR/dist/lara.ipa"
