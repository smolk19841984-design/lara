#!/usr/bin/env python3
"""
Download IPSW from Apple (via api.ipsw.me), extract firmware artifacts for static analysis.

Default device/build: iPad8,9 + 17.3.1 build 21D61 — override with --device / --build.

Outputs under: <repo>/iPad8,9_Analysis/<BUILD>/extracted/
  - kernelcache raw + kernelcache.decompressed.macho (via ../decompress_kernelcache.py)
  - BuildManifest.plist, Restore.plist
  - DeviceTree / Firmware payloads (img4, etc.)
  - *.dmg copied to dmg/ when --include-dmg (large)
  - EXTRACT_MANIFEST.json (paths, sizes, sha256)

Requires: Python 3.8+
Optional: pip install pyliblzfse  (for LZFSE kernelcache decompression)
Optional: blacktop/ipsw in PATH for further dmg/apfs work (see manifest notes).

Already unpacked (typical ipsw / ``ipsw kernel extract`` layout) — no IPSW download needed:
  ``iPad8,9_Analysis/21D61/kernelcache.decompressed``
  ``iPad8,9_Analysis/21D61/21D61__iPad8,9/kernelcache.release.iPad8,9_10_11_12``
  ``iPad8,9_Analysis/21D61/kexts/`` (including ``com.apple.security.sandbox``)
  ``iPad8,9_Analysis/21D61/symbols/*.symbols.json``
Run ``--inventory`` to list what is present on disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional


API_DEVICE = "https://api.ipsw.me/v4/device/{device}?type=ipsw"


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KiB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MiB"
    return f"{n / (1024 * 1024 * 1024):.2f} GiB"


def run_inventory(analysis_root: Path) -> int:
    """Summarize existing kernelcache / kexts / symbols under iPad8,9_Analysis/<BUILD>/."""
    print(f"Inventory: {analysis_root}\n")
    if not analysis_root.is_dir():
        print("  (not found)")
        return 1
    found = False
    for build_dir in sorted(analysis_root.iterdir()):
        if not build_dir.is_dir():
            continue
        if build_dir.name.startswith(".") or build_dir.name in ("tools", "kernel_analysis", "analysis_outputs", "8ksec_archive"):
            continue
        kc_dec = build_dir / "kernelcache.decompressed"
        sym_dir = build_dir / "symbols"
        kext_dir = build_dir / "kexts"
        nested = list(build_dir.glob("*__iPad*/kernelcache.release*"))
        has_any = kc_dec.is_file() or sym_dir.is_dir() or kext_dir.is_dir() or nested
        if not has_any:
            continue
        found = True
        print(f"=== {build_dir.name} ===")
        if kc_dec.is_file():
            print(f"  kernelcache.decompressed   {format_size(kc_dec.stat().st_size)}")
        for p in nested:
            if p.is_file():
                print(f"  {p.relative_to(build_dir)}   {format_size(p.stat().st_size)}")
        if sym_dir.is_dir():
            sj = list(sym_dir.glob("*.symbols.json"))
            print(f"  symbols/   ({len(sj)} json)")
        if kext_dir.is_dir():
            all_k = list(kext_dir.iterdir())
            dirs = sum(1 for x in all_k if x.is_dir())
            files = sum(1 for x in all_k if x.is_file())
            print(f"  kexts/   ({len(all_k)} entries: {dirs} dirs, {files} files)")
            sb = kext_dir / "com.apple.security.sandbox"
            if sb.exists():
                print("    + com.apple.security.sandbox")
        print()
    if not found:
        print("No per-build dirs with kernelcache/kexts/symbols found (expected e.g. 21D61/).")
        return 1
    print("If the above matches your device build, you do not need to download IPSW again.")
    return 0


def sha256_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def download_url(url: str, dest: Path, expect_size: Optional[int] = None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading:\n  {url}\n  -> {dest}")
    req = urllib.request.Request(url, headers={"User-Agent": "lara-extract-ipsw/1.0"})
    with urllib.request.urlopen(req) as resp:
        total = int(resp.headers.get("Content-Length") or 0) or expect_size or 0
        got = 0
        with open(dest, "wb") as out:
            while True:
                chunk = resp.read(1024 * 512)
                if not chunk:
                    break
                out.write(chunk)
                got += len(chunk)
                if total and got % (50 * 1024 * 1024) < 512 * 1024:
                    print(f"  ... {got / (1024 * 1024):.1f} MiB")
    print(f"Done. Size on disk: {dest.stat().st_size / (1024 * 1024):.1f} MiB")


def fetch_firmware_meta(device: str, build: Optional[str], version: Optional[str]) -> dict:
    api = API_DEVICE.format(device=device)
    print(f"Querying: {api}")
    with urllib.request.urlopen(api) as r:
        data = json.load(r)
    firmwares = data.get("firmwares") or []
    if build:
        for fw in firmwares:
            if fw.get("buildid", "").lower() == build.lower():
                return fw
        raise SystemExit(f"No firmware for {device} with buildid={build!r}")
    if version:
        for fw in firmwares:
            if fw.get("version") == version:
                return fw
        raise SystemExit(f"No firmware for {device} with version={version!r}")
    raise SystemExit("Specify --build or --version")


def should_extract_member(name: str, full: bool, include_dmg: bool) -> bool:
    if full:
        return True
    base = os.path.basename(name)
    if name.startswith("__MACOSX"):
        return False
    if base.startswith("kernelcache"):
        return True
    if base in ("BuildManifest.plist", "Restore.plist"):
        return True
    if "devicetree" in base.lower():
        return True
    if name.startswith("Firmware/") or "/Firmware/" in name:
        return True
    if base.endswith(".img4"):
        return True
    if base.endswith(".dmg"):
        return include_dmg
    return False


def find_kernelcache_paths(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("kernelcache*"):
        if p.is_file():
            out.append(p)
    return sorted(out)


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    analysis_root = script_dir.parent
    repo_root = analysis_root.parent

    ap = argparse.ArgumentParser(description="Download IPSW and extract kernelcache / firmware files.")
    ap.add_argument("--device", default="iPad8,9", help="Device identifier (default iPad8,9)")
    ap.add_argument("--build", default=None, help="Build id (default 21D61 if --version not set)")
    ap.add_argument("--version", default=None, help="iOS version string e.g. 17.3.1 (overrides --build)")
    ap.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help="Output root (default: iPad8,9_Analysis/<BUILD>/extracted)",
    )
    ap.add_argument("--skip-download", action="store_true", help="Use existing .ipsw at --ipsw-path")
    ap.add_argument("--ipsw-path", type=Path, default=None, help="Local .ipsw file path")
    ap.add_argument("--no-verify-sha256", action="store_true", help="Skip SHA256 check after download")
    ap.add_argument("--full", action="store_true", help="Extract entire IPSW (very large on disk)")
    ap.add_argument("--include-dmg", action="store_true", help="Include *.dmg in smart extract (large)")
    ap.add_argument("--list-only", action="store_true", help="Only print URL/metadata; do not download")
    ap.add_argument(
        "--inventory",
        action="store_true",
        help="List existing kernelcache / kexts / symbols under iPad8,9_Analysis (no download)",
    )
    args = ap.parse_args()
    if args.inventory:
        return run_inventory(analysis_root)
    if not args.version and not args.build:
        args.build = "21D61"

    fw = fetch_firmware_meta(args.device, None if args.version else args.build, args.version)
    build_id = fw["buildid"]
    url = fw["url"]
    expected_sha256 = fw.get("sha256sum")
    expected_size = int(fw.get("filesize") or 0)

    print(
        json.dumps(
            {
                "device": args.device,
                "version": fw.get("version"),
                "buildid": build_id,
                "signed": fw.get("signed"),
                "filesize": expected_size,
                "url": url,
            },
            indent=2,
        )
    )

    if args.list_only:
        return 0

    out_root = args.out_root or (analysis_root / build_id / "extracted")
    out_root = out_root.resolve()
    staging = out_root / "_staging"
    ipsw_dir = staging / "ipsw_unpacked"
    ipsw_dir.mkdir(parents=True, exist_ok=True)

    ipsw_local = args.ipsw_path
    if ipsw_local is None:
        ipsw_local = staging / Path(url.split("/")[-1])

    if not args.skip_download:
        if ipsw_local.exists():
            print(f"Using existing IPSW: {ipsw_local}")
        else:
            download_url(url, Path(ipsw_local), expect_size=expected_size or None)
            if expected_sha256 and not args.no_verify_sha256:
                print("Verifying SHA256...")
                got = sha256_file(Path(ipsw_local))
                if got.lower() != expected_sha256.lower():
                    print(f"SHA256 mismatch!\n expected: {expected_sha256}\n actual:   {got}")
                    return 1
                print("SHA256 OK.")
    else:
        if not ipsw_local or not Path(ipsw_local).exists():
            print("--skip-download requires existing --ipsw-path")
            return 1
        ipsw_local = Path(ipsw_local)

    print(f"Opening ZIP (IPSW): {ipsw_local}")
    manifest: dict = {
        "device": args.device,
        "buildid": build_id,
        "ipsw": str(ipsw_local),
        "extract_mode": "full" if args.full else "smart",
        "include_dmg": args.include_dmg,
        "files": [],
    }

    with zipfile.ZipFile(ipsw_local, "r") as zf:
        names = zf.namelist()
        to_extract = [n for n in names if should_extract_member(n, args.full, args.include_dmg)]
        print(f"Extracting {len(to_extract)} / {len(names)} members to {ipsw_dir} ...")
        for n in to_extract:
            zf.extract(n, ipsw_dir)

    # Flatten key files to out_root for convenience
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "dmg").mkdir(exist_ok=True)
    (out_root / "Firmware").mkdir(exist_ok=True)

    for p in ipsw_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ipsw_dir)
        name = rel.name
        if name.endswith(".dmg"):
            dest = out_root / "dmg" / name
            shutil.copy2(p, dest)
            manifest["files"].append({"path": str(dest.relative_to(out_root)), "size": dest.stat().st_size})
            continue
        if name.startswith("kernelcache") or name in ("BuildManifest.plist", "Restore.plist"):
            dest = out_root / name
            shutil.copy2(p, dest)
            manifest["files"].append({"path": str(dest.relative_to(out_root)), "size": dest.stat().st_size})
            continue
        if "devicetree" in name.lower() or name.endswith(".img4"):
            dest = out_root / "Firmware" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
            manifest["files"].append({"path": str(dest.relative_to(out_root)), "size": dest.stat().st_size})

    # Prefer kernelcache matching device
    kc_list = find_kernelcache_paths(out_root)
    if not kc_list:
        kc_list = find_kernelcache_paths(ipsw_dir)
    kc_raw = None
    for cand in kc_list:
        if "iPad8,9" in cand.name or "ipad8,9" in cand.name.lower():
            kc_raw = cand
            break
    if not kc_list:
        print("WARNING: No kernelcache* found in extracted tree.")
    elif kc_raw is None:
        kc_raw = kc_list[0]
        print(f"Using kernelcache: {kc_raw.name}")

    kc_out = out_root / "kernelcache.decompressed.macho"
    decompress_py = analysis_root / "decompress_kernelcache.py"
    if kc_raw and decompress_py.is_file():
        print(f"Decompressing kernelcache via {decompress_py} ...")
        r = subprocess.run(
            [sys.executable, str(decompress_py), str(kc_raw), str(kc_out)],
            cwd=str(analysis_root),
        )
        if r.returncode == 0 and kc_out.exists():
            try:
                manifest["kernelcache_raw"] = str(kc_raw.resolve().relative_to(out_root.resolve()))
            except ValueError:
                manifest["kernelcache_raw"] = str(kc_raw)
            manifest["kernelcache_decompressed"] = kc_out.name
            manifest["files"].append(
                {"path": kc_out.name, "size": kc_out.stat().st_size, "role": "kernelcache_macho"}
            )
        else:
            print("WARNING: decompress_kernelcache failed or missing output; install pyliblzfse if LZFSE.")
    else:
        print(f"WARNING: kernelcache or decompress script missing: decompress_py={decompress_py}")

    # Optional: ipsw CLI for sandbox kext etc.
    ipsw_bin = shutil.which("ipsw")
    manifest["ipsw_cli"] = ipsw_bin
    if ipsw_bin and kc_out.exists():
        print(f"Found ipsw at {ipsw_bin} — you can run manually:\n"
              f"  {ipsw_bin} kernel extract {kc_out} com.apple.security.sandbox")

    manifest_path = out_root / "EXTRACT_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nDone. Manifest: {manifest_path}")
    print(f"Output directory: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
