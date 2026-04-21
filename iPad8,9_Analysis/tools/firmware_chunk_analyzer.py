#!/usr/bin/env python3
"""
Разбор IPSW «по кусочкам» без обязательной полной распаковки всех DMG.

Что делает:
  1) Проходит ZIP (IPSW) и классифицирует каждый member по типу/роли.
  2) Считает суммарные размеры по категориям.
  3) Опционально (--extract-small) вытаскивает только небольшие файлы:
     BuildManifest.plist, Restore.plist, Info.plist внутри IPSW и т.п. (< лимит по размеру).
  4) Пишет отчёты в analysis_outputs/ipsw_chunks_<build>/

Примеры:
  python firmware_chunk_analyzer.py --ipsw "D:/firmware.ipsw"
  python firmware_chunk_analyzer.py --find-ipsw "C:/Users/.../iPad8,9_Analysis/21D61"
  python firmware_chunk_analyzer.py --ipsw firmware.ipsw --extract-small --max-extract-mb 15
"""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Optional


def fmt_size(n: int) -> str:
    if n >= 1024**3:
        return f"{n / 1024**3:.2f} GiB"
    if n >= 1024**2:
        return f"{n / 1024**2:.1f} MiB"
    if n >= 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n} B"


def classify_name(name: str) -> str:
    lower = name.lower()
    base = Path(name).name.lower()
    if "kernelcache" in lower:
        return "kernelcache"
    if base.endswith(".dmg"):
        return "dmg"
    if base.endswith(".img4") or ".img4" in lower:
        return "img4"
    if base.endswith(".plist") or base.endswith(".mobileconfig"):
        return "plist"
    if base in ("buildmanifest.plist", "restoremanifest.plist"):
        return "manifest"
    if "buildmanifest" in lower or "restoremanifest" in lower:
        return "manifest"
    if "restore.plist" in lower or base == "restore.plist":
        return "restore_plist"
    if "devicetree" in lower:
        return "devicetree"
    if "firmware/" in lower or lower.startswith("firmware/"):
        return "firmware_dir"
    if "trustcache" in lower or base.endswith(".im4p"):
        return "firmware_component"
    if base.endswith(".bbfw") or base.endswith(".bbplugin"):
        return "baseband"
    if lower.endswith(".pem") or "license" in lower:
        return "meta_text"
    return "other"


def find_ipsw_in_dir(root: Path) -> Optional[Path]:
    for p in root.rglob("*.ipsw"):
        if p.is_file():
            return p
    return None


def summarize_plist(path: Path) -> dict:
    try:
        data = plistlib.loads(path.read_bytes())
    except Exception as e:
        return {"error": str(e)}
    if not isinstance(data, dict):
        return {"type": type(data).__name__}
    keys = [
        "ProductVersion",
        "ProductBuildVersion",
        "BuildIdentities",
        "SupportedProductTypes",
    ]
    out: dict = {}
    for k in keys:
        if k in data:
            v = data[k]
            if k == "BuildIdentities" and isinstance(v, list) and v:
                out[k] = f"{len(v)} identities"
            else:
                out[k] = v
    return out


def main() -> int:
    here = Path(__file__).resolve().parent
    analysis_root = here.parent

    ap = argparse.ArgumentParser(description="IPSW chunk inventory and small-file extract")
    ap.add_argument("--ipsw", type=Path, help="Path to .ipsw file")
    ap.add_argument(
        "--find-ipsw",
        type=Path,
        help="Search recursively for first .ipsw under this directory (e.g. iPad8,9_Analysis/21D61)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: analysis_outputs/ipsw_chunks_<stem>)",
    )
    ap.add_argument("--extract-small", action="store_true", help="Extract plists/small files from IPSW")
    ap.add_argument("--max-extract-mb", type=float, default=12.0, help="Max uncompressed size per file to extract")
    args = ap.parse_args()

    ipsw_path: Optional[Path] = args.ipsw
    if args.find_ipsw:
        ipsw_path = find_ipsw_in_dir(args.find_ipsw.resolve())
        if not ipsw_path:
            print(f"No .ipsw found under {args.find_ipsw}")
            return 1
        print(f"Found IPSW: {ipsw_path}")
    if not ipsw_path or not ipsw_path.is_file():
        print("Provide --ipsw PATH or --find-ipsw DIR with a downloaded .ipsw")
        return 1

    max_bytes = int(args.max_extract_mb * 1024 * 1024)
    stem = ipsw_path.stem
    out_dir = args.out_dir or (analysis_root / "analysis_outputs" / f"ipsw_chunks_{stem[:40]}")
    out_dir = out_dir.resolve()
    extracted = out_dir / "extracted_small"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_cat: dict[str, list[tuple[str, int]]] = defaultdict(list)
    total_uncompressed = 0

    with zipfile.ZipFile(ipsw_path, "r") as zf:
        infos = zf.infolist()
        for zi in infos:
            if zi.is_dir():
                continue
            name = zi.filename
            size = zi.file_size
            total_uncompressed += size
            cat = classify_name(name)
            by_cat[cat].append((name, size))

        lines: list[str] = []
        lines.append(f"IPSW: {ipsw_path}")
        lines.append(f"ZIP members (files): {sum(len(v) for v in by_cat.values())}")
        lines.append(f"Total uncompressed (sum of file_size): {fmt_size(total_uncompressed)}")
        lines.append("")
        lines.append("=== By category (count, total size) ===")
        cat_totals: list[tuple[str, int, int]] = []
        for cat in sorted(by_cat.keys()):
            items = by_cat[cat]
            s = sum(x[1] for x in items)
            cat_totals.append((cat, len(items), s))
        cat_totals.sort(key=lambda x: -x[2])
        for cat, cnt, s in cat_totals:
            lines.append(f"  {cat:22s}  {cnt:5d} files   {fmt_size(s):>12s}")
        lines.append("")
        lines.append("=== Largest files (top 25) ===")
        flat: list[tuple[str, int]] = []
        for items in by_cat.values():
            flat.extend(items)
        flat.sort(key=lambda x: -x[1])
        for name, size in flat[:25]:
            lines.append(f"  {fmt_size(size):>12s}  {name}")

        (out_dir / "00_INVENTORY.txt").write_text("\n".join(lines), encoding="utf-8")

        # Per-category file lists (chunk reports)
        chunk_dir = out_dir / "by_category"
        chunk_dir.mkdir(exist_ok=True)
        for cat, items in by_cat.items():
            sub = sorted(items, key=lambda x: -x[1])
            body = "\n".join(f"{fmt_size(sz):>12s}  {nm}" for nm, sz in sub)
            safe = re.sub(r"[^\w\-]+", "_", cat)[:60]
            (chunk_dir / f"chunk_{safe}.txt").write_text(
                f"# {cat} ({len(items)} files)\n\n{body}\n", encoding="utf-8"
            )

        manifest_json = {
            "ipsw": str(ipsw_path),
            "total_uncompressed": total_uncompressed,
            "categories": {c: {"count": len(by_cat[c]), "bytes": sum(x[1] for x in by_cat[c])} for c in by_cat},
        }
        (out_dir / "01_summary.json").write_text(json.dumps(manifest_json, indent=2), encoding="utf-8")

        extracted_manifest: list[dict] = []
        if args.extract_small:
            extracted.mkdir(exist_ok=True)
            for zi in infos:
                if zi.is_dir() or zi.file_size > max_bytes:
                    continue
                lower = zi.filename.lower()
                if not (
                    lower.endswith(".plist")
                    or lower.endswith("buildmanifest.plist")
                    or lower.endswith("restore.plist")
                    or "license" in lower
                    or lower.endswith(".txt")
                ):
                    continue
                dest = extracted / zi.filename.replace("/", "__")
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(zi) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                entry: dict = {"name": zi.filename, "saved_as": str(dest.name), "bytes": zi.file_size}
                if lower.endswith(".plist") and "buildmanifest" in lower:
                    entry["plist_summary"] = summarize_plist(dest)
                extracted_manifest.append(entry)

            (out_dir / "02_extracted_small.json").write_text(
                json.dumps(extracted_manifest, indent=2), encoding="utf-8"
            )

    print("\n".join(lines))
    print(f"\nReports written under: {out_dir}")
    if args.extract_small:
        print(f"Small files extracted to: {extracted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
