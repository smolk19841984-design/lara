#!/usr/bin/env python3
"""
Статический шаг к «новому методу» после K/RW: разбор com.apple.security.sandbox (21D61).

Не эксплойт и не обход защиты в рантайме — только извлечение строк и классификация якорей,
чтобы решить: что ещё проверять в ядре кроме ucred/extension_set (см. sbx.m).

Запуск из корня репозитория или из iPad8,9_Analysis:
  python iPad8,9_Analysis/tools/research_new_method_sandbox.py
  python iPad8,9_Analysis/tools/research_new_method_sandbox.py --out analysis_outputs/research_new_method_sandbox_21D61.txt
"""

from __future__ import annotations

import argparse
import hashlib
import re
from collections import defaultdict
from pathlib import Path


KEYWORD_GROUPS: dict[str, list[str]] = {
    "cred_uid": [r"ucred", r"cr_uid", r"cr_ruid", r"euid", r"setuid", r"kauth_cred", r"posix_cred"],
    "proc_task": [r"\bproc\b", r"proc_", r"task_", r"uthread", r"thread_", r"current_proc"],
    "mac_label": [r"mac_label", r"label_", r"MACF", r"mac_policy"],
    "sandbox_api": [r"sandbox_", r"Sandbox", r"extension", r"container", r"seatbelt"],
    "vfs": [r"vnode", r"mount", r"fs_", r"apfs", r"chown", r"suser"],
    "special": [r"root", r"launchd", r"amfi", r"trust", r"code.?sign", r"cs_flags"],
}


def extract_printable_strings(data: bytes, min_len: int = 5) -> list[str]:
    parts = re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    out: list[str] = []
    for p in parts:
        out.append(p.decode("utf-8", errors="replace"))
    return out


def classify(s: str) -> list[str]:
    hits: list[str] = []
    low = s.lower()
    for group, patterns in KEYWORD_GROUPS.items():
        for pat in patterns:
            if re.search(pat, low, re.I):
                hits.append(group)
                break
    return hits


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--kext",
        type=Path,
        default=root / "21D61" / "kexts" / "com.apple.security.sandbox",
        help="Path to com.apple.security.sandbox Mach-O",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=root / "analysis_outputs" / "research_new_method_sandbox_21D61.txt",
        help="Write report here",
    )
    ap.add_argument("--min-len", type=int, default=6)
    args = ap.parse_args()

    if not args.kext.is_file():
        print(f"ERROR: file not found: {args.kext}")
        return 1

    raw = args.kext.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    strings = extract_printable_strings(raw, min_len=args.min_len)

    by_group: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        for g in classify(s):
            if len(by_group[g]) < 400:
                by_group[g].append(s)

    lines: list[str] = []
    lines.append("research_new_method_sandbox — static hints (NOT runtime exploit code)")
    lines.append(f"kext: {args.kext}")
    lines.append(f"sha256: {sha}")
    lines.append(f"size: {len(raw)} bytes")
    lines.append(f"unique strings (min_len={args.min_len}): {len(seen)}")
    lines.append("")
    lines.append("--- How this feeds a NEW method (workflow) ---")
    lines.append("1) Strings suggest which kernel/MAC subsystems the sandbox kext touches.")
    lines.append("2) Cross-check with IDA/Hopper on kernelcache.decompressed at symbols from")
    lines.append("   21D61/symbols/*.symbols.json — find who calls what.")
    lines.append("3) In Lara: one minimal new primitive (e.g. label vs ucred) + PPL-safe write,")
    lines.append("   then device log — iterate. No method appears from docs alone.")
    lines.append("")
    for g in sorted(KEYWORD_GROUPS.keys()):
        lines.append(f"=== {g} ({len(by_group[g])} samples) ===")
        for s in sorted(by_group[g])[:120]:
            lines.append(s)
        if len(by_group[g]) > 120:
            lines.append(f"... ({len(by_group[g]) - 120} more)")
        lines.append("")

    report = "\n".join(lines)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nWrote: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
