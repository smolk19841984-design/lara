#!/usr/bin/env python3
"""
remote_call_probe.py — RemoteCall / TaskRop thread offset analyzer
===================================================================
Analyzes the correct thread_t / task_t / proc_t struct offsets needed
by init_remote_call() for the lara jailbreak, using two sources:

  1. LIVE LOG analysis — parses lara.log output to extract confirmed
     runtime values (PROC_STRUCT_SIZE, t_tro, task_threads_next, etc.)

  2. KERNELCACHE analysis — optionally disassembles the kernelcache
     using the `ipsw` binary to find offsets from thread_set_apc_statelock
     and thread_get_state / task_threads() patterns.

  3. OFFSET CROSS-VALIDATION — computes proc→task diff from log and
     cross-checks against PROC_STRUCT_SIZE from runtime init.

  4. COMPARISON with static rc_offsets table — reports any mismatch
     between live probed values and the compile-time static tables.

Output: human-readable + JSON suitable for patching rc_offsets.m

Usage:
  # Analyse existing logs only (no ipsw needed):
  python remote_call_probe.py --logfile ../log/lara.log

  # Also probe kernelcache (requires ipsw tool):
  python remote_call_probe.py --logfile ../log/lara.log \\
      --kernelcache 21D61/kernelcache.release.iPad8,9 \\
      --ipsw $(which ipsw)
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Known static offsets from jbdc/kexploit/rc_offsets.m (for cross-checking)
# ─────────────────────────────────────────────────────────────────────────────

# Format: (iOS_major, iOS_minor, soc_family) → {field: offset}
# SOC families: "VORTEX_TEMPEST" = A12/A12X, "LIGHTNING_THUNDER" = A13, etc.
STATIC_OFFSETS: Dict[Tuple, Dict[str, int]] = {
    # iOS 17.0–17.3  A12 / A12X (CPUFAMILY_ARM_VORTEX_TEMPEST)
    (17, 0, "VORTEX_TEMPEST"): {
        "rc_off_thread_t_tro":              0x368,
        "rc_off_thread_task_threads_next":  0x358,
        "rc_off_task_threads_next":         0x058,
        "PROC_STRUCT_SIZE":                 0x730,
    },
    (17, 3, "VORTEX_TEMPEST"): {
        "rc_off_thread_t_tro":              0x368,
        "rc_off_thread_task_threads_next":  0x358,
        "rc_off_task_threads_next":         0x058,
        "PROC_STRUCT_SIZE":                 0x730,
    },
    # iOS 17.0–17.3  A13 (LIGHTNING_THUNDER)
    (17, 0, "LIGHTNING_THUNDER"): {
        "rc_off_thread_t_tro":              0x368,
        "rc_off_thread_task_threads_next":  0x358,
        "rc_off_task_threads_next":         0x058,
        "PROC_STRUCT_SIZE":                 0x740,
    },
    # iOS 17.4–17.7  A12 / A12X
    (17, 4, "VORTEX_TEMPEST"): {
        "rc_off_thread_t_tro":              0x378,
        "rc_off_thread_task_threads_next":  0x368,
        "rc_off_task_threads_next":         0x058,
        "PROC_STRUCT_SIZE":                 0x730,
    },
}

# Canonical TRO relationships (hold across all iOS 17–18 SoC combos checked):
#   task_threads_next  = t_tro - 0x10
#   guard_exc_info     = t_tro - 0x50
#   ctid               = t_tro + 0xb0  (A18: +0xc0)
TRO_DERIVED = {
    "rc_off_thread_task_threads_next": lambda tro: tro - 0x10,
    "rc_off_thread_guard_exc_info":    lambda tro: tro - 0x50,
    "rc_off_thread_ctid":              lambda tro: tro + 0xb0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Log parsing
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LiveOffsets:
    proc_struct_size: Optional[int]   = None
    task_tnext_offset: Optional[int]  = None
    thread_mupcb_off: Optional[int]   = None
    proc_pid_off: Optional[int]      = None
    our_proc: Optional[int]           = None
    our_task: Optional[int]           = None
    proc_task_diff: Optional[int]     = None
    rc_t_tro_probed: Optional[int]    = None     # from rc_probe_tro_offset
    rc_t_tro_static: Optional[int]    = None     # from PRE-WALK first_tro (inferred)
    rc_task_threads_next: Optional[int] = None
    ios_version: str                  = ""
    device: str                       = ""
    soc_family: str                   = ""       # inferred from device
    invalid_tro_values: List[int]     = field(default_factory=list)
    warnings: List[str]               = field(default_factory=list)


_RE_PROC_STRUCT  = re.compile(r'PROC_STRUCT_SIZE:\s*(0x[0-9a-fA-F]+)')
_RE_TASK_TNEXT   = re.compile(r'TASK_TNEXT_OFFSET:\s*(0x[0-9a-fA-F]+)')
_RE_MUPCB        = re.compile(r'THREAD_MUPCB_OFFSET:\s*(0x[0-9a-fA-F]+)')
_RE_PID_OFF      = re.compile(r'PROC_PID_OFFSET:\s*(0x[0-9a-fA-F]+)')
_RE_OUR_PROC     = re.compile(r'our_proc[=:]\s*(0x[0-9a-fA-F]+)', re.I)
_RE_OUR_TASK     = re.compile(r'our_task[=:]\s*(0x[0-9a-fA-F]+)', re.I)
_RE_DEVICE       = re.compile(r'device:\s+([\w,]+)')
_RE_PROBE_OK     = re.compile(r'rc_probe_tro_offset\s+OK.*t_tro=(0x[0-9a-fA-F]+)')
_RE_SKIP_TRO     = re.compile(r'SKIP\s+invalid\s+tro:\s*(0x[0-9a-fA-F]+)', re.I)
_RE_PRE_WALK_TRO = re.compile(r'PRE-WALK.*first_tro=(0x[0-9a-fA-F]+)')


_DEVICE_TO_SOC = {
    # A12X Bionic
    "iPad8,1": "VORTEX_TEMPEST", "iPad8,2": "VORTEX_TEMPEST",
    "iPad8,3": "VORTEX_TEMPEST", "iPad8,4": "VORTEX_TEMPEST",
    "iPad8,5": "VORTEX_TEMPEST", "iPad8,6": "VORTEX_TEMPEST",
    "iPad8,7": "VORTEX_TEMPEST", "iPad8,8": "VORTEX_TEMPEST",
    "iPad8,9": "VORTEX_TEMPEST", "iPad8,10": "VORTEX_TEMPEST",
    "iPad8,11": "VORTEX_TEMPEST", "iPad8,12": "VORTEX_TEMPEST",
    # A12 Bionic (iPhones)
    "iPhone11,2": "VORTEX_TEMPEST", "iPhone11,4": "VORTEX_TEMPEST",
    "iPhone11,6": "VORTEX_TEMPEST", "iPhone11,8": "VORTEX_TEMPEST",
    # A13
    "iPhone12,1": "LIGHTNING_THUNDER", "iPhone12,3": "LIGHTNING_THUNDER",
    "iPhone12,5": "LIGHTNING_THUNDER",
    # A14
    "iPhone13,1": "FIRESTORM_ICESTORM", "iPhone13,2": "FIRESTORM_ICESTORM",
    "iPhone13,3": "FIRESTORM_ICESTORM", "iPhone13,4": "FIRESTORM_ICESTORM",
}


def parse_log_for_offsets(log_path: str) -> LiveOffsets:
    live = LiveOffsets()
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip()
                m = _RE_PROC_STRUCT.search(line)
                if m:
                    live.proc_struct_size = int(m.group(1), 16)
                m = _RE_TASK_TNEXT.search(line)
                if m:
                    live.task_tnext_offset = int(m.group(1), 16)
                m = _RE_MUPCB.search(line)
                if m:
                    live.thread_mupcb_off = int(m.group(1), 16)
                m = _RE_PID_OFF.search(line)
                if m:
                    live.proc_pid_off = int(m.group(1), 16)
                m = _RE_OUR_PROC.search(line)
                if m:
                    live.our_proc = int(m.group(1), 16)
                m = _RE_OUR_TASK.search(line)
                if m:
                    live.our_task = int(m.group(1), 16)
                m = _RE_DEVICE.search(line)
                if m and not live.device:
                    live.device = m.group(1)
                    live.soc_family = _DEVICE_TO_SOC.get(live.device, "UNKNOWN")
                m = _RE_PROBE_OK.search(line)
                if m:
                    live.rc_t_tro_probed = int(m.group(1), 16)
                m = _RE_PRE_WALK_TRO.search(line)
                if m:
                    val = int(m.group(1), 16)
                    if val > 0xFFFFFF8000000000:
                        live.rc_t_tro_static = val  # this is a live kptr, not the offset
                m = _RE_SKIP_TRO.search(line)
                if m:
                    val = int(m.group(1), 16)
                    if val not in live.invalid_tro_values:
                        live.invalid_tro_values.append(val)
    except OSError as e:
        print(f"[WARN] Cannot read {log_path}: {e}", file=sys.stderr)

    if live.our_proc and live.our_task:
        live.proc_task_diff = live.our_task - live.our_proc

    return live


# ─────────────────────────────────────────────────────────────────────────────
# Kernelcache analysis via ipsw
# ─────────────────────────────────────────────────────────────────────────────

def run_ipsw(ipsw_bin: str, *args, timeout: int = 60) -> Tuple[bool, str]:
    """Run ipsw tool, return (ok, output)."""
    cmd = [ipsw_bin] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, (result.stdout + result.stderr)
    except FileNotFoundError:
        return False, f"ipsw not found at: {ipsw_bin}"
    except subprocess.TimeoutExpired:
        return False, "ipsw timed out"


def find_thread_tro_offset_from_kernelcache(
    ipsw_bin: str, kernelcache_path: str
) -> Optional[int]:
    """
    Use ipsw disassembler to find the t_tro offset in thread_t.
    Strategy: disassemble thread_set_apc_statelock (or thread_apc_state_set)
    and look for LDR x*, [x0, #N] patterns where N is in the known TRO range.

    Falls back to scanning for the known constant patterns used in the probe.
    """
    if not os.path.exists(kernelcache_path):
        return None

    # Symbolicate first
    ok, symbols_json = run_ipsw(
        ipsw_bin, "kernel", "sym", kernelcache_path, "--json", timeout=120
    )
    if not ok:
        print(f"  [ipsw] Symbol extraction failed: {symbols_json[:200]}", file=sys.stderr)
        return None

    # Look for thread_set_apc_statelock or thread_set_mach_voucher
    sym_re = re.compile(
        r'(0x[0-9a-fA-F]+)\s+.*?thread_(?:set_apc_statelock|set_mach_voucher|'
        r'get_state_internal|assign_pset)'
    )
    target_addr = None
    for m in sym_re.finditer(symbols_json):
        target_addr = m.group(1)
        break

    if not target_addr:
        print("  [ipsw] Could not find target thread function", file=sys.stderr)
        return None

    # Disassemble function
    ok, disasm = run_ipsw(
        ipsw_bin, "kernel", "disass", kernelcache_path,
        "--vaddr", target_addr, "--count", "80", timeout=60
    )
    if not ok:
        return None

    # Look for LDR patterns: LDR x*, [x*, #0x3XX]
    tro_range = re.compile(r'LDR\s+\w+,\s+\[x\d+,\s+#(0x3[0-9a-fA-F]{2})\]', re.I)
    candidates: Dict[int, int] = {}  # offset → frequency
    for m in tro_range.finditer(disasm):
        off = int(m.group(1), 16)
        if 0x330 <= off <= 0x420:
            candidates[off] = candidates.get(off, 0) + 1

    if not candidates:
        return None

    # The most frequent offset in 0x330–0x420 range is t_tro
    best = max(candidates, key=lambda k: candidates[k])
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Validation & report
# ─────────────────────────────────────────────────────────────────────────────

def validate_offsets(live: LiveOffsets) -> List[str]:
    """Cross-validate live values. Returns list of issue strings."""
    issues = []

    # 1. proc → task diff should equal PROC_STRUCT_SIZE
    if live.proc_task_diff is not None and live.proc_struct_size is not None:
        if live.proc_task_diff != live.proc_struct_size:
            issues.append(
                f"PROC_STRUCT_SIZE mismatch: "
                f"live diff=0x{live.proc_task_diff:x}, "
                f"init value=0x{live.proc_struct_size:x}"
            )

    # 2. task_tnext_offset should be 0x58 for iOS 17.x
    if live.task_tnext_offset is not None:
        if live.task_tnext_offset not in (0x58, 0x60):
            issues.append(
                f"Unusual TASK_TNEXT_OFFSET=0x{live.task_tnext_offset:x} "
                f"(expected 0x58 or 0x60 for iOS 17.x)"
            )

    # 3. If there are invalid TRO values, they indicate wrong offsets
    if live.invalid_tro_values:
        small_vals = [v for v in live.invalid_tro_values if v < 0xFFFF]
        if small_vals:
            issues.append(
                f"Invalid TRO values found (not kernel ptrs): "
                f"{[hex(v) for v in small_vals[:6]]} — "
                f"indicates wrong rc_off_thread_t_tro or wrong task address"
            )

    # 4. Static table lookup
    if live.soc_family and live.soc_family != "UNKNOWN":
        # Try to match a static entry
        ios_major = 17  # TODO: parse from log
        best_match = None
        for (maj, minor, soc), offs in STATIC_OFFSETS.items():
            if maj == ios_major and soc == live.soc_family:
                best_match = offs
        if best_match and live.proc_struct_size:
            expected_pss = best_match.get("PROC_STRUCT_SIZE")
            if expected_pss and live.proc_struct_size != expected_pss:
                issues.append(
                    f"PROC_STRUCT_SIZE: live=0x{live.proc_struct_size:x} "
                    f"vs static table=0x{expected_pss:x}"
                )

    return issues


def compute_recommended_offsets(live: LiveOffsets, kc_tro: Optional[int] = None) -> Dict[str, int]:
    """Return a recommended offset dict based on live + kernelcache probing."""
    offsets: Dict[str, int] = {}

    # Determine best t_tro
    t_tro = None
    if live.rc_t_tro_probed is not None:
        t_tro = live.rc_t_tro_probed  # runtime probe is most reliable
    elif kc_tro is not None:
        t_tro = kc_tro
    else:
        # Fall back to static table
        if live.soc_family:
            for (maj, minor, soc), offs in STATIC_OFFSETS.items():
                if soc == live.soc_family:
                    t_tro = offs.get("rc_off_thread_t_tro")

    if t_tro is not None:
        offsets["rc_off_thread_t_tro"] = t_tro
        for name, fn in TRO_DERIVED.items():
            offsets[name] = fn(t_tro)

    if live.task_tnext_offset is not None:
        offsets["rc_off_task_threads_next"] = live.task_tnext_offset
    elif t_tro is None:
        # Best-guess: 0x58 for iOS 17.x
        offsets["rc_off_task_threads_next"] = 0x58

    if live.proc_struct_size is not None:
        offsets["PROC_STRUCT_SIZE"] = live.proc_struct_size

    return offsets


def print_live_report(live: LiveOffsets, issues: List[str],
                      recommended: Dict[str, int],
                      kc_tro: Optional[int]) -> None:
    sep = "=" * 68
    print(sep)
    print("  REMOTE CALL / THREAD OFFSET PROBE REPORT")
    print(sep)

    print(f"\n[DEVICE]")
    print(f"  Device     : {live.device or 'N/A'}")
    print(f"  SoC Family : {live.soc_family or 'N/A'}")

    print(f"\n[LIVE OFFSETS (from log)]")
    print(f"  PROC_STRUCT_SIZE       : 0x{live.proc_struct_size:x}" if live.proc_struct_size else
          f"  PROC_STRUCT_SIZE       : N/A")
    print(f"  TASK_TNEXT_OFFSET      : 0x{live.task_tnext_offset:x}" if live.task_tnext_offset else
          f"  TASK_TNEXT_OFFSET      : N/A")
    print(f"  our_proc               : 0x{live.our_proc:x}" if live.our_proc else
          f"  our_proc               : N/A")
    print(f"  our_task               : 0x{live.our_task:x}" if live.our_task else
          f"  our_task               : N/A")
    if live.proc_task_diff is not None:
        diff_ok = (live.proc_task_diff == live.proc_struct_size)
        mark = "  ← CORRECT PROC_STRUCT_SIZE" if diff_ok else f"  ← EXPECTED 0x{live.proc_struct_size:x}"
        print(f"  proc→task diff         : 0x{live.proc_task_diff:x}{mark}")

    print(f"\n[RUNTIME TRO PROBE (rc_probe_tro_offset)]")
    if live.rc_t_tro_probed is not None:
        print(f"  t_tro offset (probed)  : 0x{live.rc_t_tro_probed:x}  ← RUNTIME VERIFIED")
    else:
        print(f"  t_tro offset (probed)  : NOT RUN (needs patched build)")

    if kc_tro is not None:
        print(f"\n[KERNELCACHE SCAN]")
        print(f"  t_tro offset (kc scan) : 0x{kc_tro:x}")

    if live.invalid_tro_values:
        print(f"\n[INVALID TRO READS (BAD OFFSETS)]")
        print(f"  Count      : {len(live.invalid_tro_values)} unique values")
        for v in live.invalid_tro_values[:8]:
            print(f"  0x{v:x}", end="")
        print()

    print(f"\n[CROSS-VALIDATION]")
    if issues:
        print(f"  Issues ({len(issues)}):")
        for iss in issues:
            print(f"    - {iss}")
    else:
        print(f"  No issues found.")

    print(f"\n[RECOMMENDED OFFSETS]")
    for name, val in sorted(recommended.items()):
        print(f"  {name:<42} : 0x{val:x}")

    # Derived values
    t_tro = recommended.get("rc_off_thread_t_tro")
    if t_tro:
        print(f"\n[DERIVED OFFSETS (from t_tro=0x{t_tro:x})]")
        print(f"  rc_off_thread_task_threads_next  = t_tro - 0x10 = 0x{t_tro - 0x10:x}")
        print(f"  rc_off_thread_guard_exc_info     = t_tro - 0x50 = 0x{t_tro - 0x50:x}")
        print(f"  rc_off_thread_ctid               = t_tro + 0xb0 = 0x{t_tro + 0xb0:x}")
        print(f"  (for A18: ctid = t_tro + 0xc0   = 0x{t_tro + 0xc0:x})")

    # Compare with static tables
    if live.soc_family:
        print(f"\n[STATIC TABLE COMPARISON ({live.soc_family})]")
        found_any = False
        for (maj, minor, soc), offs in sorted(STATIC_OFFSETS.items()):
            if soc == live.soc_family:
                found_any = True
                print(f"  iOS {maj}.{minor}: rc_off_thread_t_tro=0x{offs.get('rc_off_thread_t_tro', 0):x}  "
                      f"PROC_STRUCT_SIZE=0x{offs.get('PROC_STRUCT_SIZE', 0):x}")
        if not found_any:
            print(f"  (no static entries found for {live.soc_family})")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log = os.path.normpath(os.path.join(script_dir, '..', 'log', 'lara.log'))

    parser = argparse.ArgumentParser(
        description="Probe and validate RemoteCall thread offsets from lara logs + kernelcache"
    )
    parser.add_argument('--logfile', default=default_log,
                        help=f"lara.log path (default: {default_log})")
    parser.add_argument('--kernelcache', default=None,
                        help="Path to kernelcache.release.iPad8,9 (optional)")
    parser.add_argument('--ipsw', default='ipsw',
                        help="Path to ipsw binary (default: ipsw in PATH)")
    parser.add_argument('--json-out', default=None,
                        help="Write recommended offsets to JSON file")
    args = parser.parse_args()

    print(f"[*] Parsing log: {args.logfile}", file=sys.stderr)
    live = parse_log_for_offsets(args.logfile)

    kc_tro: Optional[int] = None
    if args.kernelcache:
        print(f"[*] Scanning kernelcache: {args.kernelcache}", file=sys.stderr)
        kc_tro = find_thread_tro_offset_from_kernelcache(args.ipsw, args.kernelcache)
        if kc_tro:
            print(f"[*] Kernelcache scan: t_tro=0x{kc_tro:x}", file=sys.stderr)
        else:
            print("[!] Kernelcache scan: could not determine t_tro", file=sys.stderr)

    issues = validate_offsets(live)
    recommended = compute_recommended_offsets(live, kc_tro)
    print_live_report(live, issues, recommended, kc_tro)

    if args.json_out:
        out = {
            "device": live.device,
            "soc_family": live.soc_family,
            "proc_struct_size": f"0x{recommended.get('PROC_STRUCT_SIZE', 0):x}",
            "offsets": {k: f"0x{v:x}" for k, v in recommended.items()
                        if k != "PROC_STRUCT_SIZE"},
            "validation_issues": issues,
            "source": "log" if live.rc_t_tro_probed else "static_table",
        }
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=4)
        print(f"\n[*] JSON written to: {args.json_out}", file=sys.stderr)


if __name__ == '__main__':
    main()
