#!/usr/bin/env python3
"""
log_analyzer.py — Lara jailbreak log parser and failure analyzer
=================================================================
Parses lara.log, syslog, var_jb_log.txt and trustcache logs.
Produces a structured report of:
  - Kernel r/w acquisition result
  - Sandbox escape status
  - Remote call injection failures (TRO invalids, loop, task addr)
  - VFS/namecache failures
  - proc_task / PROC_STRUCT_SIZE readings
  - Thread walk statistics
  - Kernel panic strings (if any)

Usage:
  python log_analyzer.py [--logdir LOG_DIR] [--out report.txt]

Default log dir: ../log  (relative to this script)
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RemoteCallRun:
    process: str = ""
    task_addr: str = ""
    proc_struct_size: str = ""
    sentinel: str = ""
    first_chain: str = ""
    first_thread: str = ""
    first_tro: str = ""
    tro_probe_ok: Optional[bool] = None
    tro_probe_offset: str = ""
    invalid_tro_count: int = 0
    invalid_tro_values: List[str] = field(default_factory=list)
    valid_thread_count: int = 0
    injected_count: int = 0
    final_result: str = ""          # "success" / "fail" / "timeout" / "unknown"
    max_iter_hit: bool = False
    bad_chain_break: bool = False
    retries: int = 0
    raw_lines: List[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    kernel_base: str = ""
    kernel_slide: str = ""
    our_proc: str = ""
    our_task: str = ""
    proc_struct_size: str = ""
    task_tnext_offset: str = ""
    thread_mupcb_offset: str = ""
    proc_pid_offset: str = ""
    device: str = ""
    pid: str = ""
    darksword_result: str = ""      # "success" / "fail" / "unknown"
    sb_escape_result: str = ""
    var_jb_errno: Optional[int] = None
    vfs_mac_label_failures: List[str] = field(default_factory=list)
    trustcache_results: List[str] = field(default_factory=list)
    remote_call_runs: List[RemoteCallRun] = field(default_factory=list)
    panic_strings: List[str] = field(default_factory=list)
    raw_warnings: List[str] = field(default_factory=list)
    raw_errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────────────────

# proc / task
RE_PROC_STRUCT   = re.compile(r'PROC_STRUCT_SIZE:\s*(0x[0-9a-fA-F]+)')
RE_TASK_TNEXT    = re.compile(r'TASK_TNEXT_OFFSET:\s*(0x[0-9a-fA-F]+)')
RE_THREAD_MUPCB  = re.compile(r'THREAD_MUPCB_OFFSET:\s*(0x[0-9a-fA-F]+)')
RE_PROC_PID      = re.compile(r'PROC_PID_OFFSET:\s*(0x[0-9a-fA-F]+)')
RE_OUR_PROC      = re.compile(r'our_proc[=:]\s*(0x[0-9a-fA-F]+)', re.I)
RE_OUR_TASK      = re.compile(r'our_task[=:]\s*(0x[0-9a-fA-F]+)', re.I)
RE_PROC_TASK_NOTE= re.compile(r'\[proc_task\]\s+(note|taskbyproc|proc_ro|ERROR).*')

# device / kernel
RE_DEVICE        = re.compile(r'device:\s+([\w,]+)')
RE_KBASE         = re.compile(r'[Kk]ern(?:el)?[Cc]ache\s+base:\s*(0x[0-9a-fA-F]+)')
RE_KSLIDE        = re.compile(r'[Kk]ern(?:el)?[Cc]ache\s+slide:\s*(0x[0-9a-fA-F]+)')
RE_PID           = re.compile(r'\blara\[(\d+):\d+\]')

# darksword
RE_DS_SUCCESS    = re.compile(r'exploit\s+success|darksword\s+(?:done|success|ok)|kread.*ready', re.I)
RE_DS_FAIL       = re.compile(r'darksword\s+fail(?:ed)?', re.I)
RE_KREAD_READY   = re.compile(r'kread/kwrite\s+ready', re.I)

# sandbox
RE_SBX_SUCCESS   = re.compile(r'sandbox\s+escape\s+ready|escaped!|sandbox\s+(?:escape\s+)?(?:ok|success|done)', re.I)
RE_SBX_FAIL      = re.compile(r'sandbox\s+escape\s+fail', re.I)

# remote call
# Matches: init_remote_call('SpringBoard') OR "Initializing remote call into SpringBoard"
RE_RC_PROC       = re.compile(r"init_remote_call\('?([^'\")\ s]+)|Initializing\s+remote\s+call\s+into\s+(\S+)", re.I)
RE_RC_TASK       = re.compile(r'PRE-WALK.*taskAddr=(0x[0-9a-fA-F]+)')
RE_RC_SENTINEL   = re.compile(r'PRE-WALK.*sentinel=(0x[0-9a-fA-F]+)')
RE_RC_FIRST_CHN  = re.compile(r'PRE-WALK.*first_chain=(0x[0-9a-fA-F]+)')
RE_RC_FIRST_THR  = re.compile(r'PRE-WALK.*first_thread=(0x[0-9a-fA-F]+)')
RE_RC_FIRST_TRO  = re.compile(r'PRE-WALK.*first_tro=(0x[0-9a-fA-F]+)')
RE_RC_PROBE_OK   = re.compile(r'rc_probe_tro_offset\s+OK.*t_tro=(0x[0-9a-fA-F]+)')
RE_RC_PROBE_FAIL = re.compile(r'WARNING:\s+rc_probe_tro_offset\s+fail', re.I)
RE_RC_SKIP_INVLD = re.compile(r'SKIP\s+invalid\s+tro:\s*(0x[0-9a-fA-F]+)', re.I)
RE_RC_VALID_CNT  = re.compile(r'Valid\s+threads:\s*(\d+),\s*Injected:\s*(\d+)', re.I)
RE_RC_NO_EXCEPTS = re.compile(r'No\s+exceptions\s+injected', re.I)
RE_RC_TIMEOUT    = re.compile(r'Failed\s+to\s+receive\s+first\s+exception', re.I)
RE_RC_DONE       = re.compile(r'init_remote_call\(.+\)\s+done', re.I)
RE_RC_FAIL_RET   = re.compile(r'init_remote_call.*return(?:ing)?\s+-1', re.I)
RE_RC_MAXITER    = re.compile(r'maxIter.*hit|aborting\s+walk.*tro\s+offset', re.I)
RE_RC_BAD_CHAIN  = re.compile(r'nextChain.*not\s+a\s+kptr.*sentinel.*aborting', re.I)
RE_RC_RETRY      = re.compile(r'retryCount\s*\+\+|retry.*\d+', re.I)

# vfs / namecache
RE_VFS_FAIL      = re.compile(r'vfs_bypass_mac_label.*fail|vnode\s+not\s+found', re.I)
RE_VFS_PATH      = re.compile(r'vfs_bypass_mac_label.*?"([^"]+)"', re.I)
RE_VFS_WARN      = re.compile(r'WARNING.*vfs_bypass_mac_label', re.I)

# trustcache
RE_TC_ADD        = re.compile(r'trustcache.*add.*?(/[^\s]+)', re.I)
RE_TC_OK         = re.compile(r'trustcache.*(?:ok|success|inserted)', re.I)
RE_TC_FAIL       = re.compile(r'trustcache.*fail', re.I)

# var/jb
RE_VJB_MKDIR_FAIL= re.compile(r'Failed\s+to\s+mkdir\s+/var/jb.*errno\s*=\s*(\d+)', re.I)
RE_VJB_WARN      = re.compile(r'vfs_bypass_mac_label.*-1.*May\s+fail', re.I)

# panic
RE_PANIC_STR     = re.compile(r'panic\s*\(.*?string.*?"(.+?)"', re.I)
RE_PANIC_SIMPLE  = re.compile(r'panic:\s+(.+)', re.I)


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

class LogParser:
    def __init__(self):
        self.report = AnalysisReport()
        self._current_rc: Optional[RemoteCallRun] = None

    def _flush_rc(self):
        if self._current_rc:
            self.report.remote_call_runs.append(self._current_rc)
            self._current_rc = None

    def parse_file(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except OSError as e:
            print(f"[WARN] Cannot read {path}: {e}", file=sys.stderr)
            return

        fname = os.path.basename(path)
        for line in lines:
            line = line.rstrip('\n')
            self._parse_line(line, fname)

        self._flush_rc()

    def _parse_line(self, line: str, source: str):
        r = self.report

        # ── proc struct sizes ──────────────────────────────────────────────
        m = RE_PROC_STRUCT.search(line)
        if m:
            r.proc_struct_size = m.group(1)

        m = RE_TASK_TNEXT.search(line)
        if m:
            r.task_tnext_offset = m.group(1)

        m = RE_THREAD_MUPCB.search(line)
        if m:
            r.thread_mupcb_offset = m.group(1)

        m = RE_PROC_PID.search(line)
        if m:
            r.proc_pid_offset = m.group(1)

        m = RE_OUR_PROC.search(line)
        if m:
            r.our_proc = m.group(1)

        m = RE_OUR_TASK.search(line)
        if m:
            r.our_task = m.group(1)

        # ── device / kernel ────────────────────────────────────────────────
        m = RE_DEVICE.search(line)
        if m and not r.device:
            r.device = m.group(1)

        m = RE_KBASE.search(line)
        if m:
            r.kernel_base = m.group(1)

        m = RE_KSLIDE.search(line)
        if m:
            r.kernel_slide = m.group(1)

        m = RE_PID.search(line)
        if m and not r.pid:
            r.pid = m.group(1)

        # ── darksword ──────────────────────────────────────────────────────
        if RE_DS_SUCCESS.search(line) or RE_KREAD_READY.search(line):
            r.darksword_result = 'success'
        if RE_DS_FAIL.search(line) and r.darksword_result != 'success':
            r.darksword_result = 'fail'

        # ── sandbox ────────────────────────────────────────────────────────
        if RE_SBX_SUCCESS.search(line):
            r.sb_escape_result = 'success'
        if RE_SBX_FAIL.search(line) and r.sb_escape_result != 'success':
            r.sb_escape_result = 'fail'

        # ── /var/jb ────────────────────────────────────────────────────────
        m = RE_VJB_MKDIR_FAIL.search(line)
        if m:
            r.var_jb_errno = int(m.group(1))

        # ── vfs_bypass_mac_label ───────────────────────────────────────────
        if RE_VFS_FAIL.search(line) or RE_VFS_WARN.search(line) or RE_VJB_WARN.search(line):
            m = RE_VFS_PATH.search(line)
            path = m.group(1) if m else line.strip()[:80]
            r.vfs_mac_label_failures.append(path)

        # ── trustcache ─────────────────────────────────────────────────────
        if RE_TC_ADD.search(line):
            m = RE_TC_ADD.search(line)
            r.trustcache_results.append(f"ADD {m.group(1)}")
        if RE_TC_OK.search(line):
            r.trustcache_results.append("OK")
        if RE_TC_FAIL.search(line):
            r.trustcache_results.append("FAIL")

        # ── remote call ────────────────────────────────────────────────────
        # Start new run when init_remote_call is called
        m = RE_RC_PROC.search(line)
        if m:
            self._flush_rc()
            process = m.group(1) or m.group(2) or "unknown"
            self._current_rc = RemoteCallRun(process=process.rstrip(')'))

        # Also capture the "found proc:" line to record process name
        m2 = re.search(r'found\s+proc:\s+([\w.]+)\s+\(pid=(\d+)', line)
        if m2 and self._current_rc:
            if not self._current_rc.process or self._current_rc.process == 'unknown':
                self._current_rc.process = m2.group(1)

        # Capture init_remote_call failed: -1
        if re.search(r'init_remote_call\s+failed:\s*-1', line, re.I):
            if self._current_rc and self._current_rc.final_result not in ('success',):
                self._current_rc.final_result = 'fail'
                self._flush_rc()

        if self._current_rc is None:
            return   # everything below is per-run

        rc = self._current_rc
        rc.raw_lines.append(line)

        # Pre-walk diagnostics (new in patched version)
        m = RE_RC_TASK.search(line)
        if m:
            rc.task_addr = m.group(1)

        m = RE_RC_FIRST_CHN.search(line)
        if m:
            rc.first_chain = m.group(1)

        m = RE_RC_FIRST_THR.search(line)
        if m:
            rc.first_thread = m.group(1)

        m = RE_RC_FIRST_TRO.search(line)
        if m:
            rc.first_tro = m.group(1)

        # TRO probe
        m = RE_RC_PROBE_OK.search(line)
        if m:
            rc.tro_probe_ok = True
            rc.tro_probe_offset = m.group(1)

        if RE_RC_PROBE_FAIL.search(line):
            rc.tro_probe_ok = False

        # Invalid TROs
        m = RE_RC_SKIP_INVLD.search(line)
        if m:
            val = m.group(1)
            rc.invalid_tro_count += 1
            if val not in rc.invalid_tro_values:
                rc.invalid_tro_values.append(val)

        # Valid/injected counts
        m = RE_RC_VALID_CNT.search(line)
        if m:
            rc.valid_thread_count = int(m.group(1))
            rc.injected_count     = int(m.group(2))

        if RE_RC_NO_EXCEPTS.search(line):
            rc.final_result = 'fail'

        if RE_RC_TIMEOUT.search(line):
            rc.final_result = 'timeout'

        if RE_RC_DONE.search(line):
            rc.final_result = 'success'
            self._flush_rc()

        if RE_RC_FAIL_RET.search(line):
            if rc.final_result not in ('success',):
                rc.final_result = 'fail'

        if RE_RC_MAXITER.search(line):
            rc.max_iter_hit = True

        if RE_RC_BAD_CHAIN.search(line):
            rc.bad_chain_break = True

        # panic
        m = RE_PANIC_STR.search(line)
        if m:
            r.panic_strings.append(m.group(1))
        m = RE_PANIC_SIMPLE.search(line)
        if m:
            r.panic_strings.append(m.group(1))

        # generic warn/error
        if re.search(r'\b(ERROR|CRITICAL|FATAL)\b', line, re.I):
            r.raw_errors.append(line.strip()[:120])
        elif re.search(r'\bWARN(?:ING)?\b', line, re.I):
            r.raw_warnings.append(line.strip()[:120])


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def fmt_status(s: str) -> str:
    icons = {'success': '✓', 'fail': '✗', 'timeout': '⏱', 'unknown': '?', '': '?'}
    return f"{icons.get(s, '?')} {s.upper() or 'UNKNOWN'}"


def compute_proc_task_diff(report: AnalysisReport) -> Optional[str]:
    try:
        if report.our_proc and report.our_task:
            diff = int(report.our_task, 16) - int(report.our_proc, 16)
            if report.proc_struct_size:
                expected = int(report.proc_struct_size, 16)
                match = " ← MATCH (PROC_STRUCT_SIZE)" if diff == expected else f" ← MISMATCH! Expected {report.proc_struct_size}"
            else:
                match = ""
            return f"our_task - our_proc = 0x{diff:x}{match}"
    except (ValueError, TypeError):
        pass
    return None


def print_report(report: AnalysisReport, out=sys.stdout):
    sep = "=" * 72
    subsep = "-" * 60

    print(sep, file=out)
    print("  LARA LOG ANALYSIS REPORT", file=out)
    print(sep, file=out)

    # ── System info ──────────────────────────────────────────────────────────
    print("\n[SYSTEM]", file=out)
    print(f"  Device         : {report.device or 'N/A'}", file=out)
    print(f"  PID            : {report.pid or 'N/A'}", file=out)

    # ── Kernel ───────────────────────────────────────────────────────────────
    print("\n[KERNEL]", file=out)
    print(f"  KernelCache base  : {report.kernel_base or 'N/A'}", file=out)
    print(f"  KernelCache slide : {report.kernel_slide or 'N/A'}", file=out)
    print(f"  our_proc          : {report.our_proc or 'N/A'}", file=out)
    print(f"  our_task          : {report.our_task or 'N/A'}", file=out)
    diff_str = compute_proc_task_diff(report)
    if diff_str:
        print(f"  proc→task diff    : {diff_str}", file=out)

    # ── Struct offsets ───────────────────────────────────────────────────────
    print("\n[STRUCT OFFSETS]", file=out)
    print(f"  PROC_STRUCT_SIZE  : {report.proc_struct_size or 'N/A'}", file=out)
    print(f"  TASK_TNEXT_OFFSET : {report.task_tnext_offset or 'N/A'}", file=out)
    print(f"  THREAD_MUPCB_OFF  : {report.thread_mupcb_offset or 'N/A'}", file=out)
    print(f"  PROC_PID_OFFSET   : {report.proc_pid_offset or 'N/A'}", file=out)

    # ── Stage results ────────────────────────────────────────────────────────
    print("\n[STAGE RESULTS]", file=out)
    print(f"  Darksword (kR/W)  : {fmt_status(report.darksword_result)}", file=out)
    print(f"  Sandbox escape    : {fmt_status(report.sb_escape_result)}", file=out)

    if report.var_jb_errno is not None:
        errno_name = {1: 'EPERM', 2: 'ENOENT', 13: 'EACCES'}.get(report.var_jb_errno, '')
        print(f"  /var/jb mkdir     : ✗ FAIL  errno={report.var_jb_errno} ({errno_name})", file=out)
    else:
        print(f"  /var/jb mkdir     : ? UNKNOWN", file=out)

    # ── VFS ──────────────────────────────────────────────────────────────────
    if report.vfs_mac_label_failures:
        print(f"\n[VFS MAC LABEL FAILURES] ({len(report.vfs_mac_label_failures)} events)", file=out)
        seen = []
        for p in report.vfs_mac_label_failures:
            if p not in seen:
                seen.append(p)
                print(f"  - {p}", file=out)
        print("  Root cause: resolvepath() fails for newly-created files not in", file=out)
        print("              VFS namecache. FIX: stat() warm-up + retry loop.", file=out)

    # ── Trustcache ───────────────────────────────────────────────────────────
    if report.trustcache_results:
        print(f"\n[TRUSTCACHE] ({len(report.trustcache_results)} events)", file=out)
        for t in report.trustcache_results[:20]:
            print(f"  {t}", file=out)

    # ── Remote call runs ─────────────────────────────────────────────────────
    print(f"\n[REMOTE CALL] ({len(report.remote_call_runs)} run(s))", file=out)
    for i, rc in enumerate(report.remote_call_runs, 1):
        print(f"\n  Run #{i}: target='{rc.process}'", file=out)
        print(f"    Result        : {fmt_status(rc.final_result)}", file=out)
        if rc.task_addr:
            print(f"    Task addr     : {rc.task_addr}", file=out)
        if rc.tro_probe_ok is not None:
            status = "OK" if rc.tro_probe_ok else "FAILED"
            probe_str = f" (t_tro={rc.tro_probe_offset})" if rc.tro_probe_offset else ""
            print(f"    TRO probe     : {status}{probe_str}", file=out)
        else:
            print(f"    TRO probe     : NOT CALLED (old build)", file=out)
        if rc.first_chain:
            chain_ok = int(rc.first_chain, 16) > 0xFFFFFF8000000000
            print(f"    first_chain   : {rc.first_chain}  {'OK' if chain_ok else 'INVALID!'}", file=out)
        if rc.first_tro:
            tro_ok = int(rc.first_tro, 16) > 0xFFFFFF8000000000
            print(f"    first_tro     : {rc.first_tro}  {'OK' if tro_ok else 'INVALID!'}", file=out)
        print(f"    Invalid TROs  : {rc.invalid_tro_count} total, unique={rc.invalid_tro_values[:8]}", file=out)
        print(f"    Valid threads : {rc.valid_thread_count}", file=out)
        print(f"    Injected      : {rc.injected_count}", file=out)
        if rc.max_iter_hit:
            print("    !! maxIter hit — infinite loop detected (fixed in patched build)", file=out)
        if rc.bad_chain_break:
            print("    !! Chain walk stopped: nextChain not a kernel pointer", file=out)
        if rc.invalid_tro_count > 20:
            print("    DIAGNOSIS: All TROs invalid → WRONG TASK ADDRESS (proc_task bug)", file=out)
            print("               or WRONG rc_off_thread_t_tro offset.", file=out)
            print("    FIX APPLIED: proc_task uses PROC_STRUCT_SIZE (taskbyproc approach).", file=out)
            print("                 rc_probe_tro_offset() called before walk.", file=out)

    if not report.remote_call_runs:
        print("  (no remote call runs found in logs)", file=out)

    # ── Panics ───────────────────────────────────────────────────────────────
    if report.panic_strings:
        print(f"\n[KERNEL PANICS] ({len(report.panic_strings)})", file=out)
        for p in report.panic_strings[:10]:
            print(f"  {p}", file=out)

    # ── Errors / Warnings summary ────────────────────────────────────────────
    if report.raw_errors:
        print(f"\n[ERRORS] ({len(report.raw_errors)} unique lines, first 10)", file=out)
        for e in report.raw_errors[:10]:
            print(f"  {e}", file=out)

    if report.raw_warnings:
        print(f"\n[WARNINGS] ({len(report.raw_warnings)} unique lines, first 10)", file=out)
        for w in report.raw_warnings[:10]:
            print(f"  {w}", file=out)

    # ── Diagnosis summary ────────────────────────────────────────────────────
    print(f"\n{sep}", file=out)
    print("  DIAGNOSIS SUMMARY", file=out)
    print(sep, file=out)

    issues = []
    fixes = []

    for rc in report.remote_call_runs:
        if rc.final_result in ('fail', 'timeout', 'unknown'):
            if rc.invalid_tro_count > 20:
                issues.append(
                    f"init_remote_call({rc.process}): infinite TRO-invalid loop "
                    f"({rc.invalid_tro_count} bad TROs: {rc.invalid_tro_values[:4]}...)"
                )
                fixes.append("proc_task() → taskbyproc(proc+PROC_STRUCT_SIZE) [APPLIED]")
                fixes.append("maxIter=1024 guard in thread walk [APPLIED]")
                fixes.append("rc_probe_tro_offset() called before walk [APPLIED]")
            elif rc.valid_thread_count == 0:
                issues.append(
                    f"init_remote_call({rc.process}): no valid threads found "
                    f"(bad task addr or wrong t_tro offset)"
                )
            elif rc.final_result == 'timeout':
                issues.append(f"init_remote_call({rc.process}): exception not received (timeout)")

    if report.var_jb_errno == 13:
        issues.append("/var/jb mkdir failed: errno=13 (EACCES) — sandbox still blocking")
        fixes.append("Ensure sandbox escape completes before /var/jb creation")

    if report.vfs_mac_label_failures:
        issues.append(
            f"vfs_bypass_mac_label failed for {len(set(report.vfs_mac_label_failures))} path(s) "
            f"— ncache not warmed for newly-created files"
        )
        fixes.append("stat() warm-up + retry loop in vfs_bypass_mac_label [APPLIED]")

    if not issues:
        print("\n  No critical issues detected in logs.", file=out)
    else:
        print("\n  Issues found:", file=out)
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}", file=out)

        print("\n  Applied / recommended fixes:", file=out)
        for fix in fixes:
            print(f"    - {fix}", file=out)

    print("", file=out)


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_logdir = os.path.normpath(os.path.join(script_dir, '..', 'log'))

    parser = argparse.ArgumentParser(description="Lara jailbreak log analyzer")
    parser.add_argument('--logdir', default=default_logdir,
                        help=f"Directory containing log files (default: {default_logdir})")
    parser.add_argument('--out', default=None,
                        help="Output file for report (default: stdout)")
    parser.add_argument('files', nargs='*',
                        help="Specific log files to analyze (overrides --logdir)")
    args = parser.parse_args()

    log_parser = LogParser()

    if args.files:
        log_files = args.files
    else:
        if not os.path.isdir(args.logdir):
            print(f"[ERROR] Log directory not found: {args.logdir}", file=sys.stderr)
            sys.exit(1)
        # Prefer known log files; fall back to all .txt/.log
        known = ['lara.log', 'lara_syslog_20260410_201906.log',
                 'var_jb_log.txt', 'var_jb_trustcache_log.txt']
        log_files = []
        for name in known:
            p = os.path.join(args.logdir, name)
            if os.path.exists(p):
                log_files.append(p)
        if not log_files:
            for name in sorted(os.listdir(args.logdir)):
                if name.endswith(('.log', '.txt')):
                    log_files.append(os.path.join(args.logdir, name))

    if not log_files:
        print("[ERROR] No log files found.", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {len(log_files)} log file(s):", file=sys.stderr)
    for f in log_files:
        print(f"  {f}", file=sys.stderr)
        log_parser.parse_file(f)

    out_stream = open(args.out, 'w', encoding='utf-8') if args.out else sys.stdout
    try:
        print_report(log_parser.report, out=out_stream)
    finally:
        if args.out:
            out_stream.close()
            print(f"\nReport written to: {args.out}", file=sys.stderr)


if __name__ == '__main__':
    main()
