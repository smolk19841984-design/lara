#!/usr/bin/env python3
"""
audit_tool.py

Диагностический скрипт для проверки поддерживаемых механизмов повышения привилегий
через API отладчика на хосте (по умолчанию http://192.168.1.5:8686).

Работает только в режиме чтения и диагностики (только GET-запросы).
"""
import sys
import logging
from typing import Optional, Tuple, Any

import requests

BASE_URL = "http://192.168.1.5:8686"
TIMEOUT = 5.0
EXPECTED_UID = 501

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("audit_tool")


def safe_get(path: str, params: dict = None) -> Optional[dict]:
    url = BASE_URL.rstrip("/") + path
    try:
        resp = requests.get(url, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        # try parse json, if can't, return raw text wrapped
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}
    except requests.exceptions.RequestException as e:
        logger.error("Connection Lost during Audit: %s", e)
        return None


def check_rc_ok(resp: Optional[dict]) -> Optional[bool]:
    if resp is None:
        return None
    # look for rc field
    if isinstance(resp, dict) and "rc" in resp:
        try:
            return int(resp.get("rc", -1)) == 0
        except Exception:
            return None
    return None


def collect_telemetry() -> Tuple[Optional[dict], Optional[dict]]:
    ds = safe_get("/api/v1/ds")
    ids = safe_get("/api/v1/ids")
    return ds, ids


def test_builtin_escalation() -> Tuple[Optional[bool], Optional[bool], dict]:
    results = {}
    sbx = safe_get("/api/v1/sbx", params={"action": "escape"})
    elev = safe_get("/api/v1/elevate")
    sbx_ok = check_rc_ok(sbx)
    elev_ok = check_rc_ok(elev)
    results["sbx_resp"] = sbx
    results["elev_resp"] = elev
    return sbx_ok, elev_ok, results


def try_memory_read(address: int, size: int = 4) -> Optional[int]:
    """
    Попытка прочитать память по адресу через несколько возможных эндпоинтов.
    Возвращает целое значение (little-endian) при успехе или None.
    """
    endpoints = [
        ("/api/v1/mem", ("addr", "size")),
        ("/api/v1/read", ("addr", "size")),
        ("/api/v1/peek", ("addr", "size")),
        ("/api/v1/memory/read", ("address", "length")),
    ]

    for ep, (addr_name, size_name) in endpoints:
        params = {addr_name: hex(address), size_name: str(size)}
        resp = safe_get(ep, params=params)
        if resp is None:
            continue
        # try several response formats
        # 1) {"value": 0x1f5}
        if isinstance(resp, dict):
            if "value" in resp:
                try:
                    return int(resp["value"])
                except Exception:
                    pass
            # 2) {"data": "0x01020304"} or hex string
            if "data" in resp and isinstance(resp["data"], str):
                s = resp["data"].strip()
                try:
                    return int(s, 16)
                except Exception:
                    pass
            # 3) {"bytes": "01020304"}
            if "bytes" in resp and isinstance(resp["bytes"], str):
                hs = resp["bytes"].strip()
                try:
                    raw = bytes.fromhex(hs)
                    return int.from_bytes(raw, "little")
                except Exception:
                    pass
            # 4) {"raw": "..."} maybe hex
            if "raw" in resp and isinstance(resp["raw"], str):
                s = resp["raw"].strip()
                # try to extract hex substring
                if s.startswith("0x"):
                    try:
                        return int(s, 16)
                    except Exception:
                        pass
        # else continue trying other endpoints
    return None


def data_structure_integrity_check(ds: Optional[dict]) -> Tuple[Optional[int], Optional[int], str]:
    if not ds or not isinstance(ds, dict):
        return None, None, "ds missing"
    our_proc = None
    # ds may contain keys like kernel_base, our_proc
    if "our_proc" in ds:
        try:
            our_proc = int(ds["our_proc"], 0) if isinstance(ds["our_proc"], str) else int(ds["our_proc"])
        except Exception:
            our_proc = None
    elif "our_proc_addr" in ds:
        try:
            our_proc = int(ds["our_proc_addr"], 0)
        except Exception:
            our_proc = None

    if our_proc is None:
        return None, None, "our_proc not found in ds"

    # offsets: p_uid/p_gid at our_proc + 0x30 (user requested)
    addr = our_proc + 0x30
    # try 4 and 8 bytes
    uid = try_memory_read(addr, size=4)
    gid = None
    if uid is not None:
        # assume gid follows next 4 bytes
        gid = try_memory_read(addr + 4, size=4)
    status = "OK" if uid == EXPECTED_UID else "Mismatch"
    return uid, gid, status


def alternative_vector_check() -> Tuple[Optional[bool], dict]:
    """
    Попытаться запросить task port для PID 1 через возможные эндпоинты.
    Возвращаем (available, raw_resp)
    """
    endpoints = ["/api/v1/task_for_pid", "/api/v1/task", "/api/v1/port_for_pid"]
    details = {}
    for ep in endpoints:
        resp = safe_get(ep, params={"pid": "1"})
        details[ep] = resp
        ok = check_rc_ok(resp)
        if ok is True:
            return True, details
    return None, details


def format_bool_avail(b: Optional[bool]) -> str:
    if b is True:
        return "Available"
    if b is False:
        return "Unavailable"
    return "Unknown"


def main():
    logger.info("Starting audit against %s (read-only diagnostics)", BASE_URL)

    ds, ids = collect_telemetry()

    # Current UID/GID from /api/v1/ids
    current_uid = None
    current_gid = None
    if isinstance(ids, dict):
        # try common fields
        for k in ("uid", "UID", "current_uid"):
            if k in ids:
                try:
                    current_uid = int(ids[k])
                except Exception:
                    pass
        for k in ("gid", "GID", "current_gid"):
            if k in ids:
                try:
                    current_gid = int(ids[k])
                except Exception:
                    pass

    # Built-in escalation checks
    sbx_ok, elev_ok, builtin_details = test_builtin_escalation()

    # Data structure integrity
    uid_val, gid_val, integrity_status = data_structure_integrity_check(ds)

    # Alternative vector
    task_avail, task_details = alternative_vector_check()

    # Recommendation logic
    if sbx_ok is True or elev_ok is True:
        recommendation = "Use Built-in API"
    else:
        recommendation = "Manual Intervention Required"

    # Print summary in requested format
    print()
    print(f"Sandbox Escape: {format_bool_avail(sbx_ok)}")
    print(f"Auto-Elevation: {format_bool_avail(elev_ok)}")
    print(f"Current UID: {current_uid if current_uid is not None else 'Unknown'}")
    print(f"Recommendation: {recommendation}")
    print()

    # Additional diagnostic output
    print("-- Details --")
    print(f"Telemetry (/api/v1/ds): {ds}")
    print(f"IDs (/api/v1/ids): {ids}")
    print(f"Built-in responses: {builtin_details}")
    print(f"Data-structure integrity: uid={uid_val} gid={gid_val} status={integrity_status}")
    print(f"Task-port availability: {format_bool_avail(task_avail)}")
    print(f"Task-port details: {task_details}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Audit cancelled by user")
        sys.exit(1)
