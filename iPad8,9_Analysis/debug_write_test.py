#!/usr/bin/env python3
"""
debug_write_test.py

Performs a quick write test against the local debug server.

Behavior:
 - GET /api/v1/ds to check server liveness and obtain `ourproc`.
 - Immediately call GET /api/v1/elevate (alternative path) and log response.
 - Attempt to write 4 bytes (uint32) zero at ourproc+0x30 using payload {"addr": "...", "value": "0x0", "size": 4}.
 - If API doesn't accept size, try writing 64-bit zero as fallback.
 - Log full HTTP response (status and body) for each unsuccessful operation.

Usage:
  python debug_write_test.py
"""

import sys
import requests

BASE_URL = "http://192.168.1.5:8686"
DS = "/api/v1/ds"
ELEV = "/api/v1/elevate"
KWRITE = "/api/v1/kwrite"


def print_resp(prefix, r):
    try:
        txt = r.text
    except Exception:
        txt = "<no-body>"
    print(f"{prefix} -> HTTP {r.status_code}\n{txt}\n")


def main():
    s = requests.Session()

    # 1) liveness + ourproc
    try:
        r = s.get(BASE_URL + DS, timeout=5)
    except Exception as e:
        print("SERVER DEAD, REBOOT NEEDED")
        print("GET /api/v1/ds error:", e)
        sys.exit(1)

    if r.status_code != 200:
        print("SERVER DEAD, REBOOT NEEDED")
        print_resp("GET /api/v1/ds", r)
        sys.exit(1)

    try:
        dsj = r.json()
    except Exception:
        dsj = None

    print("GET /api/v1/ds -> HTTP", r.status_code)
    print("BODY:", r.text)

    ourproc = None
    if isinstance(dsj, dict):
        if "ourproc" in dsj:
            try:
                ourproc = int(dsj["ourproc"], 16)
            except Exception:
                try:
                    ourproc = int(dsj["ourproc"])
                except Exception:
                    ourproc = None
        elif "our_proc" in dsj:
            try:
                ourproc = int(dsj["our_proc"], 16)
            except Exception:
                ourproc = None

    if ourproc is None:
        print("Could not parse ourproc from /api/v1/ds; aborting.")
        sys.exit(1)

    print(f"ourproc = 0x{ourproc:x}")

    # Alternative path: GET /api/v1/elevate immediately
    try:
        r = s.get(BASE_URL + ELEV, timeout=5)
        print_resp("GET /api/v1/elevate", r)
    except Exception as e:
        print("GET /api/v1/elevate failed:", e)

    target = ourproc + 0x30
    addr_hex = hex(target)

    # Try size=4 write first
    payloads = [
        {"addr": addr_hex, "value": "0x0", "size": 4},
        {"addr": addr_hex, "value": 0, "size": 4},
        # fallback to 64-bit zero
        {"addr": addr_hex, "value": "0x0000000000000000"},
        {"addr": addr_hex, "value": "0x0", "size": 8},
    ]

    success = False
    for p in payloads:
        try:
            print(f"POST {KWRITE} payload: {p}")
            r = s.post(BASE_URL + KWRITE, json=p, timeout=5)
        except Exception as e:
            print(f"POST failed (exception): {e}")
            continue

        # If non-200, print full response
        if r.status_code != 200:
            print_resp(f"POST {KWRITE} (non-200)", r)
            continue

        # status 200; check JSON for explicit success markers
        ok = False
        try:
            j = r.json()
            if isinstance(j, dict) and (j.get("success") is True or j.get("ok") is True or j.get("result") == "ok"):
                ok = True
        except Exception:
            pass

        # If we don't detect explicit success, still treat as failure per instructions and log body
        if not ok:
            print_resp(f"POST {KWRITE} (200 but no success)", r)
            # continue trying fallbacks
            continue

        # success
        print_resp(f"POST {KWRITE} (success)", r)
        success = True
        break

    if not success:
        print("All write attempts failed or returned no explicit success flag.")
    else:
        print("At least one write attempt returned success.")


if __name__ == "__main__":
    main()
