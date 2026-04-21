#!/usr/bin/env python3
import os
import sys
import requests
import json

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")
TIMEOUT = 5

def main():
    url = API_BASE + "/api/v1/ds"
    print(f"GET {url}")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
    except Exception as e:
        print("ERROR:", repr(e))
        sys.exit(1)
    text = r.text
    print("\nRAW JSON RESPONSE:\n")
    print(text)
    try:
        data = r.json()
    except Exception as e:
        print("\nFailed to parse JSON:", e)
        sys.exit(1)
    print("\nKEYS:\n")
    for k in sorted(data.keys()):
        print(k)
    print("\nVALUES for keys containing 'kernel', 'proc', or 'base':\n")
    for k in sorted(data.keys()):
        lk = k.lower()
        if "kernel" in lk or "proc" in lk or "base" in lk:
            print(f"{k}: {data[k]}")

if __name__ == '__main__':
    main()
