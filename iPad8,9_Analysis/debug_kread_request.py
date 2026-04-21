#!/usr/bin/env python3
import os
import requests
import traceback

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000")
addr = "0xffffffe230cf22c8"
size = 8

def do_get():
    url = API_BASE + "/api/v1/kread"
    params = {"addr": addr, "size": size}
    print(f"GET {url} params={params}")
    try:
        r = requests.get(url, params=params, timeout=5)
        print("STATUS:", r.status_code)
        print("HEADERS:", dict(r.headers))
        print("TEXT:\n", r.text)
    except Exception as e:
        print("GET EXCEPTION:", repr(e))
        traceback.print_exc()

def do_post():
    url = API_BASE + "/api/v1/kread"
    json = {"addr": addr, "size": size}
    print(f"POST {url} json={json}")
    try:
        r = requests.post(url, json=json, timeout=5)
        print("STATUS:", r.status_code)
        print("HEADERS:", dict(r.headers))
        print("TEXT:\n", r.text)
    except Exception as e:
        print("POST EXCEPTION:", repr(e))
        traceback.print_exc()

if __name__ == '__main__':
    print('API_BASE=', API_BASE)
    do_get()
    print('\n---\n')
    do_post()
