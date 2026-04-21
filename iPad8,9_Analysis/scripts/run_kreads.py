#!/usr/bin/env python3
import requests, json, sys
URL = "http://192.168.1.5:8686/api/v1/kread"
ADDRS = ["0xfffffff019ba8e00","0xfffffff019ba8000","0xfffffff019ba8008"]
OUT = "iPad8,9_Analysis/scripts/kread_results.json"

def do(addr):
    try:
        r = requests.post(URL, json={"address": addr}, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

if __name__ == '__main__':
    results = {}
    for a in (sys.argv[1:] or ADDRS):
        status, body = do(a)
        results[a] = {"status": status, "body": body}
        print(a, "->", status, body)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print('\nSaved results to', OUT)
