#!/usr/bin/env python3
import json, requests, sys
IN = 'iPad8,9_Analysis/pmap_in_ppl_candidates_top10.json'
OUT = 'iPad8,9_Analysis/scripts/pmap_kread_results.json'
URL = 'http://192.168.1.5:8686/api/v1/kread'

with open(IN,'r',encoding='utf-8') as f:
    data = json.load(f)

top = data.get('top', [])
results = {}

for idx,entry in enumerate(top):
    vm = entry.get('vm')
    if not vm:
        continue
    # normalize
    vm_int = int(vm,0)
    addrs = [vm, f"0x{vm_int+8:016x}"]
    results[vm] = {}
    for a in addrs:
        try:
            r = requests.post(URL, json={"address": a}, timeout=10)
            results[vm][a] = {"status": r.status_code, "body": r.text}
            print(f"{vm} {a} -> {r.status_code} {r.text}")
        except Exception as e:
            results[vm][a] = {"status": None, "body": str(e)}
            print(f"{vm} {a} -> ERROR {e}")

with open(OUT,'w',encoding='utf-8') as f:
    json.dump(results, f, indent=2)

print('\nSaved to', OUT)
