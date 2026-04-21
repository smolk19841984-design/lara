#!/usr/bin/env python3
import json
import urllib.request
import urllib.error
from urllib.parse import urljoin
from pathlib import Path

SERVER = 'http://192.168.1.5:8686'
ENDPOINT = '/api/v1/kread'

def kread(addr):
    url = urljoin(SERVER, ENDPOINT)
    data = json.dumps({'address': hex(addr)}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode('utf-8')
            return json.loads(text)
    except urllib.error.HTTPError as e:
        return {'error': f'HTTPError {e.code}: {e.reason}', 'body': e.read().decode('utf-8', errors='ignore')}
    except Exception as e:
        return {'error': str(e)}

def main():
    # target from previous static analysis
    target_vm = 0xfffffff00a21acc8
    print('Querying MobAI server for KVA:', hex(target_vm))
    # quick health check
    try:
        with urllib.request.urlopen(SERVER + '/api/v1/health', timeout=5) as h:
            print('Health:', h.status, h.read().decode('utf-8'))
    except Exception as e:
        print('Health check failed:', e)
    res = kread(target_vm)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
