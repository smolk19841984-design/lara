#!/usr/bin/env python3
import os, json

ROOT = os.path.join(os.path.dirname(__file__), '..')
BUILD_A = os.path.join(ROOT, '21D61')
BUILD_B = os.path.join(ROOT, '21E219')
KC = 'kernelcache.decompressed'
REPORT_IN = os.path.join(os.path.dirname(__file__), 'find_functions_report.json')
OUT = os.path.join(os.path.dirname(__file__), 'binary_diff_report.json')

def diff_bytes(a,b,base=0):
    diffs = []
    i = 0
    n = min(len(a), len(b))
    cur = None
    while i < n:
        if a[i] != b[i]:
            if cur is None:
                cur = [i, i+1]
            else:
                cur[1] = i+1
        else:
            if cur is not None:
                diffs.append((base+cur[0], base+cur[1]))
                cur = None
        i += 1
    if cur is not None:
        diffs.append((base+cur[0], base+cur[1]))
    # if lengths differ, record trailing range
    if len(a) != len(b):
        diffs.append((base+n, base+max(len(a), len(b))))
    return diffs

def scan_kernelcaches():
    path_a = os.path.join(BUILD_A, KC)
    path_b = os.path.join(BUILD_B, KC)
    if not os.path.isfile(path_a) or not os.path.isfile(path_b):
        return None
    da = open(path_a,'rb').read()
    db = open(path_b,'rb').read()
    diffs = diff_bytes(da, db)
    return {'file_a': path_a, 'file_b': path_b, 'size_a': len(da), 'size_b': len(db), 'diff_ranges': diffs}

def compare_kexts():
    diffs = []
    dir_a = os.path.join(BUILD_A, 'kexts')
    dir_b = os.path.join(BUILD_B, 'kexts')
    # collect common relative paths
    files = {}
    for root,_,fs in os.walk(dir_a):
        for f in fs:
            rel = os.path.relpath(os.path.join(root,f), dir_a)
            files.setdefault(rel, {})['a'] = os.path.join(root,f)
    for root,_,fs in os.walk(dir_b):
        for f in fs:
            rel = os.path.relpath(os.path.join(root,f), dir_b)
            files.setdefault(rel, {})['b'] = os.path.join(root,f)
    for rel,entry in files.items():
        pa = entry.get('a')
        pb = entry.get('b')
        if pa and pb:
            da = open(pa,'rb').read()
            db = open(pb,'rb').read()
            if da==db:
                continue
            ranges = diff_bytes(da, db)
            diffs.append({'rel': rel, 'file_a': pa, 'file_b': pb, 'diff_ranges': ranges})
        else:
            diffs.append({'rel': rel, 'file_a': pa, 'file_b': pb, 'diff_ranges': 'only_in_one_build'})
    return diffs

def correlate_with_report(binary_report, kext_diffs):
    # load find_functions_report.json
    try:
        rep = json.load(open(REPORT_IN,'r',encoding='utf-8'))
    except Exception:
        rep = {}
    out = {'kernel_matches': [], 'kext_matches': []}
    # kernel ranges
    ranges = binary_report.get('diff_ranges', [])
    # flatten all function fileoffs from report
    for build in ['21D61','21E219']:
        for func, hits in rep.get(build, {}).items():
            for h in hits:
                file = h['file']
                off = int(h['fileoff'],16)
                if file == 'kernelcache.decompressed':
                    for r in ranges:
                        if r[0]-0x100 <= off <= r[1]+0x100:
                            out['kernel_matches'].append({'func': func, 'build': build, 'fileoff': hex(off), 'range': [hex(r[0]),hex(r[1])]})
                else:
                    # kext match
                    for kd in kext_diffs:
                        if kd['rel'].lower() == file.replace('kexts\\','').lower() or kd['rel']==file:
                            out['kext_matches'].append({'func': func, 'build': build, 'fileoff': hex(off), 'kext': kd['rel']})
    return out

def main():
    report = {}
    print('Scanning kernelcaches...')
    kc_report = scan_kernelcaches()
    report['kernelcache'] = kc_report
    print('Comparing kexts...')
    kexts = compare_kexts()
    report['kexts'] = kexts
    print('Correlating with function report...')
    corr = correlate_with_report(kc_report, kexts)
    report['correlation'] = corr
    with open(OUT,'w',encoding='utf-8') as fo:
        json.dump(report, fo, indent=2)
    print('Wrote', OUT)

if __name__ == '__main__':
    main()
