#!/usr/bin/env python3
import os, json

ROOT = os.path.join(os.path.dirname(__file__), '..')
BUILDS = ['21D61', '21E219']
TARGETS = [
    # PPL
    'ppl_', 'pmap_set_xprr_perm', 'pmap_set_nested_xprr', 'pmap_update_xprr', 'pmap_mark_page_as_ppl_page', 'pmap_create_ppl',
    # SPTM
    'sptm_', 'pmap_sptm_',
    # pmap core
    'pmap_protect', 'pmap_enter', 'pmap_enter_options', 'pmap_remove', 'pmap_remove_options', 'pmap_change_wiring', 'pmap_nest', 'pmap_unnest', 'pmap_expand', 'pmap_create', 'pmap_destroy', 'pmap_set_options',
    # validation
    'pmap_verify_free', 'pmap_valid_page', 'pmap_valid_phys', 'pmap_lookup_in_loaded_kexts', 'pmap_is_in_kernel_region',
    # locks
    'pmap_lock', 'pmap_unlock', 'pmap_lock_dir', 'pmap_unlock_dir', 'pmap_assert_locked', 'pmap_lock_assert',
    # cs
    'pmap_cs_', 'pmap_cs_enter', 'pmap_cs_validate',
    # trust cache
    'pmap_trust_cache', 'pmap_image4_trust_caches', 'pmap_get_default_access',
    # memory access
    'ml_nofault_copy', 'ml_static_copy', 'pmap_copy', 'pmap_copy_page',
    # page allocation
    'pmap_get_phys_page', 'pmap_free_page', 'pmap_alloc_page', 'pmap_page_is_mapped',
    # ref/submap
    'pmap_set_reference', 'pmap_clear_reference', 'pmap_set_submap',
]

def search_in_file(path, pat):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return []
    res = []
    idx = 0
    bpat = pat.encode('utf-8')
    while True:
        i = data.find(bpat, idx)
        if i == -1:
            break
        res.append(i)
        idx = i + 1
    return res

def scan_build(build):
    out = {}
    build_dir = os.path.join(ROOT, build)
    kc = os.path.join(build_dir, 'kernelcache.decompressed')
    files = []
    if os.path.isfile(kc):
        files.append(('kernelcache.decompressed', kc))
    kexts_dir = os.path.join(build_dir, 'kexts')
    if os.path.isdir(kexts_dir):
        for root, dirs, fs in os.walk(kexts_dir):
            for fn in fs:
                files.append((os.path.relpath(os.path.join(root, fn), build_dir), os.path.join(root, fn)))

    for t in TARGETS:
        out[t] = []
        for display, path in files:
            matches = search_in_file(path, t)
            if matches:
                for m in matches:
                    out[t].append({'file': display, 'fileoff': hex(m)})
    return out

def main():
    report = {}
    for b in BUILDS:
        report[b] = scan_build(b)
    outp = os.path.join(os.path.dirname(__file__), 'find_functions_report.json')
    with open(outp, 'w', encoding='utf-8') as fo:
        json.dump(report, fo, indent=2)
    print('Wrote', outp)

if __name__ == '__main__':
    main()
