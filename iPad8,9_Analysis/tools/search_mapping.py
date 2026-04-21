import mmap, re, sys

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [b'off_proc_proc_ro', b'off_proc_ro_ucred', b'off_ucred_cr_label', b'off_label_sandbox', b'off_sandbox_ext_set']

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for t in targets:
        mm.seek(0)
        found = 0
        while True:
            pos = mm.find(t)
            if pos == -1:
                break
            start = max(0, pos - 10)
            end = min(len(mm), pos + 80)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  Found at {pos}: ...{chunk}...')
            mm.seek(pos + 1)
            found += 1
            if found >= 3:
                break
        if found == 0:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
