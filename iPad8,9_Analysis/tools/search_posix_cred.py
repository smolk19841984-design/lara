import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    b'cr_uid', b'cr_ruid', b'cr_svuid', b'cr_gid', b'cr_rgid',
    b'cr_groups', b'cr_gmuid', b'cr_svgid', b'posix_cred',
    b'off_ucr', b'off_posix', b'off_cred', b'cr_ref',
    b'cr_audit', b'cr_session', b'cr_label'
]

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for t in targets:
        mm.seek(0)
        found = 0
        while True:
            pos = mm.find(t)
            if pos == -1:
                break
            start = max(0, pos - 20)
            end = min(len(mm), pos + 100)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  [{t.decode()}] at {pos}: ...{chunk}...')
            mm.seek(pos + 1)
            found += 1
            if found >= 5:
                break
        if found == 0:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
