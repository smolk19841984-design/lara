import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    b'possibly wrong', b'ios 17', b'iOS 17',
    b'off_proc_uid', b'off_proc_gid',
    b'cr_uid', b'cr_ruid', b'cr_svuid',
    b'cr_ngroups', b'cr_ref',
    b'off_proc_p_csflags', b'off_proc_p_ucred',
    b'off_proc_p_sysent', b'off_proc_p_fd',
    b'off_ucred_cr_ref', b'off_ucred_cr_posix',
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
            start = max(0, pos - 30)
            end = min(len(mm), pos + 150)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  [{t.decode()}] at {pos}: ...{chunk}...')
            mm.seek(pos + 1)
            found += 1
            if found >= 3:
                break
        if found == 0:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
