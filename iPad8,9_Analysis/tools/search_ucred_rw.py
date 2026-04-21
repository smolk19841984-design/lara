import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    b'ucred_rw', b'ucred_rw_p', b'off_ucred_rw',
    b'cr_uid.*ppl', b'ppl.*cr_uid',
    b'off_proc_p_ucred', b'off_proc_ro_p_ucred',
    b'off_proc_p_fd', b'off_proc_p_flag',
    b'off_filedesc_fd_rdir', b'off_filedesc_fd_cdir',
    b'off_vnode_v_mount', b'off_vnode_v_flag', b'off_vnode_v_data',
    b'off_vnode_v_name', b'off_vnode_v_iocount',
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
