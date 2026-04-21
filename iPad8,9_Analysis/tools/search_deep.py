import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    # proc fields
    b'off_proc_uid', b'off_proc_gid', b'off_proc_svuid', b'off_proc_svgid',
    b'off_proc_pflag', b'off_proc_p_fd', b'off_proc_p_textvp',
    # ucred fields
    b'off_ucred', b'off_ucred_rw',
    # sandbox fields
    b'off_ext_data', b'off_ext_datalen', b'off_ext_profile',
    b'off_sandbox_profile', b'off_sandbox_flags',
    # PPL
    b'ppl', b'xnu_ppl',
    # fd/rdir
    b'off_fd_rdir', b'off_fd_cdir', b'off_filedesc',
    # vnode
    b'off_vnode', b'rootvnode', b'off_v_type', b'off_v_mount',
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
            start = max(0, pos - 10)
            end = min(len(mm), pos + 120)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  [{t.decode()}] at {pos}: ...{chunk}...')
            mm.seek(pos + 1)
            found += 1
            if found >= 3:
                break
        if found == 0:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
