import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    # proc structure
    b'off_proc_p_fd', b'off_proc_p_flag', b'off_proc_p_pid',
    b'off_proc_p_name', b'off_proc_p_proc_ro',
    b'off_proc_p_textvp', b'off_proc_p_list_le',
    # proc_ro structure
    b'off_proc_ro_p_ucred', b'off_proc_ro_pr_task',
    b'_rc_off_proc_ro_p_ucred', b'_rc_off_proc_ro_pr_task',
    # filedesc
    b'off_filedesc_fd_cdir', b'off_filedesc_fd_ofiles',
    b'off_fileglob_fg_data', b'off_fileglob_fg_flag',
    b'off_fileproc_fp_glob',
    # vnode
    b'off_vnode_v_mount', b'off_vnode_v_flag', b'off_vnode_v_data',
    b'off_vnode_v_name', b'off_vnode_v_parent', b'off_vnode_v_usecount',
    b'off_vnode_v_ncchildren', b'off_vnode_v_nclinks',
    # mount
    b'off_mount', b'off_mount_mnt_vnodecovered', b'off_mount_mnt_flag',
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
            end = min(len(mm), pos + 200)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  [{t.decode()}] at {pos}: ...{chunk}...')
            mm.seek(pos + 1)
            found += 1
            if found >= 2:
                break
        if found == 0:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
