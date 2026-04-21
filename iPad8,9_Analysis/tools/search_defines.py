import mmap, re

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'
targets = [
    b'#define off_proc_p_fd',
    b'#define off_proc_p_flag',
    b'#define off_proc_p_pid',
    b'#define off_proc_p_proc_ro',
    b'#define off_proc_ro_p_ucred',
    b'#define off_proc_ro_pr_task',
    b'#define off_filedesc_fd_cdir',
    b'#define off_filedesc_fd_rdir',
    b'#define off_filedesc_fd_ofiles',
    b'#define off_vnode_v_mount',
    b'#define off_vnode_v_flag',
    b'#define off_vnode_v_data',
    b'#define off_vnode_v_name',
    b'#define off_vnode_v_parent',
    b'#define off_mount_mnt_vnodecovered',
    b'#define off_mount_mnt_flag',
]

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for t in targets:
        mm.seek(0)
        pos = mm.find(t)
        if pos != -1:
            start = max(0, pos - 5)
            end = min(len(mm), pos + 100)
            chunk = mm[start:end].decode('utf-8', errors='replace')
            print(f'  {chunk}')
        else:
            print(f'  NOT FOUND: {t.decode()}')
    mm.close()
