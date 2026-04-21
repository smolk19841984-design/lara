import mmap

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'

# Search for the null-separated offset list that contains proc/vnode/filedesc offsets
# We know from previous search that these exist as _off_* strings
targets = [
    b'_off_proc_p_fd\x00',
    b'_off_proc_p_flag\x00',
    b'_off_proc_p_pid\x00',
    b'_off_proc_p_name\x00',
    b'_off_proc_p_proc_ro\x00',
    b'_off_proc_p_textvp\x00',
    b'_off_filedesc_fd_cdir\x00',
    b'_off_filedesc_fd_ofiles\x00',
    b'_off_vnode_v_mount\x00',
    b'_off_vnode_v_flag\x00',
    b'_off_vnode_v_data\x00',
    b'_off_vnode_v_name\x00',
    b'_off_vnode_v_parent\x00',
    b'_off_vnode_v_iocount\x00',
    b'_off_vnode_v_ncchildren\x00',
    b'_off_vnode_v_nclinks\x00',
    b'_off_vnode_v_usecount\x00',
]

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for t in targets:
        mm.seek(0)
        pos = mm.find(t)
        if pos != -1:
            # Get 300 bytes of context after to see neighboring offsets
            end = min(len(mm), pos + 400)
            chunk = mm[pos:end].decode('utf-8', errors='replace')
            # Show as null-separated list
            parts = chunk.split('\x00')
            print(f'  {t.decode().strip(chr(0))}: {parts[:15]}')
        else:
            print(f'  NOT FOUND: {t.decode().strip(chr(0))}')
    mm.close()
