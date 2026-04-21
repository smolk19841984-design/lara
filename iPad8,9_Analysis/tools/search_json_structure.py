import mmap, json, re

path = '/mnt/c/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/8ksec_archive/mapping.json'

with open(path, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    
    # Find the keyword index section
    mm.seek(0)
    pos = mm.find(b'"keyword"')
    if pos != -1:
        # Get surrounding context to understand structure
        start = max(0, pos - 50)
        end = min(len(mm), pos + 500)
        chunk = mm[start:end].decode('utf-8', errors='replace')
        print(f'First keyword context:\n{chunk[:500]}')
    
    # Also search for "off_proc_uid" with 0x value
    mm.seek(0)
    pos = mm.find(b'0x30')
    count = 0
    while pos != -1 and count < 5:
        start = max(0, pos - 50)
        end = min(len(mm), pos + 50)
        chunk = mm[start:end].decode('utf-8', errors='replace')
        if 'proc' in chunk.lower() or 'uid' in chunk.lower():
            print(f'\n0x30 context: ...{chunk}...')
            count += 1
        mm.seek(pos + 1)
        pos = mm.find(b'0x30')
    
    mm.close()
