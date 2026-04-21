import sys
path=r'C:/Users/smolk/Documents/2/lara-main/iPad8,9_Analysis/21D61/kernelcache.decompressed'
off=0x4CD80
n=0x200
with open(path,'rb') as f:
    f.seek(off)
    data=f.read(n)

for i in range(0,len(data),16):
    chunk=data[i:i+16]
    addr=off+i
    hexs=' '.join(f"{b:02x}" for b in chunk)
    asc=''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
    print(f"0x{addr:06x}: {hexs:<48}  {asc}")
