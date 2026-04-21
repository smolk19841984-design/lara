import sys
k1=r'..\\21D61\\kernelcache.decompressed'
k2=r'..\\21E219\\kernelcache.decompressed'
off=0x4cdd0
size=0x200
try:
    d1=open(k1,'rb').read()
    d2=open(k2,'rb').read()
except Exception as e:
    print('Error opening files:', e); sys.exit(1)
if off+size>len(d1) or off+size>len(d2):
    print('Region out of range')
    sys.exit(1)
seg1=d1[off:off+size]
seg2=d2[off:off+size]
if seg1==seg2:
    print('Region identical')
    sys.exit(0)
# print hex diff summary
print('Differing bytes at indices (hex):')
for i,(b1,b2) in enumerate(zip(seg1,seg2)):
    if b1!=b2:
        print(hex(off+i), hex(b1), '!=', hex(b2))
# print first 64 bytes of each
print('\nFirst 64 bytes (21D61):')
print(' '.join(f"{x:02x}" for x in seg1[:64]))
print('\nFirst 64 bytes (21E219):')
print(' '.join(f"{x:02x}" for x in seg2[:64]))
