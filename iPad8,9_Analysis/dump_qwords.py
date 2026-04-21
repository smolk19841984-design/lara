import struct
f='21D61\\kernelcache_decompressed\\kernelcache.release.ipad8.decompressed'
with open(f,'rb') as fh:
    fh.seek(0x880000)
    b=fh.read(128)
for i in range(0,128,8):
    v=struct.unpack_from('<Q', b, i)[0]
    print(hex(v))
