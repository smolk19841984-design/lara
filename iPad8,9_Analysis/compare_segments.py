import struct

def parse_macho_segments(data):
    segments = {}
    ncmds = struct.unpack("<I", data[16:20])[0]
    offset = 32
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[offset:offset+8])
        if cmd == 0x19:
            segname = data[offset+8:offset+24].rstrip(b"\00").decode("ascii", errors="replace")
            vmaddr = struct.unpack("<Q", data[offset+32:offset+40])[0]
            vmsize = struct.unpack("<Q", data[offset+40:offset+48])[0]
            fileoff = struct.unpack("<Q", data[offset+48:offset+56])[0]
            filesize = struct.unpack("<Q", data[offset+56:offset+64])[0]
            segments[segname] = {"vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize}
        offset += cmdsize
    return segments

with open(r"C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21D61\kernelcache.decompressed", "rb") as f:
    kc173 = f.read()
with open(r"C:\Users\smolk\Documents\2\lara-main\iPad8,9_Analysis\21E219\kernelcache.decompressed", "rb") as f:
    kc174 = f.read()

print(f"17.3.1 size: {len(kc173):,} bytes")
print(f"17.4 size:   {len(kc174):,} bytes")

segs173 = parse_macho_segments(kc173)
segs174 = parse_macho_segments(174)

print(f"\n17.3.1 segments: {list(segs173.keys())}")
print(f"17.4 segments:   {list(segs174.keys())}")

print("\n=== Segment Comparison ===")
all_segs = set(segs173.keys()) | set(segs174.keys())
for seg in sorted(all_segs):
    s173 = segs173.get(seg, {})
    s174 = segs174.get(seg, {})
    v173 = s173.get("vmsize", 0)
    v174 = s174.get("vmsize", 0)
    diff = v174 - v173
    print(f"{seg:20s}  17.3.1: 0{v173:x}  17.4: 0{v174:x}  diff: {diff:+d} ({abs(diff):x=})")
