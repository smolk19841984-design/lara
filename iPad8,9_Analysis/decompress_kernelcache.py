#!/usr/bin/env python3
"""iOS Kernelcache Decompressor
"""

import struct
import sys
import os

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def detect_format(data):
    if len(data) < 4:
        return "unknown"
    magic = data[:4]
    if magic == b"IMG4":
        return "img4"
    if magic in (b"bvxn", b"bvx1", b"bvx2", b"bvx-"):
        return "lzfse"
    if magic == b"lzss":
        return "lzss"
    if magic == b"comp":
        return "compressed"
    if magic == b"\xcf\xfa\xed\xfe":
        return "macho64"
    if magic == b"\xce\xfa\xed\xfe":
        return "macho32"
    if magic == b"\xca\xfe\ba\be":
        return "fat"
    return "unknown"

def decompress_lzss(data):
    if len(data) < 4:
        raise ValueError("LZSS data too short")
    output = bytearray()
    pos = 4
    while pos < len(data):
        flag = data[pos]
        pos += 1
        for i in range(8):
            if pos >= len(data):
                break
            if flag & (1 << i):
                output.append(data[pos])
                pos += 1
            else:
                if pos + 2 > len(data):
                    break
                ref = struct.unpack("<H", data[pos:pos+2])[0]
                pos += 2
                offset = (ref >> 4) + 1
                length = (ref & 0xF) + 3
                if offset > len(output):
                    return None
                for j in range(length):
                    output.append(output[-offset])
    return bytes(output)

def decompress_lzfse(data):
    try:
        import lzfse
        return lzfse.decompress(data)
    except ImportError:
        print("LZFSE decompression not available. Install pyliblzfse.")
        return None

def strip_img4(data):
    if data[:4] != b"IMG4":
        return data
    macho_magic_64 = b"\xcf\xfa\xed\xfe"
    macho_magic_32 = b"\xce\xfa\xed\xfe"
    for magic in [macho_magic_64, macho_magic_32]:
        idx = data.find(magic)
        if idx >= 0:
            print(f"Found Mach-O at offset 0{idx:x}")
            return data[idx:]
    return None

def is_kernelcache_decompressed(data):
    if len(data) < 32:
        return False
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xfeedfacf, 0xfeedface):
        return False
    ncmds = struct.unpack("<I", data[16:20])[0]
    sizeofcmds = struct.unpack("<I", data[20:24])[0]
    if ncmds < 10 or ncmds > 500:
        return False
    if sizeofcmds < 1000 or sizeofcmds > len(data):
        return False
    known_segments = [b"__TEXT", b"__DATA", b"__LINKEDIT", b"__PRELINK_TEXT", b"__PRELINK_INFO"]
    found = 0
    offset = 32
    for i in range(min(ncmds, 500)):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack("<II", data[offset:offset+8])
        if cmd in (0x19, 0x1A):
            segname = data[offset+8:offset+24]
            for known in known_segments:
                if known in segname:
                    found += 1
                    break
        offset += cmdsize
    return found >= 3

def decompress_kernelcache(input_path, output_path):
    print(f"Reading kernelcache: {input_path}")
    data = read_file(input_path)
    print(f"File size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")
    fmt = detect_format(data)
    print(f"Detected format: {fmt}")
    if fmt == "img4":
        print("Stripping IMG4 wrapper...")
        data = strip_img4(data)
        if data is None:
            print("ERROR: Failed to strip IMG4")
            return False
        fmt = detect_format(data)
        print(f"After IMG4 strip: {fmt}")
    if is_kernelcache_decompressed(data):
        print("Kernelcache is already decompressed (valid Mach-O with segments)")
        print(f"Writing to: {output_path}")
        write_file(output_path, data)
        print("Done!")
        return True
    if fmt == "lzss":
        print("Decompressing LZSS...")
        decompressed = decompress_lzss(data)
    elif fmt == "lzfse":
        print("Decompressing LZFSE...")
        decompressed = decompress_lzfse(data)
    elif fmt == "compressed":
        print("Decompressing compressed format...")
        decompressed = decompress_lzss(data)
    else:
        print(f"Unknown format: {fmt}")
        print("Attempting to find Mach-O within file...")
        macho_magic = b"\xcf\xfa\xed\xfe"
        idx = data.find(macho_magic)
        if idx >= 0:
            print(f"Found Mach-O at offset 0{idx:x}")
            data = data[idx:]
            if is_kernelcache_decompressed(data):
                print("Extracted valid Mach-O kernelcache")
                write_file(output_path, data)
                return True
        print("ERROR: Could not decompress")
        return False
    if decompressed is None:
        print("ERROR: Decompression failed")
        return False
    print(f"Decompressed size: {len(decompressed):,} bytes ({len(decompressed)/1024/1024:.1f} MB)")
    if is_kernelcache_decompressed(decompressed):
        print("Verification: Valid Mach-O kernelcache")
        write_file(output_path, decompressed)
        print(f"Written to: {output_path}")
        return True
    else:
        print("WARNING: Output does not appear to be a valid Mach-O kernelcache")
        print("Writing anyway for manual inspection...")
        write_file(output_path, decompressed)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python decompress_kernelcache.py <input> <output>")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)
    success = decompress_kernelcache(input_path, output_path)
    sys.exit(0 if success else 1)
