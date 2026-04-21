#!/usr/bin/env python3
import os,sys,struct
BASE=os.path.dirname(__file__)
AMFI_PATH=os.path.join(os.path.dirname(BASE),'21D61','kernelcache_decompressed','kexts','com.apple.driver.AppleMobileFileIntegrity')
PFX=512

def read32(data,off):
    return struct.unpack_from('<I',data,off)[0]

def parse_macho(data):
    # reuse minimal parser from sandbox_macho_parser.parse_macho
    MH_MAGIC_64 = 0xFEEDFACF
    LC_SEGMENT_64 = 0x19
    def r32(off): return struct.unpack_from('<I',data,off)[0]
    def r64(off): return struct.unpack_from('<Q',data,off)[0]
    if r32(0) != MH_MAGIC_64:
        raise SystemExit('Not a Mach-O 64-bit')
    ncmds = r32(16)
    off = 32
    sections=[]
    for _ in range(ncmds):
        cmd = r32(off)
        csz = r32(off+4)
        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('utf-8',errors='replace')
            vmaddr = r64(off+24)
            vmsize = r64(off+32)
            fileoff = r64(off+40)
            filesz = r64(off+48)
            nsects = r32(off+64)
            sect_off = off+72
            for i in range(nsects):
                sectname = data[sect_off:sect_off+16].rstrip(b'\x00').decode('utf-8',errors='replace')
                seg_n = data[sect_off+16:sect_off+32].rstrip(b'\x00').decode('utf-8',errors='replace')
                s_addr = r64(sect_off+32)
                s_size = r64(sect_off+40)
                s_off = r32(sect_off+48)
                sections.append({'sectname':sectname,'segname':seg_n,'addr':s_addr,'size':s_size,'offset':s_off})
                sect_off += 80
        off += csz
    return sections

def extract_strings(b,minlen=4):
    out=[]; cur=bytearray()
    for i,ch in enumerate(b):
        if 32<=ch<127:
            cur.append(ch)
        else:
            if len(cur)>=minlen:
                out.append((i-len(cur), bytes(cur).decode('utf-8',errors='replace')))
            cur=bytearray()
    if len(cur)>=minlen:
        out.append((len(b)-len(cur), bytes(cur).decode('utf-8',errors='replace')))
    return out

def find_prologue(buf, start_off, lookback=512):
    # search backwards for ARM64 prologue: STP X29, X30, [SP, #-0x??] => bytes 0xFD 0x7B .. pattern not unique
    # we'll search for common STP pattern 0xFD 0x7B (little-endian: 0x7B 0xFD)
    s = max(0, start_off - lookback)
    seg = buf[s:start_off]
    idx = seg.rfind(b'\xFD\x7B')
    if idx==-1:
        idx = seg.rfind(b'\xFD\x7C')
        if idx==-1:
            return None
    return s+idx

def main():
    if not os.path.isfile(AMFI_PATH):
        print('AMFI not found at', AMFI_PATH); sys.exit(1)
    with open(AMFI_PATH,'rb') as f:
        data = f.read()
    sections = parse_macho(data)
    strings = extract_strings(data,4)
    targets = [s for off,s in strings if 'cs_enforcement' in s or 'cs_enforce' in s or 'cs_enforcement_disable' in s]
    print(f'Found {len(targets)} cs_enforcement* string occurrences (may include duplicates).')
    # actually we need offsets too, so rebuild with offsets
    hits = [(off,s) for off,s in strings if 'cs_enforcement' in s or 'cs_enforce' in s or 'cs_enforcement_disable' in s]
    for off,s in hits:
        # find section containing this offset
        sect = None
        for se in sections:
            if se['offset'] <= off < se['offset']+se['size']:
                sect = se; break
        if not sect:
            print(f'  string at fileoff 0x{off:X} (no section) : {s[:80]}')
            continue
        vm = sect['addr'] + (off - sect['offset'])
        print(f"  fileoff=0x{off:X} vm=0x{vm:X} section={sect['segname']}.{sect['sectname']} string='{s[:80]}'")
        # look for nearby function prologue
        pro = find_prologue(data, off, lookback=PFX)
        if pro:
            # compute vmaddr for pro
            # find section for pro
            psect=None
            for se in sections:
                if se['offset'] <= pro < se['offset']+se['size']:
                    psect=se; break
            if psect:
                pvm = psect['addr'] + (pro - psect['offset'])
                sig = data[pro:pro+32]
                print(f"    nearby prologue at fileoff=0x{pro:X} vm=0x{pvm:X} sig={sig.hex()}")
            else:
                print(f"    prologue at fileoff=0x{pro:X} (no section)")
        else:
            print('    no prologue found nearby')
        # If no prologue, search for full 8-byte VM address occurrences in the __TEXT.__text section
        if not pro:
            vm_bytes = (sect['addr'] + (off - sect['offset'])).to_bytes(8, byteorder='little', signed=False)
            occurrences = [i for i in range(len(data)) if data.startswith(vm_bytes, i)]
            if occurrences:
                print(f'    Found {len(occurrences)} literal occurrences of vmaddr in AMFI binary')
            for occ in occurrences[:20]:
                # try to find prologue up to 512 bytes before occurrence
                pro2 = find_prologue(data, occ, lookback=512)
                if pro2:
                    psect=None
                    for se in sections:
                        if se['offset'] <= pro2 < se['offset']+se['size']:
                            psect=se; break
                    if psect:
                        pvm = psect['addr'] + (pro2 - psect['offset'])
                        sig = data[pro2:pro2+32]
                        print(f"    occ at fileoff=0x{occ:X} -> prologue at fileoff=0x{pro2:X} vm=0x{pvm:X} sig={sig.hex()}")
                    else:
                        print(f"    occ at fileoff=0x{occ:X} -> prologue at fileoff=0x{pro2:X} (no section)")
                else:
                    print(f'    occ at fileoff=0x{occ:X} -> no prologue found near occurrence')

if __name__=='__main__':
    main()
