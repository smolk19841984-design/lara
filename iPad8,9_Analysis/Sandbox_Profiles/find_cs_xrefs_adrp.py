#!/usr/bin/env python3
import os,sys,re,struct
BASE=os.path.dirname(__file__)
AMFI_PATH=os.path.join(os.path.dirname(BASE),'21D61','kernelcache_decompressed','kexts','com.apple.driver.AppleMobileFileIntegrity')
TARGET_VM = 0xFFFFFFF007410E50

def read32(data,off): return struct.unpack_from('<I',data,off)[0]
def read64(data,off): return struct.unpack_from('<Q',data,off)[0]

def parse_macho_sections(data):
    MH_MAGIC_64 = 0xFEEDFACF
    LC_SEGMENT_64 = 0x19
    if read32(data,0) != MH_MAGIC_64:
        raise SystemExit('Not Mach-O 64')
    ncmds = read32(data,16)
    off = 32
    sections = []
    for _ in range(ncmds):
        cmd = read32(data,off); csz = read32(data,off+4)
        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].rstrip(b'\x00').decode('utf-8',errors='replace')
            vmaddr = read64(data,off+24); vmsize = read64(data,off+32)
            fileoff = read64(data,off+40); filesz = read64(data,off+48)
            nsects = read32(data,off+64)
            sect_off = off+72
            for i in range(nsects):
                sectname = data[sect_off:sect_off+16].rstrip(b'\x00').decode('utf-8',errors='replace')
                seg_n = data[sect_off+16:sect_off+32].rstrip(b'\x00').decode('utf-8',errors='replace')
                s_addr = read64(data,sect_off+32); s_size = read64(data,sect_off+40); s_off = read32(data,sect_off+48)
                sections.append({'segname':seg_n,'sectname':sectname,'addr':s_addr,'size':s_size,'offset':s_off})
                sect_off += 80
        off += csz
    return sections

def find_text_exec_section(sections):
    for s in sections:
        if s['segname']=='__TEXT_EXEC' and s['sectname']=='__text':
            return s
    # fallback: search for __TEXT.__text
    for s in sections:
        if s['segname']=='__TEXT' and s['sectname']=='__text':
            return s
    return None

def run():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except Exception as e:
        print('capstone import failed:', e); sys.exit(1)
    if not os.path.isfile(AMFI_PATH):
        print('AMFI not found at', AMFI_PATH); sys.exit(1)
    with open(AMFI_PATH,'rb') as f:
        data = f.read()
    sections = parse_macho_sections(data)
    text = find_text_exec_section(sections)
    if not text:
        print('No __TEXT_EXEC.__text found in AMFI'); sys.exit(1)
    base_vm = text['addr']; off = text['offset']; size = text['size']
    code = data[off:off+size]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(code, base_vm))
    # build index by address
    addr_index = {ins.address: idx for idx,ins in enumerate(insns)}

    def imm_from_opstr(opstr):
        m = re.search(r'0x[0-9a-fA-F]+', opstr)
        return int(m.group(0),16) if m else None

    results = []
    for i,ins in enumerate(insns):
        if ins.mnemonic == 'adrp':
            # parse dest reg and imm
            dest = ins.op_str.split(',',1)[0].strip()
            imm1 = imm_from_opstr(ins.op_str)
            if imm1 is None: continue
            # look ahead for add or ldr using same dest
            for j in range(1,6):
                if i+j >= len(insns): break
                ins2 = insns[i+j]
                if ins2.mnemonic == 'add' and dest in ins2.op_str.split(',',1)[1]:
                    imm2 = imm_from_opstr(ins2.op_str)
                    if imm2 is None: imm2 = 0
                    addr = (imm1 & ~0xFFF) + imm2
                    # also capstone may provide imm1 as page address directly; try addr=imm1+imm2 too
                    addr2 = imm1 + imm2
                    if addr==TARGET_VM or addr2==TARGET_VM:
                        results.append((ins.address, ins, ins2, addr if addr==TARGET_VM else addr2, i))
                if ins2.mnemonic == 'ldr' and '[' in ins2.op_str and dest in ins2.op_str:
                    # ldr xN, [dest, #imm]
                    imm2 = imm_from_opstr(ins2.op_str)
                    if imm2 is None: imm2 = 0
                    addr = (imm1 & ~0xFFF) + imm2
                    addr2 = imm1 + imm2
                    if addr==TARGET_VM or addr2==TARGET_VM:
                        results.append((ins.address, ins, ins2, addr if addr==TARGET_VM else addr2, i))

    if not results:
        print('No ADRP+ADD/LDR XREFs to target VM found in __TEXT_EXEC.__text')
        # try searching for global variable in __DATA or __DATA_CONST
        data_sects = [s for s in sections if s['segname'].startswith('__DATA')]
        for s in data_sects:
            start = s['offset']; end = start + s['size']
            # search for 8-byte little-endian target
            b = TARGET_VM.to_bytes(8,byteorder='little')
            idx = data.find(b, start, end)
            if idx != -1:
                vm = s['addr'] + (idx - s['offset'])
                sig = data[idx:idx+8]
                print(f'Found target as 8-byte value in {s["segname"]}.{s["sectname"]} fileoff=0x{idx:X} vm=0x{vm:X}')
                # attempt to find nearby prologue
                pro_idx = data.rfind(b'\xFD\x7B', max(start, idx-512), idx)
                if pro_idx != -1:
                    # compute vm for pro
                    psect = s
                    pvm = psect['addr'] + (pro_idx - psect['offset'])
                    sig32 = data[pro_idx:pro_idx+32]
                    print(f'  nearby prologue at fileoff=0x{pro_idx:X} vm=0x{pvm:X} sig={sig32.hex()}')
                else:
                    print('  no nearby prologue')
        return

    # For each result, find function start (search backwards for STP X29, X30)
    for res in results:
        adrp_addr, adrp_ins, next_ins, final_addr, idx = res
        # search backwards in insns for stp x29, x30
        func_start_addr = None
        for k in range(idx, -1, -1):
            if insns[k].mnemonic == 'stp' and 'x29' in insns[k].op_str and 'x30' in insns[k].op_str:
                func_start_addr = insns[k].address
                break
        if func_start_addr is None:
            print(f'XREF at 0x{adrp_addr:X} -> final_addr=0x{final_addr:X}, but function prologue not found')
            continue
        # compute file offset of func_start
        func_fileoff = off + (func_start_addr - base_vm)
        sig32 = data[func_fileoff:func_fileoff+32]
        print(f'Found function using cs_enforcement at func_vm=0x{func_start_addr:X} fileoff=0x{func_fileoff:X} sig={sig32.hex()}')

if __name__=='__main__':
    run()
