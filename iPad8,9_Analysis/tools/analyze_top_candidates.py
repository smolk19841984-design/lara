import struct
from pathlib import Path

KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

def disasm_instruction(instr):
    """Simple ARM64 disassembler for common instructions"""
    # NOP
    if instr == 0xD503201F:
        return 'nop'
    # PACIBSP
    if instr == 0xD503237F:
        return 'pacibsp'
    # RETAB
    if instr == 0xD65F0BFF:
        return 'retab'
    # RET
    if instr == 0xD65F03C0:
        return 'ret'
    # STP x29, x30, [sp, #-0x10]!
    if instr == 0xA9BF7BFD:
        return 'stp x29, x30, [sp, #-0x10]!'
    # MOV x29, xsp
    if instr == 0x910003FD:
        return 'mov x29, sp'
    # LDP x29, x30, [sp], #0x10
    if instr == 0xA8C17BFD:
        return 'ldp x29, x30, [sp], #0x10'
    
    # ADRP
    if (instr & 0x9F000000) == 0x90000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        return f'adrp x{rd}, #0x{imm:x}'
    
    # ADR
    if (instr & 0x9F000000) == 0x10000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        return f'adr x{rd}, #0x{imm:x}'
    
    # ADD (immediate)
    if (instr & 0xFF8003FF) == 0x91000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'add x{rd}, x{rn}, #0x{imm12:x}'
    
    # MOVZ
    if (instr & 0x1F800000) == 0x52800000:
        op = (instr >> 29) & 0x3
        rd = instr & 0x1F
        imm16 = (instr >> 5) & 0xFFFF
        if op == 0:
            return f'movz w{rd}, #0x{imm16:x}'
        elif op == 1:
            return f'movk w{rd}, #0x{imm16:x}'
    
    # CMP (immediate) W
    if (instr & 0xFF80001F) == 0x7100001F:
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'cmp w{rn}, #0x{imm12:x}'
    
    # B.cond
    if (instr & 0xFF000010) == 0x54000000:
        cond = instr & 0xF
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm = imm | 0xFFFC0000
        cond_names = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']
        return f'b.{cond_names[cond]} #+0x{imm << 2:x}'
    
    # BL
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x03FFFFFF
        if imm & 0x02000000:
            imm = imm | 0xFC000000
        return f'bl #+0x{imm << 2:x}'
    
    # CBZ/CBNZ
    if (instr & 0x7F000000) == 0x34000000:
        is_cbnz = (instr >> 24) & 1
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm = imm | 0xFFFC0000
        return f'{"cbnz" if is_cbnz else "cbz"} w0, #+0x{imm << 2:x}'
    
    # UDF
    if (instr & 0x0000FFFF) == 0:
        return f'udf #0x{(instr >> 16) & 0xFFFF:x}'
    
    # Default
    return f'.word 0x{instr:08x}'

def analyze_top_candidates():
    """Analyze top candidate functions in detail"""
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    # Top candidates from previous analysis (functions that gained cmp+bcond in 17.4)
    candidates = [
        # (fo_1731, fo_174) - file offsets in __TEXT_EXEC
        # Candidate 1: VM 0xfffffff007f2e930 vs 0xfffffff007f2eacc
        (0xd48000 + (0xfffffff007f2e930 - 0xfffffff007d4c000),
         0xd48000 + (0xfffffff007f2eacc - 0xfffffff007d4c000)),
        # Candidate 8: VM 0xfffffff0083d307c vs 0xfffffff0083d2d04
        (0xd48000 + (0xfffffff0083d307c - 0xfffffff007d4c000),
         0xd48000 + (0xfffffff0083d2d04 - 0xfffffff007d4c000)),
        # Candidate 9: VM 0xfffffff0083f3810 vs 0xfffffff0083f2c78
        (0xd48000 + (0xfffffff0083f3810 - 0xfffffff007d4c000),
         0xd48000 + (0xfffffff0083f2c78 - 0xfffffff007d4c000)),
    ]
    
    for idx, (fo_1731, fo_174) in enumerate(candidates):
        vm_1731 = 0xfffffff007d4c000 + (fo_1731 - 0xd48000)
        vm_174 = 0xfffffff007d4c000 + (fo_174 - 0xd48000)
        
        print(f'\n{"="*80}')
        print(f'Candidate {idx+1}: VM 0x{vm_1731:x} (17.3.1) vs 0x{vm_174:x} (17.4)')
        print(f'{"="*80}')
        
        print(f'\n17.3.1 (fileoff 0x{fo_1731:x}):')
        for j in range(60):
            w = struct.unpack('<I', data1[fo_1731 + j*4:fo_1731 + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (fo_1731 + j*4 - 0xd48000)
            disasm = disasm_instruction(w)
            print(f'  0x{vm:x}: {disasm}')
        
        print(f'\n17.4 (fileoff 0x{fo_174:x}):')
        for j in range(60):
            w = struct.unpack('<I', data2[fo_174 + j*4:fo_174 + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (fo_174 + j*4 - 0xd48000)
            disasm = disasm_instruction(w)
            print(f'  0x{vm:x}: {disasm}')

if __name__ == '__main__':
    analyze_top_candidates()
