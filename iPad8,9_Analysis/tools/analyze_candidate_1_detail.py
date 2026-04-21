import struct
from pathlib import Path

KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

def disasm_instruction(instr, pc_vm=None):
    """ARM64 disassembler with PC-relative calculation"""
    if instr == 0xD503201F: return 'nop'
    if instr == 0xD503237F: return 'pacibsp'
    if instr == 0xD65F0BFF: return 'retab'
    if instr == 0xD65F03C0: return 'ret'
    if instr == 0xA9BF7BFD: return 'stp x29, x30, [sp, #-0x10]!'
    if instr == 0x910003FD: return 'mov x29, sp'
    if instr == 0xA8C17BFD: return 'ldp x29, x30, [sp], #0x10'
    if instr == 0xD50323FF: return 'paciasp'
    if instr == 0xD503245F: return 'autiasp'
    if instr == 0xD50320DF: return 'esb'
    
    # ADRP
    if (instr & 0x9F000000) == 0x90000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        target = (pc_vm & ~0xFFF) + imm if pc_vm else imm
        return f'adrp x{rd}, #0x{imm:x}  // -> 0x{target:x}'
    
    # ADR
    if (instr & 0x9F000000) == 0x10000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        target = pc_vm + imm if pc_vm else imm
        return f'adr x{rd}, #0x{imm:x}  // -> 0x{target:x}'
    
    # ADD (immediate)
    if (instr & 0xFFC003FF) == 0x91000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        shift = (instr >> 22) & 0x3
        imm = imm12 << (shift * 12)
        return f'add x{rd}, x{rn}, #0x{imm:x}'
    
    # SUB (immediate)
    if (instr & 0xFFC003FF) == 0xD1000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        shift = (instr >> 22) & 0x3
        imm = imm12 << (shift * 12)
        return f'sub x{rd}, x{rn}, #0x{imm:x}'
    
    # MOVZ
    if (instr & 0x1F800000) == 0x52800000:
        op = (instr >> 29) & 0x3
        rd = instr & 0x1F
        imm16 = (instr >> 5) & 0xFFFF
        if op == 0: return f'movz w{rd}, #0x{imm16:x}'
        elif op == 1: return f'movk w{rd}, #0x{imm16:x}'
    
    # MOVZ X
    if (instr & 0x1F800000) == 0xD2800000:
        rd = instr & 0x1F
        imm16 = (instr >> 5) & 0xFFFF
        return f'movz x{rd}, #0x{imm16:x}'
    
    # CMP (immediate) W
    if (instr & 0xFF80001F) == 0x7100001F:
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'cmp w{rn}, #0x{imm12:x}'
    
    # CMP (immediate) X
    if (instr & 0xFF80001F) == 0xF100001F:
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'cmp x{rn}, #0x{imm12:x}'
    
    # TST
    if (instr & 0xFF80001F) == 0x7200001F:
        rn = (instr >> 5) & 0x1F
        imm16 = (instr >> 5) & 0xFFFF
        return f'tst w{rn}, #0x{imm16:x}'
    
    # B.cond
    if (instr & 0xFF000010) == 0x54000000:
        cond = instr & 0xF
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000: imm = imm | 0xFFFC0000
        target = pc_vm + (imm << 2) if pc_vm else imm << 2
        cond_names = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']
        return f'b.{cond_names[cond]} #+0x{imm << 2:x}  // -> 0x{target:x}'
    
    # B (unconditional)
    if (instr & 0xFC000000) == 0x14000000:
        imm = instr & 0x03FFFFFF
        if imm & 0x02000000: imm = imm | 0xFC000000
        target = pc_vm + (imm << 2) if pc_vm else imm << 2
        return f'b #+0x{imm << 2:x}  // -> 0x{target:x}'
    
    # BL
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x03FFFFFF
        if imm & 0x02000000: imm = imm | 0xFC000000
        target = pc_vm + (imm << 2) if pc_vm else imm << 2
        return f'bl #+0x{imm << 2:x}  // -> 0x{target:x}'
    
    # CBZ/CBNZ W
    if (instr & 0x7F000000) == 0x34000000:
        is_cbnz = (instr >> 24) & 1
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000: imm = imm | 0xFFFC0000
        target = pc_vm + (imm << 2) if pc_vm else imm << 2
        return f'{"cbnz" if is_cbnz else "cbz"} w0, #+0x{imm << 2:x}  // -> 0x{target:x}'
    
    # LDR (immediate)
    if (instr & 0xFFC00000) == 0xF9400000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'ldr x{rt}, [x{rn}, #0x{imm12 << 3:x}]'
    
    # LDRSW
    if (instr & 0xFFC00000) == 0xB9800000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'ldrsw x{rt}, [x{rn}, #0x{imm12 << 2:x}]'
    
    # LDR W
    if (instr & 0xFFC00000) == 0xB9400000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'ldr w{rt}, [x{rn}, #0x{imm12 << 2:x}]'
    
    # STR W
    if (instr & 0xFFC00000) == 0xB9000000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'str w{rt}, [x{rn}, #0x{imm12 << 2:x}]'
    
    # STR X
    if (instr & 0xFFC00000) == 0xF9000000:
        rt = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'str x{rt}, [x{rn}, #0x{imm12 << 3:x}]'
    
    # AND
    if (instr & 0x1F800000) == 0x0A000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        rm = (instr >> 16) & 0x1F
        return f'and x{rd}, x{rn}, x{rm}'
    
    # EOR
    if (instr & 0x1F800000) == 0xCA000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        rm = (instr >> 16) & 0x1F
        return f'eor x{rd}, x{rn}, x{rm}'
    
    # UDF
    if (instr & 0x0000FFFF) == 0:
        return f'udf #0x{(instr >> 16) & 0xFFFF:x}'
    
    return f'.word 0x{instr:08x}'

def find_function_end(data, start_fo, end_fo, max_instructions=500):
    """Find the end of a function by looking for ret + next prologue or padding"""
    ret_count = 0
    for j in range(max_instructions):
        fo = start_fo + j * 4
        if fo + 4 >= end_fo:
            return fo
        w = struct.unpack('<I', data[fo:fo+4])[0]
        if w == 0xD65F03C0 or w == 0xD65F0BFF:  # ret or retab
            ret_count += 1
            # Check if next instruction is a prologue or padding
            if fo + 8 < end_fo:
                next_w = struct.unpack('<I', data[fo+4:fo+8])[0]
                if next_w == 0xA9BF7BFD or next_w == 0xD503237F:
                    return fo + 4
                if ret_count >= 2:
                    return fo + 4
    return start_fo + max_instructions * 4

def find_callers(data, target_fo, start_fo, end_fo):
    """Find all BL instructions that call the target function"""
    callers = []
    for i in range(start_fo, end_fo - 4, 4):
        w = struct.unpack('<I', data[i:i+4])[0]
        if (w & 0xFC000000) == 0x94000000:  # BL
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm = imm | 0xFC000000
            target = i + (imm << 2)
            if abs(target - target_fo) < 8:
                callers.append(i)
    return callers

def analyze_candidate_1():
    """Detailed analysis of Candidate 1"""
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    # Candidate 1 offsets
    fo_1731 = 0xd48000 + (0xfffffff007f2e930 - 0xfffffff007d4c000)
    fo_174 = 0xd48000 + (0xfffffff007f2eacc - 0xfffffff007d4c000)
    
    vm_1731 = 0xfffffff007d4c000 + (fo_1731 - 0xd48000)
    vm_174 = 0xfffffff007d4c000 + (fo_174 - 0xd48000)
    
    start_fo = 0xd48000
    end_fo = 0xd48000 + 0x22bc000
    
    print(f'\n{"="*80}')
    print(f'Candidate 1: VM 0x{vm_1731:x} (17.3.1) vs 0x{vm_174:x} (17.4)')
    print(f'{"="*80}')
    
    # Disassemble full function in 17.4
    print(f'\n17.4 full function (fileoff 0x{fo_174:x}):')
    print(f'{"-"*80}')
    func_end = find_function_end(data2, fo_174, end_fo, 500)
    for j in range((func_end - fo_174) // 4):
        fo = fo_174 + j * 4
        w = struct.unpack('<I', data2[fo:fo+4])[0]
        vm = 0xfffffff007d4c000 + (fo - 0xd48000)
        disasm = disasm_instruction(w, vm)
        print(f'  0x{vm:x}: {disasm}')
    
    print(f'\nFunction size: {func_end - fo_174} bytes ({(func_end - fo_174) // 4} instructions)')
    
    # Find callers in 17.4
    print(f'\nFinding callers of 0x{vm_174:x} in 17.4...')
    callers_174 = find_callers(data2, fo_174, start_fo, end_fo)
    print(f'Found {len(callers_174)} callers')
    
    for caller_fo in callers_174[:20]:
        caller_vm = 0xfffffff007d4c000 + (caller_fo - 0xd48000)
        # Show context around caller
        print(f'\n  Caller at 0x{caller_vm:x} (fileoff 0x{caller_fo:x}):')
        for j in range(-10, 5):
            fo = caller_fo + j * 4
            if fo < start_fo or fo >= end_fo:
                continue
            w = struct.unpack('<I', data2[fo:fo+4])[0]
            vm = 0xfffffff007d4c000 + (fo - 0xd48000)
            disasm = disasm_instruction(w, vm)
            marker = '>>>' if j == 0 else '   '
            print(f'    {marker} 0x{vm:x}: {disasm}')
    
    # Find callers in 17.3.1 (of the stub function)
    print(f'\nFinding callers of 0x{vm_1731:x} in 17.3.1...')
    callers_1731 = find_callers(data1, fo_1731, start_fo, end_fo)
    print(f'Found {len(callers_1731)} callers')
    
    for caller_fo in callers_1731[:20]:
        caller_vm = 0xfffffff007d4c000 + (caller_fo - 0xd48000)
        print(f'\n  Caller at 0x{caller_vm:x} (fileoff 0x{caller_fo:x}):')
        for j in range(-10, 5):
            fo = caller_fo + j * 4
            if fo < start_fo or fo >= end_fo:
                continue
            w = struct.unpack('<I', data1[fo:fo+4])[0]
            vm = 0xfffffff007d4c000 + (fo - 0xd48000)
            disasm = disasm_instruction(w, vm)
            marker = '>>>' if j == 0 else '   '
            print(f'    {marker} 0x{vm:x}: {disasm}')
    
    # Save analysis
    output_path = OUTPUT_DIR / 'candidate_1_analysis.txt'
    with output_path.open('w', encoding='utf-8') as f:
        f.write(f'Candidate 1 Analysis\n')
        f.write(f'{"="*80}\n')
        f.write(f'VM 17.3.1: 0x{vm_1731:x}\n')
        f.write(f'VM 17.4:   0x{vm_174:x}\n')
        f.write(f'\n17.4 full function:\n')
        f.write(f'{"-"*80}\n')
        for j in range((func_end - fo_174) // 4):
            fo = fo_174 + j * 4
            w = struct.unpack('<I', data2[fo:fo+4])[0]
            vm = 0xfffffff007d4c000 + (fo - 0xd48000)
            disasm = disasm_instruction(w, vm)
            f.write(f'  0x{vm:x}: {disasm}\n')
        
        f.write(f'\nCallers in 17.4 ({len(callers_174)} total):\n')
        for caller_fo in callers_174[:20]:
            caller_vm = 0xfffffff007d4c000 + (caller_fo - 0xd48000)
            f.write(f'  0x{caller_vm:x}\n')
        
        f.write(f'\nCallers in 17.3.1 ({len(callers_1731)} total):\n')
        for caller_fo in callers_1731[:20]:
            caller_vm = 0xfffffff007d4c000 + (caller_fo - 0xd48000)
            f.write(f'  0x{caller_vm:x}\n')
    
    print(f'\nAnalysis saved to: {output_path}')

if __name__ == '__main__':
    analyze_candidate_1()
