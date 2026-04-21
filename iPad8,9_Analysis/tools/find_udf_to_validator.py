import struct
from pathlib import Path

KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

def disasm_instruction(instr):
    """Simple ARM64 disassembler"""
    if instr == 0xD503201F: return 'nop'
    if instr == 0xD503237F: return 'pacibsp'
    if instr == 0xD65F0BFF: return 'retab'
    if instr == 0xD65F03C0: return 'ret'
    if instr == 0xA9BF7BFD: return 'stp x29, x30, [sp, #-0x10]!'
    if instr == 0x910003FD: return 'mov x29, sp'
    if instr == 0xA8C17BFD: return 'ldp x29, x30, [sp], #0x10'
    if instr == 0xD50323FF: return 'hint #0x18'  # paciasp
    
    if (instr & 0x9F000000) == 0x90000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = ((immhi << 2) | immlo) << 12
        return f'adrp x{rd}, #0x{imm:x}'
    if (instr & 0x9F000000) == 0x10000000:
        rd = instr & 0x1F
        immlo = (instr >> 29) & 0x3
        immhi = (instr >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        return f'adr x{rd}, #0x{imm:x}'
    if (instr & 0xFF8003FF) == 0x91000000:
        rd = instr & 0x1F
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'add x{rd}, x{rn}, #0x{imm12:x}'
    if (instr & 0x1F800000) == 0x52800000:
        op = (instr >> 29) & 0x3
        rd = instr & 0x1F
        imm16 = (instr >> 5) & 0xFFFF
        if op == 0: return f'movz w{rd}, #0x{imm16:x}'
        elif op == 1: return f'movk w{rd}, #0x{imm16:x}'
    if (instr & 0xFF80001F) == 0x7100001F:
        rn = (instr >> 5) & 0x1F
        imm12 = (instr >> 10) & 0xFFF
        return f'cmp w{rn}, #0x{imm12:x}'
    if (instr & 0xFF000010) == 0x54000000:
        cond = instr & 0xF
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000: imm = imm | 0xFFFC0000
        cond_names = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']
        return f'b.{cond_names[cond]} #+0x{imm << 2:x}'
    if (instr & 0xFC000000) == 0x94000000:
        imm = instr & 0x03FFFFFF
        if imm & 0x02000000: imm = imm | 0xFC000000
        return f'bl #+0x{imm << 2:x}'
    if (instr & 0x7F000000) == 0x34000000:
        is_cbnz = (instr >> 24) & 1
        imm = (instr >> 5) & 0x7FFFF
        if imm & 0x40000: imm = imm | 0xFFFC0000
        return f'{"cbnz" if is_cbnz else "cbz"} w0, #+0x{imm << 2:x}'
    if (instr & 0x0000FFFF) == 0:
        return f'udf #0x{(instr >> 16) & 0xFFFF:x}'
    return f'.word 0x{instr:08x}'

def find_udf_to_validator():
    """Find functions that were udf/ret stubs in 17.3.1 but became validators in 17.4"""
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    start_fo = 0xd48000
    end_fo = 0xd48000 + 0x22bc000
    
    # Find all function prologues
    functions_1731 = []
    functions_174 = []
    
    for i in range(start_fo, end_fo - 4, 4):
        w1 = struct.unpack('<I', data1[i:i+4])[0]
        w2 = struct.unpack('<I', data2[i:i+4])[0]
        if w1 == 0xA9BF7BFD:
            functions_1731.append(i)
        if w2 == 0xA9BF7BFD:
            functions_174.append(i)
    
    print(f'Found {len(functions_1731)} functions in 17.3.1')
    print(f'Found {len(functions_174)} functions in 17.4')
    
    # Find functions that are udf/ret stubs in 17.3.1 but have cmp+bcond in 17.4
    candidates = []
    
    for fo_1731 in functions_1731:
        # Check if 17.3.1 function is a udf/ret stub
        is_udf_stub = False
        udf_count = 0
        ret_count = 0
        for j in range(20):
            if fo_1731 + j*4 >= end_fo:
                break
            w = struct.unpack('<I', data1[fo_1731 + j*4:fo_1731 + j*4 + 4])[0]
            if (w & 0x0000FFFF) == 0:
                udf_count += 1
            if w == 0xD65F03C0:
                ret_count += 1
        
        if udf_count >= 3 and ret_count >= 3:
            is_udf_stub = True
        
        if not is_udf_stub:
            continue
        
        # Find corresponding function in 17.4
        for fo_174 in functions_174:
            if abs(fo_1731 - fo_174) < 0x1000:
                # Check if 17.4 function has cmp+bcond
                has_cmp = False
                has_bcond = False
                has_bl = False
                for j in range(100):
                    if fo_174 + j*4 >= end_fo:
                        break
                    w = struct.unpack('<I', data2[fo_174 + j*4:fo_174 + j*4 + 4])[0]
                    if (w & 0xFF80001F) == 0x7100001F:
                        has_cmp = True
                    if (w & 0xFF000010) == 0x54000000:
                        has_bcond = True
                    if (w & 0xFC000000) == 0x94000000:
                        has_bl = True
                
                if has_cmp and has_bcond:
                    vm_1731 = 0xfffffff007d4c000 + (fo_1731 - 0xd48000)
                    vm_174 = 0xfffffff007d4c000 + (fo_174 - 0xd48000)
                    candidates.append({
                        'fo_1731': fo_1731,
                        'fo_174': fo_174,
                        'vm_1731': vm_1731,
                        'vm_174': vm_174,
                        'udf_count': udf_count,
                        'ret_count': ret_count,
                        'has_cmp': has_cmp,
                        'has_bcond': has_bcond,
                        'has_bl': has_bl,
                    })
                break
    
    print(f'\nFound {len(candidates)} udf-stub -> validator transformations')
    
    # Show top candidates
    for idx, cand in enumerate(candidates[:10]):
        print(f'\n{"="*80}')
        print(f'Candidate {idx+1}: VM 0x{cand["vm_1731"]:x} (17.3.1) -> 0x{cand["vm_174"]:x} (17.4)')
        print(f'  17.3.1: udf={cand["udf_count"]}, ret={cand["ret_count"]}')
        print(f'  17.4: cmp={cand["has_cmp"]}, bcond={cand["has_bcond"]}, bl={cand["has_bl"]}')
        
        # Disassemble both
        print(f'\n17.3.1 (first 30 instructions):')
        for j in range(30):
            w = struct.unpack('<I', data1[cand['fo_1731'] + j*4:cand['fo_1731'] + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (cand['fo_1731'] + j*4 - 0xd48000)
            disasm = disasm_instruction(w)
            print(f'  0x{vm:x}: {disasm}')
        
        print(f'\n17.4 (first 60 instructions):')
        for j in range(60):
            w = struct.unpack('<I', data2[cand['fo_174'] + j*4:cand['fo_174'] + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (cand['fo_174'] + j*4 - 0xd48000)
            disasm = disasm_instruction(w)
            print(f'  0x{vm:x}: {disasm}')

if __name__ == '__main__':
    find_udf_to_validator()
