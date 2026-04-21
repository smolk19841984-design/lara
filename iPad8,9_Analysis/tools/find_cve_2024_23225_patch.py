import struct
from pathlib import Path

KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

def find_cve_patch():
    """Find CVE-2024-23225 patch by looking for expected_perm validation"""
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    # __TEXT_EXEC.__text range in raw kernelcache
    # From ipsw: __TEXT_EXEC at fileoff=0xd48000, size=0x22bc000
    start_fo = 0xd48000
    end_fo = 0xd48000 + 0x22bc000
    
    # Strategy 1: Find functions that changed between 17.3.1 and 17.4
    # and have both:
    # - BL instructions (function calls)
    # - CMP instructions (validation checks)
    # - Conditional branches (B.cond)
    
    print('Searching for functions with validation changes...')
    
    # Find all function boundaries by looking for prologues
    functions_1731 = []
    functions_174 = []
    
    for i in range(start_fo, end_fo - 4, 4):
        # stp x29, x30, [sp, #-0x10]!
        w1 = struct.unpack('<I', data1[i:i+4])[0]
        w2 = struct.unpack('<I', data2[i:i+4])[0]
        
        if w1 == 0xA9BF7BFD:
            functions_1731.append(i)
        if w2 == 0xA9BF7BFD:
            functions_174.append(i)
    
    print(f'Found {len(functions_1731)} functions in 17.3.1')
    print(f'Found {len(functions_174)} functions in 17.4')
    
    # Find functions that exist in both but have different code
    changed_functions = []
    
    for fo_1731 in functions_1731:
        # Find corresponding function in 17.4 (same offset or nearby)
        # Functions may have moved, so search within a range
        for fo_174 in functions_174:
            if abs(fo_1731 - fo_174) < 0x1000:  # Within 4KB
                # Compare first 100 instructions
                same = True
                for j in range(100):
                    if fo_1731 + j*4 >= end_fo or fo_174 + j*4 >= end_fo:
                        break
                    w1 = struct.unpack('<I', data1[fo_1731 + j*4:fo_1731 + j*4 + 4])[0]
                    w2 = struct.unpack('<I', data2[fo_174 + j*4:fo_174 + j*4 + 4])[0]
                    if w1 != w2:
                        same = False
                        break
                
                if not same:
                    changed_functions.append((fo_1731, fo_174))
                break
    
    print(f'Found {len(changed_functions)} changed functions')
    
    # Analyze changed functions for CVE-2024-23225 patterns
    cve_candidates = []
    
    for fo_1731, fo_174 in changed_functions[:500]:  # Analyze first 500
        # Check if function has:
        # 1. CMP instructions (validation)
        # 2. Conditional branches
        # 3. BL to panic or validation functions
        
        has_cmp_1731 = False
        has_cmp_174 = False
        has_bcond_1731 = False
        has_bcond_174 = False
        has_bl_1731 = False
        has_bl_174 = False
        
        for j in range(200):  # Check first 200 instructions
            if fo_1731 + j*4 >= end_fo or fo_174 + j*4 >= end_fo:
                break
            
            w1 = struct.unpack('<I', data1[fo_1731 + j*4:fo_1731 + j*4 + 4])[0]
            w2 = struct.unpack('<I', data2[fo_174 + j*4:fo_174 + j*4 + 4])[0]
            
            # CMP W
            if (w1 & 0xFF80001F) == 0x7100001F:
                has_cmp_1731 = True
            if (w2 & 0xFF80001F) == 0x7100001F:
                has_cmp_174 = True
            
            # B.cond
            if (w1 & 0xFF000010) == 0x54000000:
                has_bcond_1731 = True
            if (w2 & 0xFF000010) == 0x54000000:
                has_bcond_174 = True
            
            # BL
            if (w1 & 0xFC000000) == 0x94000000:
                has_bl_1731 = True
            if (w2 & 0xFC000000) == 0x94000000:
                has_bl_174 = True
        
        # CVE-2024-23225 adds expected_perm validation
        # Look for functions that have MORE cmp/bcond in 17.4 than 17.3.1
        vm_1731 = 0xfffffff007d4c000 + (fo_1731 - 0xd48000)
        vm_174 = 0xfffffff007d4c000 + (fo_174 - 0xd48000)
        
        cve_candidates.append({
            'fo_1731': fo_1731,
            'fo_174': fo_174,
            'vm_1731': vm_1731,
            'vm_174': vm_174,
            'has_cmp_1731': has_cmp_1731,
            'has_cmp_174': has_cmp_174,
            'has_bcond_1731': has_bcond_1731,
            'has_bcond_174': has_bcond_174,
            'has_bl_1731': has_bl_1731,
            'has_bl_174': has_bl_174,
        })
    
    # Sort by functions that have more validation in 17.4
    cve_candidates.sort(key=lambda x: (
        x['has_cmp_174'] and not x['has_cmp_1731'],  # New cmp in 17.4
        x['has_bcond_174'] and not x['has_bcond_1731'],  # New bcond in 17.4
    ), reverse=True)
    
    print('\n=== Top 30 CVE-2024-23225 Candidate Functions ===')
    for i, cand in enumerate(cve_candidates[:30]):
        print(f'{i+1}. VM 17.3.1: 0x{cand["vm_1731"]:x}, VM 17.4: 0x{cand["vm_174"]:x}')
        print(f'   17.3.1: cmp={cand["has_cmp_1731"]}, bcond={cand["has_bcond_1731"]}, bl={cand["has_bl_1731"]}')
        print(f'   17.4:   cmp={cand["has_cmp_174"]}, bcond={cand["has_bcond_174"]}, bl={cand["has_bl_174"]}')
    
    # Save top candidates for further analysis
    print('\nSaving top candidates for detailed analysis...')
    
    # Disassemble top 5 candidates
    for cand in cve_candidates[:5]:
        fo_1731 = cand['fo_1731']
        fo_174 = cand['fo_174']
        
        print(f'\n=== Function at VM 0x{cand["vm_1731"]:x} (17.3.1) vs 0x{cand["vm_174"]:x} (17.4) ===')
        
        print('17.3.1:')
        for j in range(40):
            if fo_1731 + j*4 >= end_fo:
                break
            w = struct.unpack('<I', data1[fo_1731 + j*4:fo_1731 + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (fo_1731 + j*4 - 0xd48000)
            print(f'  0x{vm:x}: 0x{w:08x}')
        
        print('17.4:')
        for j in range(40):
            if fo_174 + j*4 >= end_fo:
                break
            w = struct.unpack('<I', data2[fo_174 + j*4:fo_174 + j*4 + 4])[0]
            vm = 0xfffffff007d4c000 + (fo_174 + j*4 - 0xd48000)
            print(f'  0x{vm:x}: 0x{w:08x}')

if __name__ == '__main__':
    find_cve_patch()
