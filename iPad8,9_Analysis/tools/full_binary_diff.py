import struct
import json
from pathlib import Path

# Paths
KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

# ARM64 instruction decoder helpers
def decode_adrp(instr):
    """Decode ADRP instruction"""
    if (instr & 0x9F000000) != 0x90000000:
        return None
    rd = instr & 0x1F
    immlo = (instr >> 29) & 0x3
    immhi = (instr >> 5) & 0x7FFFF
    imm = ((immhi << 2) | immlo) << 12
    return ('ADRP', rd, imm)

def decode_add_imm(instr):
    """Decode ADD (immediate) instruction"""
    if (instr & 0xFF8003FF) != 0x91000000:
        return None
    rd = instr & 0x1F
    rn = (instr >> 5) & 0x1F
    imm12 = (instr >> 10) & 0xFFF
    shift = (instr >> 22) & 0x3
    imm = imm12 << (shift * 12)
    return ('ADD', rd, rn, imm)

def decode_adr(instr):
    """Decode ADR instruction"""
    if (instr & 0x9F000000) != 0x10000000:
        return None
    rd = instr & 0x1F
    immlo = (instr >> 29) & 0x3
    immhi = (instr >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    return ('ADR', rd, imm)

def decode_bl(instr):
    """Decode BL instruction"""
    if (instr & 0xFC000000) != 0x94000000:
        return None
    imm = instr & 0x03FFFFFF
    if imm & 0x02000000:
        imm = imm | 0xFC000000
    return ('BL', imm << 2)

def decode_b_cond(instr):
    """Decode B.cond instruction"""
    if (instr & 0xFF000010) != 0x54000000:
        return None
    cond = instr & 0xF
    imm = (instr >> 5) & 0x7FFFF
    if imm & 0x40000:
        imm = imm | 0xFFFC0000
    return ('B.cond', cond, imm << 2)

def decode_cbz_w(instr):
    """Decode CBZ/CBNZ W instruction"""
    if (instr & 0x7F000000) != 0x34000000:
        return None
    is_cbnz = (instr >> 24) & 1
    imm = (instr >> 5) & 0x7FFFF
    if imm & 0x40000:
        imm = imm | 0xFFFC0000
    return ('CBNZ' if is_cbnz else 'CBZ', imm << 2)

def decode_cmp_w(instr):
    """Decode CMP (immediate) W instruction"""
    if (instr & 0xFF80001F) != 0x7100001F:
        return None
    rn = (instr >> 5) & 0x1F
    imm12 = (instr >> 10) & 0xFFF
    return ('CMP', rn, imm12)

def decode_mov_wide_w(instr):
    """Decode MOVZ/MOVN/MOVK W instruction"""
    if (instr & 0x1F800000) != 0x52800000:
        return None
    op = (instr >> 29) & 0x3
    rd = instr & 0x1F
    imm16 = (instr >> 5) & 0xFFFF
    hw = (instr >> 21) & 0x3
    if op == 0:
        return ('MOVZ', rd, imm16, hw)
    elif op == 1:
        return ('MOVK', rd, imm16, hw)
    elif op == 2:
        return ('MOVN', rd, imm16, hw)
    return None

def disasm_single(instr):
    """Try to decode a single instruction"""
    for decoder in [decode_adrp, decode_adr, decode_add_imm, decode_bl, decode_b_cond, decode_cbz_w, decode_cmp_w, decode_mov_wide_w]:
        result = decoder(instr)
        if result:
            return result
    return None

def find_diff_regions(data1, data2):
    """Find regions where two binaries differ"""
    min_len = min(len(data1), len(data2))
    diff_regions = []
    in_diff = False
    diff_start = 0
    
    for i in range(0, min_len, 4):
        w1 = struct.unpack('<I', data1[i:i+4])[0]
        w2 = struct.unpack('<I', data2[i:i+4])[0]
        
        if w1 != w2:
            if not in_diff:
                diff_start = i
                in_diff = True
        else:
            if in_diff:
                diff_regions.append((diff_start, i))
                in_diff = False
    
    if in_diff:
        diff_regions.append((diff_start, min_len))
    
    return diff_regions

def analyze_diff_region(data1, data2, start, end):
    """Analyze a diff region and return detailed info"""
    info = {
        'start': start,
        'end': end,
        'size': end - start,
        'instructions_a': [],
        'instructions_b': [],
        'has_xprr_ref': False,
        'has_expected_perm_ref': False,
        'has_pacibsp': False,
        'has_udf': False,
        'has_bl': False,
        'has_adrp_add': False,
        'has_adr': False,
    }
    
    # XPRR string VMs (from 17.3.1)
    xprr_strings = [0xfffffff007050dda, 0xfffffff007050d9b, 0xfffffff007050f8d, 0xfffffff007051055]
    
    for i in range(start, end, 4):
        if i + 4 > len(data1) or i + 4 > len(data2):
            break
            
        instr_a = struct.unpack('<I', data1[i:i+4])[0]
        instr_b = struct.unpack('<I', data2[i:i+4])[0]
        
        info['instructions_a'].append({'offset': i, 'instr': instr_a})
        info['instructions_b'].append({'offset': i, 'instr': instr_b})
        
        # Check for specific patterns
        decoded_a = disasm_single(instr_a)
        decoded_b = disasm_single(instr_b)
        
        if decoded_a:
            if decoded_a[0] == 'ADRP':
                # Check if next instruction is ADD
                if i + 4 < end:
                    next_instr = struct.unpack('<I', data1[i+4:i+8])[0]
                    add_decoded = decode_add_imm(next_instr)
                    if add_decoded and add_decoded[2] == decoded_a[1]:
                        info['has_adrp_add'] = True
            elif decoded_a[0] == 'ADR':
                info['has_adr'] = True
            elif decoded_a[0] == 'BL':
                info['has_bl'] = True
        
        # Check for PAC/UDF
        if instr_a == 0xD503237F or instr_b == 0xD503237F:  # pacibsp
            info['has_pacibsp'] = True
        if (instr_a & 0x0000FFFF) == 0x0000 or (instr_b & 0x0000FFFF) == 0x0000:  # udf
            if instr_a == 0x00000000 or instr_b == 0x00000000:
                info['has_udf'] = True
    
    return info

def main():
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    print(f'17.3.1 size: {len(data1)} bytes (0x{len(data1):x})')
    print(f'17.4 size:   {len(data2)} bytes (0x{len(data2):x})')
    
    # Use known offsets from ipsw analysis
    # 17.3.1: __TEXT_EXEC.__text at fileoff=0x1bf000, size=0x7505d4, vmaddr=0xfffffff007d50000
    # 17.4: similar structure
    
    # Find __TEXT_EXEC.__text in both kernelcaches by searching for the segment
    def find_text_exec_in_kernelcache(data):
        """Find __TEXT_EXEC.__text segment in prelinked kernelcache"""
        # Search for the string "__TEXT_EXEC" in load commands
        for i in range(len(data) - 0x48):
            if data[i:i+11] == b'__TEXT_EXEC':
                # This is likely a segment name
                # Check if it's followed by __text
                if i + 24 < len(data) and b'__text' in data[i:i+32]:
                    # Parse segment info
                    # The segment name starts at offset i-8 from the command start
                    cmd_start = i - 8
                    if cmd_start < 0:
                        continue
                    vmaddr = struct.unpack('<Q', data[cmd_start+48:cmd_start+56])[0]
                    fileoff = struct.unpack('<Q', data[cmd_start+64:cmd_start+72])[0]
                    filesize = struct.unpack('<Q', data[cmd_start+72:cmd_start+80])[0]
                    if 0xfffffff000000000 <= vmaddr <= 0xffffffffffffffff and filesize < 0x10000000:
                        return {'vmaddr': vmaddr, 'fileoff': fileoff, 'filesize': filesize}
        return None
    
    seg1 = find_text_exec_in_kernelcache(data1)
    seg2 = find_text_exec_in_kernelcache(data2)
    
    if seg1:
        print(f'17.3.1 __TEXT_EXEC.__text: vmaddr=0x{seg1["vmaddr"]:x} fileoff=0x{seg1["fileoff"]:x} filesize=0x{seg1["filesize"]:x}')
    if seg2:
        print(f'17.4 __TEXT_EXEC.__text:   vmaddr=0x{seg2["vmaddr"]:x} fileoff=0x{seg2["fileoff"]:x} filesize=0x{seg2["filesize"]:x}')
    
    # Use known offsets if parsing fails
    if not seg1:
        seg1 = {'vmaddr': 0xfffffff007d50000, 'fileoff': 0x1bf000, 'filesize': 0x7505d4}
        print(f'Using known 17.3.1 __TEXT_EXEC.__text: vmaddr=0x{seg1["vmaddr"]:x} fileoff=0x{seg1["fileoff"]:x} filesize=0x{seg1["filesize"]:x}')
    if not seg2:
        seg2 = {'vmaddr': 0xfffffff007d50000, 'fileoff': 0x1bf000, 'filesize': 0x7505d4}
        print(f'Using known 17.4 __TEXT_EXEC.__text: vmaddr=0x{seg2["vmaddr"]:x} fileoff=0x{seg2["fileoff"]:x} filesize=0x{seg2["filesize"]:x}')
    
    # Find diff regions only in __TEXT_EXEC
    start_fo = max(seg1['fileoff'], seg2['fileoff'])
    end_fo = min(seg1['fileoff'] + seg1['filesize'], seg2['fileoff'] + seg2['filesize'])
    
    print(f'\nComparing __TEXT_EXEC from 0x{start_fo:x} to 0x{end_fo:x}...')
    
    # Find diff regions in __TEXT_EXEC only
    diff_regions = []
    in_diff = False
    diff_start = 0
    
    for i in range(start_fo, end_fo, 4):
        w1 = struct.unpack('<I', data1[i:i+4])[0]
        w2 = struct.unpack('<I', data2[i:i+4])[0]
        
        if w1 != w2:
            if not in_diff:
                diff_start = i
                in_diff = True
        else:
            if in_diff:
                diff_regions.append((diff_start, i))
                in_diff = False
    
    if in_diff:
        diff_regions.append((diff_start, end_fo))
    
    print(f'Found {len(diff_regions)} diff regions in __TEXT_EXEC')
    
    # Filter regions by size (skip very small ones)
    significant_regions = [(s, e) for s, e in diff_regions if e - s >= 16]
    print(f'Significant regions (>=16 bytes): {len(significant_regions)}')
    
    # Analyze all significant regions
    print('\nAnalyzing diff regions...')
    analyzed = []
    for start, end in significant_regions:
        info = analyze_diff_region(data1, data2, start, end)
        analyzed.append(info)
    
    # Filter regions with interesting patterns
    interesting = [r for r in analyzed if r['has_pacibsp'] or r['has_udf'] or r['has_bl'] or r['has_adrp_add'] or r['has_adr']]
    print(f'Interesting regions (with pacibsp/udf/bl/adrp+add/adr): {len(interesting)}')
    
    # Sort by size
    interesting.sort(key=lambda x: x['size'], reverse=True)
    
    # Generate report
    report = {
        'total_diff_regions': len(diff_regions),
        'significant_regions': len(significant_regions),
        'interesting_regions': len(interesting),
        'top_regions': interesting[:100],
    }
    
    # Write report
    output_json = OUTPUT_DIR / 'full_binary_diff_report.json'
    with output_json.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f'\nReport written to: {output_json}')
    
    # Print summary
    print('\n=== Top 30 Interesting Diff Regions ===')
    for i, region in enumerate(interesting[:30]):
        print(f'{i+1}. offset 0x{region["start"]:x}-0x{region["end"]:x} (size: {region["size"]} bytes)')
        print(f'   pacibsp: {region["has_pacibsp"]}, udf: {region["has_udf"]}, bl: {region["has_bl"]}')
        print(f'   adrp+add: {region["has_adrp_add"]}, adr: {region["has_adr"]}')

if __name__ == '__main__':
    main()
