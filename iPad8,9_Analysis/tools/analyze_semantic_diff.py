import struct
import json
from pathlib import Path

KERNEL_1731 = Path(__file__).parents[1] / '21D61' / 'kernelcache.decompressed'
KERNEL_174 = Path(__file__).parents[1] / '21E219' / 'kernelcache.decompressed'
OUTPUT_DIR = Path(__file__).parents[1]

def is_adr_only_change(data1, data2, start, end):
    """Check if the diff region is only ADR relocation changes"""
    adr_only = True
    has_semantic_change = False
    
    for i in range(start, end, 4):
        if i + 4 > len(data1) or i + 4 > len(data2):
            break
        
        w1 = struct.unpack('<I', data1[i:i+4])[0]
        w2 = struct.unpack('<I', data2[i:i+4])[0]
        
        if w1 != w2:
            # Check if both are ADR instructions
            is_adr1 = (w1 & 0x9F000000) == 0x10000000
            is_adr2 = (w2 & 0x9F000000) == 0x10000000
            is_adrp1 = (w1 & 0x9F000000) == 0x90000000
            is_adrp2 = (w2 & 0x9F000000) == 0x90000000
            
            if (is_adr1 and is_adr2) or (is_adrp1 and is_adrp2):
                # Both are ADR/ADRP - this is a relocation
                continue
            else:
                # Not ADR - semantic change
                adr_only = False
                has_semantic_change = True
                break
    
    return not has_semantic_change

def analyze_semantic_changes(data1, data2, diff_regions):
    """Analyze diff regions for semantic changes only"""
    semantic_regions = []
    
    for start, end in diff_regions:
        if is_adr_only_change(data1, data2, start, end):
            continue
        
        # This region has semantic changes
        info = {
            'start': start,
            'end': end,
            'size': end - start,
            'vm_start': 0xfffffff007d50000 + (start - 0x1bf000),
            'vm_end': 0xfffffff007d50000 + (end - 0x1bf000),
            'instructions_a': [],
            'instructions_b': [],
            'has_pacibsp': False,
            'has_udf': False,
            'has_bl': False,
            'has_ret': False,
            'has_cbz_cbnz': False,
            'has_cmp': False,
            'has_mov': False,
        }
        
        for i in range(start, min(end, start + 200), 4):
            if i + 4 > len(data1) or i + 4 > len(data2):
                break
            
            w1 = struct.unpack('<I', data1[i:i+4])[0]
            w2 = struct.unpack('<I', data2[i:i+4])[0]
            
            info['instructions_a'].append({'offset': i, 'instr': f'0x{w1:08x}'})
            info['instructions_b'].append({'offset': i, 'instr': f'0x{w2:08x}'})
            
            # Check for specific patterns
            if w1 == 0xD503237F or w2 == 0xD503237F:
                info['has_pacibsp'] = True
            if (w1 & 0x0000FFFF) == 0 or (w2 & 0x0000FFFF) == 0:
                if w1 == 0 or w2 == 0:
                    info['has_udf'] = True
            if (w1 & 0xFC000000) == 0x94000000 or (w2 & 0xFC000000) == 0x94000000:
                info['has_bl'] = True
            if w1 == 0xD65F03C0 or w2 == 0xD65F03C0:
                info['has_ret'] = True
            if (w1 & 0xFF000010) == 0x54000000 or (w2 & 0xFF000010) == 0x54000000:
                info['has_cbz_cbnz'] = True
            if (w1 & 0xFF80001F) == 0x7100001F or (w2 & 0xFF80001F) == 0x7100001F:
                info['has_cmp'] = True
            if (w1 & 0x1F800000) == 0x52800000 or (w2 & 0x1F800000) == 0x52800000:
                info['has_mov'] = True
        
        semantic_regions.append(info)
    
    return semantic_regions

def main():
    print('Loading kernelcache files...')
    data1 = KERNEL_1731.read_bytes()
    data2 = KERNEL_174.read_bytes()
    
    # Load diff regions from previous report
    report_path = OUTPUT_DIR / 'full_binary_diff_report.json'
    if not report_path.exists():
        print('ERROR: full_binary_diff_report.json not found. Run full_binary_diff.py first.')
        return
    
    print('Loading diff report...')
    with report_path.open('r') as f:
        report = json.load(f)
    
    # Reconstruct diff regions from the report
    # We need to re-run the diff since the report doesn't store all regions
    print('Re-finding diff regions in __TEXT_EXEC...')
    
    start_fo = 0x1bf000
    end_fo = 0x90f5d4
    
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
    
    print(f'Found {len(diff_regions)} diff regions')
    
    # Filter for semantic changes only
    print('Filtering for semantic changes (excluding ADR-only)...')
    semantic_regions = analyze_semantic_changes(data1, data2, diff_regions)
    
    print(f'Found {len(semantic_regions)} regions with semantic changes')
    
    # Sort by size
    semantic_regions.sort(key=lambda x: x['size'], reverse=True)
    
    # Generate report
    output_json = OUTPUT_DIR / 'semantic_diff_report.json'
    with output_json.open('w', encoding='utf-8') as f:
        json.dump(semantic_regions[:100], f, indent=2, default=str)
    
    print(f'\nReport written to: {output_json}')
    
    # Print summary
    print('\n=== Top 50 Semantic Diff Regions ===')
    for i, region in enumerate(semantic_regions[:50]):
        print(f'{i+1}. VM 0x{region["vm_start"]:x}-0x{region["vm_end"]:x} (size: {region["size"]} bytes)')
        flags = []
        if region['has_pacibsp']: flags.append('pacibsp')
        if region['has_udf']: flags.append('udf')
        if region['has_bl']: flags.append('bl')
        if region['has_ret']: flags.append('ret')
        if region['has_cbz_cbnz']: flags.append('cbz/cbnz')
        if region['has_cmp']: flags.append('cmp')
        if region['has_mov']: flags.append('mov')
        print(f'   flags: {", ".join(flags) if flags else "none"}')

if __name__ == '__main__':
    main()
