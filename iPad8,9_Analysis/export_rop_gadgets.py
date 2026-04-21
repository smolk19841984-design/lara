#!/usr/bin/env python3
"""Export ROP gadgets that move into x0/x1/x2 immediately before an epilog
and perform a basic controllability check (ADRP / stack sources).

Writes: pmap_rop_gadgets_x0_x1_x2.json
"""
import os
import re
import json
import sys


line_re = re.compile(r'^\s*(0x[0-9a-fA-F]+):\s*(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s*)?\s*(.*\S.*)$')
mov_re = re.compile(r'\bmov\s+(x\d+),\s*(x\d+)\b', re.IGNORECASE)
ldp_epilog_re = re.compile(r'\bldp\s+x29,\s*x30\b', re.IGNORECASE)
adrp_re = re.compile(r'\badrp\b', re.IGNORECASE)
ldr_sp_re = re.compile(r'\bldr\s+(x\d+),\s*\[sp\b', re.IGNORECASE)
ldp_sp_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[sp\b', re.IGNORECASE)
ldp_sp_postinc_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[sp\],', re.IGNORECASE)


def find_disasm_files(search_dir):
    for root, dirs, files in os.walk(search_dir):
        for fn in files:
            if fn.lower().endswith('.txt'):
                yield os.path.join(root, fn)


def parse_file(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = f.readlines()
    except Exception as e:
        print(f'Failed to read {path}: {e}', file=sys.stderr)
        return []
    items = []
    for i, raw in enumerate(raw_lines):
        m = line_re.match(raw)
        if m:
            addr = m.group(1)
            instr = m.group(2).strip()
        else:
            addr = None
            instr = raw.strip()
        items.append({'addr': addr, 'instr': instr, 'raw': raw.rstrip('\n'), 'line_no': i+1})
    return items


def analyze_items(items, filename):
    gadgets = []
    for i, it in enumerate(items):
        instr = it['instr']
        if not instr:
            continue
        mov_m = mov_re.search(instr)
        if not mov_m:
            continue
        dest = mov_m.group(1)
        src = mov_m.group(2)
        if dest not in ('x0', 'x1', 'x2'):
            continue
        # search forward for epilog ldp x29,x30 within next ~12 instructions
        epilog_idx = None
        for j in range(i+1, min(len(items), i+13)):
            if ldp_epilog_re.search(items[j]['instr']):
                epilog_idx = j
                break
        if epilog_idx is None:
            continue
        # basic controllability: was src loaded from stack shortly before?
        from_stack = False
        reg_loaded_line = None
        for k in range(max(0, i-12), i):
            s = items[k]['instr']
            if not s:
                continue
            a = ldp_sp_re.search(s)
            if a:
                r1 = a.group(1); r2 = a.group(2)
                if src in (r1, r2):
                    from_stack = True
                    reg_loaded_line = items[k]
                    break
            b = ldr_sp_re.search(s)
            if b and b.group(1) == src:
                from_stack = True
                reg_loaded_line = items[k]
                break
            c = ldp_sp_postinc_re.search(s)
            if c:
                r1 = c.group(1); r2 = c.group(2)
                if src in (r1, r2):
                    from_stack = True
                    reg_loaded_line = items[k]
                    break
        # check for adrp near before mov
        adrp_present = False
        for k in range(max(0, i-16), i):
            if adrp_re.search(items[k]['instr']):
                adrp_present = True
                break
        start = max(0, i-6)
        end = min(len(items), epilog_idx+6)
        context = [items[x]['raw'] for x in range(start, end)]
        gadgets.append({
            'file': os.path.relpath(filename).replace('\\','/'),
            'mov_addr': it['addr'],
            'mov_instr': it['instr'],
            'epilog_addr': items[epilog_idx]['addr'],
            'epilog_instr': items[epilog_idx]['instr'],
            'target_reg': dest,
            'source_reg': src,
            'from_stack': bool(from_stack),
            'reg_loaded_line': reg_loaded_line['raw'] if reg_loaded_line else None,
            'adrp_before': bool(adrp_present),
            'context': context,
            'mov_line_no': it['line_no'],
            'epilog_line_no': items[epilog_idx]['line_no'],
        })
    return gadgets


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_dir = script_dir
    out_path = os.path.join(script_dir, 'pmap_rop_gadgets_x0_x1_x2.json')
    all_gadgets = []
    for fpath in find_disasm_files(search_dir):
        if os.path.abspath(fpath) == os.path.abspath(out_path):
            continue
        items = parse_file(fpath)
        if not items:
            continue
        g = analyze_items(items, fpath)
        if g:
            all_gadgets.extend(g)
    # dedupe
    seen = set()
    uniq = []
    for gad in all_gadgets:
        key = (gad['file'], gad['mov_addr'], gad['epilog_addr'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(gad)
    try:
        with open(out_path, 'w', encoding='utf-8') as of:
            json.dump({'count': len(uniq), 'gadgets': uniq}, of, ensure_ascii=False, indent=2)
    except Exception as e:
        print('Failed to write output:', e, file=sys.stderr)
        sys.exit(2)
    print(f'Wrote {len(uniq)} gadget(s) to {out_path}')


if __name__ == '__main__':
    main()
