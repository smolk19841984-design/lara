#!/usr/bin/env python3
"""Deep controllability check for exported ROP gadgets.

Loads `pmap_rop_gadgets_x0_x1_x2.json`, parses disassembly files and
attempts to trace the origin of each gadget's source register:
- stack loads (ldr/ldp [sp,...])
- ADRP+ADD+LDR sequences (likely kernel/static memory)
- immediate/constant constructions (mov/movk/movz)

Writes: `pmap_rop_gadgets_x0_x1_x2_deep.json` with traces and a summary.
"""
import os
import re
import json
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
IN_JSON = os.path.join(HERE, 'pmap_rop_gadgets_x0_x1_x2.json')
OUT_JSON = os.path.join(HERE, 'pmap_rop_gadgets_x0_x1_x2_deep.json')

line_re = re.compile(r'^\s*(0x[0-9a-fA-F]+):\s*(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s*)?\s*(.*\S.*)$')
mov_reg_re = re.compile(r'\bmov\s+(x\d+),\s*(x\d+)\b', re.IGNORECASE)
mov_imm_re = re.compile(r'\bmov(?:w|z|k)?\s+(x\d+|w\d+),\s*#', re.IGNORECASE)
ldr_sp_re = re.compile(r'\bldr\s+(x\d+),\s*\[sp', re.IGNORECASE)
ldp_sp_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[sp', re.IGNORECASE)
ldp_sp_postinc_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[sp\],', re.IGNORECASE)
ldp_reg_re = re.compile(r'\bldp\s+(x\d+),\s*(x\d+),\s*\[(x\d+)(?:,\s*#0x[0-9a-fA-F]+)?\]', re.IGNORECASE)
ldr_reg_re = re.compile(r'\bldr\s+(x\d+),\s*\[(x\d+)(?:,\s*#0x[0-9a-fA-F]+)?\]', re.IGNORECASE)
adrp_re = re.compile(r'\badrp\s+(x\d+),', re.IGNORECASE)
add_re = re.compile(r'\badd(?:s)?\s+(x\d+),\s*(x\d+),\s*#', re.IGNORECASE)
movk_re = re.compile(r'\bmovk\b', re.IGNORECASE)
movz_re = re.compile(r'\bmovz\b', re.IGNORECASE)


def parse_file(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_lines = f.readlines()
    except Exception:
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


def find_adrp_for_reg(items, start_idx, reg, lookback=120):
    # search backwards for 'adrp reg,' within lookback
    for k in range(start_idx-1, max(-1, start_idx-1-lookback), -1):
        s = items[k]['instr']
        if not s:
            continue
        m = adrp_re.search(s)
        if m and m.group(1) == reg:
            return {'idx': k, 'addr': items[k]['addr'], 'raw': items[k]['raw'], 'line_no': items[k]['line_no']}
    return None


def deep_trace(items, mov_idx, source_reg):
    cur = source_reg
    trace = []
    max_back = 300
    for idx in range(mov_idx-1, max(-1, mov_idx-1-max_back), -1):
        s = items[idx]['instr']
        if not s:
            continue
        a = items[idx]['addr']
        raw = items[idx]['raw']
        # stack ldp/ldr
        m_ldp_sp = ldp_sp_re.search(s)
        if m_ldp_sp and cur in (m_ldp_sp.group(1), m_ldp_sp.group(2)):
            trace.append({'kind': 'ldp_sp', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw})
            return {'method': 'stack', 'trace': trace}
        m_ldr_sp = ldr_sp_re.search(s)
        if m_ldr_sp and m_ldr_sp.group(1) == cur:
            trace.append({'kind': 'ldr_sp', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw})
            return {'method': 'stack', 'trace': trace}
        # loads from register base
        m_ldp_reg = ldp_reg_re.search(s)
        if m_ldp_reg and cur in (m_ldp_reg.group(1), m_ldp_reg.group(2)):
            base = m_ldp_reg.group(3)
            trace.append({'kind': 'ldp_reg', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw, 'base': base})
            adrp = find_adrp_for_reg(items, idx, base)
            if adrp:
                trace.append({'kind': 'adrp_def', 'addr': adrp['addr'], 'line': adrp['line_no'], 'raw': adrp['raw']})
                return {'method': 'adrp+ldp', 'trace': trace}
            # follow base register
            trace.append({'kind': 'follow_base', 'base': base})
            cur = base
            continue
        m_ldr_reg = ldr_reg_re.search(s)
        if m_ldr_reg and m_ldr_reg.group(1) == cur:
            base = m_ldr_reg.group(2)
            trace.append({'kind': 'ldr_reg', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw, 'base': base})
            adrp = find_adrp_for_reg(items, idx, base)
            if adrp:
                trace.append({'kind': 'adrp_def', 'addr': adrp['addr'], 'line': adrp['line_no'], 'raw': adrp['raw']})
                return {'method': 'adrp+ldr', 'trace': trace}
            cur = base
            continue
        # mov reg, reg -> follow chain
        m_mov_reg = mov_reg_re.search(s)
        if m_mov_reg and m_mov_reg.group(1) == cur:
            new = m_mov_reg.group(2)
            trace.append({'kind': 'mov', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw, 'new_src': new})
            cur = new
            continue
        # immediate constant / movk/movz
        m_mov_imm = mov_imm_re.search(s)
        if m_mov_imm and m_mov_imm.group(1) == cur:
            trace.append({'kind': 'mov_imm', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw})
            return {'method': 'constant', 'trace': trace}
        if (movk_re.search(s) or movz_re.search(s)) and re.search(r'\b' + re.escape(cur) + r'\b', s):
            trace.append({'kind': 'movk/movz', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw})
            return {'method': 'constant', 'trace': trace}
        # adrp directly to reg
        m_adrp = adrp_re.search(s)
        if m_adrp and m_adrp.group(1) == cur:
            trace.append({'kind': 'adrp_def', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw})
            return {'method': 'adrp', 'trace': trace}
        # if we see an add to the same reg, record it (used with adrp)
        m_add = add_re.search(s)
        if m_add and m_add.group(1) == cur:
            trace.append({'kind': 'add_def', 'addr': a, 'line': items[idx]['line_no'], 'raw': raw, 'base': m_add.group(2)})
            # continue searching for base definition
            continue
    return {'method': 'unknown', 'trace': trace}


def main():
    if not os.path.exists(IN_JSON):
        print('Input JSON not found:', IN_JSON, file=sys.stderr)
        sys.exit(1)
    try:
        with open(IN_JSON, 'r', encoding='utf-8') as f:
            base = json.load(f)
    except Exception as e:
        print('Failed to load input:', e, file=sys.stderr)
        sys.exit(2)

    gadgets = base.get('gadgets', [])
    results = []
    counts = {'stack': 0, 'adrp': 0, 'adrp+ldp': 0, 'constant': 0, 'unknown': 0, 'other': 0}
    # cache parsed files
    parsed_cache = {}
    for gad in gadgets:
        fn = os.path.join(HERE, gad['file']) if not os.path.isabs(gad['file']) else gad['file']
        if not os.path.exists(fn):
            # try relative path
            fn = os.path.join(HERE, gad['file'])
        if fn not in parsed_cache:
            parsed_cache[fn] = parse_file(fn)
        items = parsed_cache[fn]
        if not items:
            res = {'method': 'no_disasm', 'trace': []}
        else:
            mov_idx = gad.get('mov_line_no', None)
            if not mov_idx:
                res = {'method': 'no_mov_line', 'trace': []}
            else:
                res = deep_trace(items, mov_idx, gad.get('source_reg'))
        gad_out = dict(gad)
        gad_out['deep'] = res
        m = res.get('method')
        if m in counts:
            counts[m] += 1
        else:
            counts['other'] += 1
        results.append(gad_out)

    out = {'count': len(results), 'counts': counts, 'gadgets': results}
    try:
        with open(OUT_JSON, 'w', encoding='utf-8') as of:
            json.dump(out, of, ensure_ascii=False, indent=2)
    except Exception as e:
        print('Failed to write output:', e, file=sys.stderr)
        sys.exit(3)

    print(f"Deep check done: {len(results)} gadgets — stack={counts['stack']}, adrp={counts['adrp']}, adrp+ldp={counts['adrp+ldp']}, constant={counts['constant']}, unknown={counts['unknown']}")


if __name__ == '__main__':
    main()
