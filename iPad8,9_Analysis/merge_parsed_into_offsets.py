#!/usr/bin/env python3
"""Merge parsed-symbol offsets into main offsets JSON and emit C header."""
import json

BASE = 'offsets_iPad8_9_17.3.1.json'
PARSED = 'offsets_parsed_symbols.json'
OUT = 'offsets_iPad8_9_17.3.1_merged.json'
OUT_H = 'offsets_iPad8_9_17.3.1.h'

def main():
    base = json.load(open(BASE))
    parsed = json.load(open(PARSED))
    # merge under 'symbols'
    syms = base.get('symbols', {})
    for k,v in parsed.items():
        syms[k] = v
    base['symbols'] = syms
    json.dump(base, open(OUT,'w'), indent=2)
    # write header
    with open(OUT_H,'w') as fh:
        fh.write('/* Merged offsets header */\n')
        kb = base.get('kernel_base_offset') or base.get('kernel_base') or '0'
        fh.write('#define KERNEL_BASE %s\n' % kb)
        for k,v in syms.items():
            fh.write('#define SYM_%s %s\n' % (k.upper(), v))
    print('Wrote', OUT, 'and', OUT_H)

if __name__=='__main__':
    main()
