#!/usr/bin/env python3
"""Extract common kernel symbol addresses from parsed symbol JSON files.
Writes `offsets_parsed_symbols.json` and a C header `offsets_parsed_symbols.h`.
"""
import json, os

INPUTS = ['pmap_ppl_parsed_precise_21D61.json','pmap_ppl_parsed_21D61.json']
OUT_JSON = 'offsets_parsed_symbols.json'
OUT_H = 'offsets_parsed_symbols.h'

KEYWORDS = [
    'allproc','_allproc','current_proc','current_task','proc_list','proc_for_each','rootvnode',
    'vm_map_enter','vm_map_protect','copyin','copyout','bzero','memmove','panic','trust_cache','amfi','sandbox'
]

def find_symbols():
    found = {}
    for fname in INPUTS:
        if not os.path.exists(fname):
            continue
        j = json.load(open(fname))
        items = j.get('items', [])
        for it in items:
            name = it.get('name','')
            addr = it.get('addr')
            if not name or not addr:
                continue
            lname = name.lower()
            for kw in KEYWORDS:
                if kw in lname:
                    # prefer first occurrence
                    if kw not in found:
                        try:
                            val = int(addr)
                            found[kw] = hex(val)
                        except Exception:
                            found[kw] = addr
    return found

def write_outputs(found):
    json.dump(found, open(OUT_JSON,'w'), indent=2)
    with open(OUT_H,'w') as fh:
        fh.write('/* Auto-generated offsets from parsed symbol files */\n')
        for k,v in found.items():
            fh.write('#define OFF_%s %s\n' % (k.upper(), v))
    print('Wrote', OUT_JSON, 'and', OUT_H)

def main():
    f = find_symbols()
    write_outputs(f)

if __name__=='__main__':
    main()
