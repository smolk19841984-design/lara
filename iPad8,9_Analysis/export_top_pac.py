#!/usr/bin/env python3
"""Export top-N PAC candidates by score from the expanded PAC JSON.
Writes pac_candidates_top200.json (configurable N).
"""
import json, sys

IN = 'offsets_iPad8_9_17.3.1_pac_candidates_expanded.json'
OUT = 'pac_candidates_top200.json'
N = 200

def main():
    j = json.load(open(IN))
    ranked = j.get('ranked_candidates', [])
    top = ranked[:N]
    summary = {'source': IN, 'total': len(ranked), 'exported': len(top), 'top': top}
    json.dump(summary, open(OUT,'w'), indent=2)
    print('Wrote', OUT)

if __name__=='__main__':
    main()
