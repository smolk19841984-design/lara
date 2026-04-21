from pathlib import Path
import json
import re

IN_JSON = Path('iPad8,9_Analysis/scripts/full_instr_diff_all_report.json')
OUT_JSON = Path('iPad8,9_Analysis/scripts/key_instr_changes_report.json')
OUT_TXT = Path('iPad8,9_Analysis/key_instr_changes_summary.txt')

BRANCHES = re.compile(r'\b(cbz|cbnz|tbz|tbnz|b\.|b\s)')
ATOMIC = re.compile(r'\b(ldxr|stxr|ldrex|strex|swp|cas)\b')
CALLS = re.compile(r'\b(blr|bl)\b')

def inspect_inst_list(insts):
    found = {'branches': [], 'atomic': [], 'calls': []}
    for i,ins in enumerate(insts):
        s = ins.lower()
        if BRANCHES.search(s):
            found['branches'].append((i, ins))
        if ATOMIC.search(s):
            found['atomic'].append((i, ins))
        if CALLS.search(s):
            found['calls'].append((i, ins))
    return found

def main():
    if not IN_JSON.exists():
        print('Input report missing:', IN_JSON)
        return
    data = json.loads(IN_JSON.read_text(encoding='utf-8'))
    out = {'ranges': []}
    for r in data.get('ranges', []):
        rec = {'fileoff_start': r.get('fileoff_start'), 'fileoff_end': r.get('fileoff_end'), 'diffs_count': r.get('diffs_count',0), 'matches': {}}
        matches = {'branches': [], 'atomic': [], 'calls': []}
        for d in r.get('diffs', []):
            for side in ('a','b'):
                seq = d.get(side, [])
                findings = inspect_inst_list(seq)
                for k,v in findings.items():
                    if v:
                        matches[k].append({'tag': d.get('tag'), 'side': side, 'examples': v[:6]})
        rec['matches'] = matches
        out['ranges'].append(rec)

    IN_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')

    lines = []
    total_with = 0
    for r in out['ranges']:
        has = any(r['matches'][k] for k in r['matches'])
        if has:
            total_with += 1
            lines.append(f"{r['fileoff_start']} - {r['fileoff_end']} diffs:{r['diffs_count']}")
            for k in ('branches','atomic','calls'):
                if r['matches'][k]:
                    lines.append(f"  {k}: {len(r['matches'][k])} occurrences; examples:")
                    for m in r['matches'][k][:3]:
                        lines.append(f"    tag={m['tag']} side={m['side']}")
                        for idx,ins in m['examples']:
                            lines.append(f"      - idx={idx} ins={ins}")
            lines.append('')
    lines.insert(0, f'Total ranges with any key-instr matches: {total_with}')
    OUT_TXT.write_text('\n'.join(lines), encoding='utf-8')
    print('Wrote', OUT_JSON, OUT_TXT)

if __name__ == '__main__':
    main()
