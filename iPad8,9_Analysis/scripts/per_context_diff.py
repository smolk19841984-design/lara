#!/usr/bin/env python3
import re
import os
import json
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CTX_PATH = ROOT / 'branch_call_small_changes_contexts.txt'
OUT_DIR = ROOT / 'per_context_diffs'
OUT_DIR.mkdir(exist_ok=True)

def parse_contexts(text):
    blocks = re.split(r"^=== Candidate ", text, flags=re.M)
    candidates = []
    for b in blocks:
        if not b.strip():
            continue
        header, *rest = b.splitlines()
        cid = header.split()[0]
        content = '\n'.join(rest)
        file_sections = []
        parts = re.split(r"^-- File: ", content, flags=re.M)
        for p in parts:
            if not p.strip():
                continue
            first, *lines = p.splitlines()
            file_path = first.split(' (match:')[0].strip()
            file_sections.append((file_path, '\n'.join(lines)))
        candidates.append({'id': cid, 'files': file_sections})
    return candidates

def extract_insn_lines(block_text):
    lines = []
    for ln in block_text.splitlines():
        ln = ln.rstrip()
        m = re.match(r"^\s*([0-9a-fxA-F]+):\s+([0-9A-Fa-f ]{2,})\s{2,}(.+)$", ln)
        if m:
            addr = m.group(1)
            bytes_hex = m.group(2).strip()
            asm = m.group(3).strip()
            bytes_compact = bytes_hex.replace(' ', '')
            lines.append({'addr': addr, 'bytes': bytes_hex, 'bytes_compact': bytes_compact, 'asm': asm, 'raw': ln})
    return lines

def compare_blocks(a_lines, b_lines):
    a_bytes_lines = [l['bytes'] for l in a_lines]
    b_bytes_lines = [l['bytes'] for l in b_lines]
    a_asm_lines = [l['asm'] for l in a_lines]
    b_asm_lines = [l['asm'] for l in b_lines]
    bytes_diff = list(difflib.unified_diff(a_bytes_lines, b_bytes_lines, lineterm=''))
    asm_diff = list(difflib.unified_diff(a_asm_lines, b_asm_lines, lineterm=''))
    return bytes_diff, asm_diff

def main():
    if not CTX_PATH.exists():
        print(f'Missing contexts file: {CTX_PATH}')
        return
    txt = CTX_PATH.read_text(encoding='utf-8')
    candidates = parse_contexts(txt)
    summary = []
    for c in candidates:
        cid = c['id']
        files = c['files']
        if not files:
            continue
        out_path = OUT_DIR / f'candidate_{cid}.diff.txt'
        with out_path.open('w', encoding='utf-8') as fh:
            fh.write(f'Candidate {cid}\n')
            fh.write('='*60 + '\n')
            extracted = []
            for file_path, block in files:
                fp = file_path.replace('\\','/')
                fh.write(f'File: {fp}\n')
                insns = extract_insn_lines(block)
                extracted.append((fp, insns))
                for ins in insns:
                    fh.write(ins['raw'] + '\n')
                fh.write('\n')
            results = []
            for i in range(len(extracted)):
                for j in range(i+1, len(extracted)):
                    fa, a_ins = extracted[i]
                    fb, b_ins = extracted[j]
                    bytes_diff, asm_diff = compare_blocks(a_ins, b_ins)
                    fh.write(f'--- Diff {fa} VS {fb} ---\n')
                    if bytes_diff:
                        fh.write('Bytes diff:\n')
                        fh.write('\n'.join(bytes_diff) + '\n')
                    else:
                        fh.write('Bytes identical\n')
                    if asm_diff:
                        fh.write('Asm diff:\n')
                        fh.write('\n'.join(asm_diff) + '\n')
                    else:
                        fh.write('Asm identical\n')
                    fh.write('\n')
                    results.append({'a': fa, 'b': fb, 'bytes_changed': bool(bytes_diff), 'asm_changed': bool(asm_diff)})
            summary.append({'id': cid, 'comparisons': results, 'out': str(out_path)})
    (OUT_DIR / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(f'Done: wrote {len(summary)} candidate diffs to {OUT_DIR}')

if __name__ == '__main__':
    main()
