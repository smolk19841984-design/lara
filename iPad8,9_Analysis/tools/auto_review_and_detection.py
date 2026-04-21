import re
import json
import csv
from pathlib import Path

PATTERNS = {
    'udf': re.compile(r'\budf\b', re.IGNORECASE),
    'mov_w0_0x190': re.compile(r'mov\s+w0,\s*#0x190', re.IGNORECASE),
    'bl_validator': re.compile(r'bl\s+0xfffffff00849f814', re.IGNORECASE),
    'pacibsp': re.compile(r'pacibsp', re.IGNORECASE),
    'retab': re.compile(r'retab', re.IGNORECASE),
    'added_ret': re.compile(r'^\+.*\bret\b', re.IGNORECASE),
}

def scan_candidates(src_dir: Path):
    report = []
    for path in sorted(src_dir.glob('candidate_*.diff.txt')):
        text = path.read_text(errors='ignore')
        lines = text.splitlines()
        item = {'file': path.name, 'counts': {}, 'samples': {}, 'total_lines': len(lines)}
        for name, pat in PATTERNS.items():
            matches = pat.findall(text)
            item['counts'][name] = len(matches)
            sample = None
            for ln in lines:
                if pat.search(ln):
                    sample = ln.strip()
                    break
            item['samples'][name] = sample
        report.append(item)
    return report

def write_reports(report, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / 'auto_review_report.json'
    out_csv = out_dir / 'auto_review_report.csv'
    with out_json.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        header = ['file','total_lines'] + [f"count_{k}" for k in PATTERNS.keys()] + [f"sample_{k}" for k in PATTERNS.keys()]
        writer.writerow(header)
        for it in report:
            row = [it['file'], it['total_lines']] + [it['counts'][k] for k in PATTERNS.keys()] + [it['samples'][k] or '' for k in PATTERNS.keys()]
            writer.writerow(row)
    return out_json, out_csv

def main():
    src = Path(__file__).resolve().parents[1] / 'per_context_diffs'
    out = Path(__file__).resolve().parents[1]
    report = scan_candidates(src)
    out_json, out_csv = write_reports(report, out)
    print('Wrote', out_json.as_posix(), out_csv.as_posix())

if __name__ == '__main__':
    main()
