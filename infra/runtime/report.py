#!/usr/bin/env python3
"""Fail closed unless every M09 runtime gate has verified passing evidence."""
import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = {f'R{i:02}' for i in range(1, 11)}


def evaluate(repo, ledger, manifest):
    reasons = []
    if ledger.get('milestone') != 'P1-M09':
        reasons.append('wrong milestone')
    cases = ledger.get('cases', [])
    ids = [case.get('id') for case in cases]
    if set(ids) != REQUIRED or len(ids) != len(REQUIRED):
        reasons.append('missing, duplicated or unknown required gates')
    for case in cases:
        if case.get('status') != 'PASS':
            reasons.append(f'{case.get("id", "unknown")}: not PASS')
        evidence = case.get('evidence', [])
        if not evidence:
            reasons.append(f'{case.get("id", "unknown")}: missing evidence')
        for name in evidence:
            path = repo / name
            if not path.is_relative_to(repo) or '..' in Path(name).parts or not path.is_file() or name not in manifest.get('evidence', {}):
                reasons.append('unverified evidence reference')
    for section in ('source', 'evidence'):
        items = manifest.get(section, {})
        if not items:
            reasons.append(f'missing {section} manifest')
        for name, expected in items.items():
            path = repo / name
            if '..' in Path(name).parts or Path(name).is_absolute() or not path.is_file():
                reasons.append('invalid manifest path')
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if expected != actual:
                reasons.append(f'changed {section}: {name}')
    if not manifest.get('isolated_runtime_acceptance'):
        reasons.append('isolated runtime acceptance incomplete')
    return {'milestone': 'P1-M09', 'status': 'INCOMPLETE' if reasons else 'PASS', 'reasons': reasons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        report = evaluate(repo, json.loads(Path(args.ledger).read_text()), json.loads(Path(args.manifest).read_text()))
    except (ValueError, KeyError, TypeError, OSError):
        report = {'milestone': 'P1-M09', 'status': 'INCOMPLETE', 'reasons': ['invalid or unavailable evidence']}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
