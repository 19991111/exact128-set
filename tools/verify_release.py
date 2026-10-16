"""Check release bytes and saved evidence without importing the candidate."""
import ast
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify():
    manifest = json.loads((ROOT / 'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    expected = {r['path'] for r in manifest['files']}
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
              if p.is_file() and not any(part in ('.git', '__pycache__', '.venv', 'local-results')
                                        for part in p.relative_to(ROOT).parts)}
    if actual != expected | {'RELEASE_MANIFEST.json'}:
        raise RuntimeError('Release file set differs: ' + str(sorted(actual ^ (expected | {'RELEASE_MANIFEST.json'}))))
    python_files = 0
    for row in manifest['files']:
        path = ROOT / row['path']
        if path.is_symlink():
            raise RuntimeError('Symlink is not allowed: ' + row['path'])
        data = path.read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Release byte mismatch: ' + row['path'])
        if path.suffix == '.py':
            ast.parse(data.decode('utf-8'), filename=row['path'])
            python_files += 1
    provenance = json.loads((ROOT / 'SOURCE_PROVENANCE.json').read_text(encoding='utf-8'))
    upstream = json.loads((ROOT / 'provenance/upstream_source_manifest.json').read_text(encoding='utf-8'))
    original_hashes = {r['path']: r['sha256'] for r in upstream['files']}
    preserved = provenance['preserved_files']
    if len(preserved) != 15:
        raise RuntimeError('Unexpected preserved source count')
    for row in preserved:
        data = (ROOT / row['public_path']).read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Source provenance mismatch: ' + row['public_path'])
        if row['public_path'] != 'cases.py' and original_hashes[row['original_path']] != row['sha256']:
            raise RuntimeError('Original candidate hash mismatch')
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'frozen/verify_source.py')],
                            capture_output=True, text=True, check=True)
    frozen = json.loads(result.stdout)
    with (ROOT / 'evaluation/conflict_histogram.csv').open(encoding='utf-8-sig', newline='') as stream:
        hist = [(int(r['conflicts']), int(r['groups'])) for r in csv.DictReader(stream)]
    if sum(n for _, n in hist) != 100000 or sum(x*n for x, n in hist) != 17372510:
        raise RuntimeError('Histogram totals differ')
    quantiles = {}
    for p in (.5, .95, .99, .999):
        cumulative = 0
        for value, count in hist:
            cumulative += count
            if cumulative >= p * 100000:
                quantiles[str(p)] = value
                break
    summary = json.loads((ROOT / 'evaluation/summary.json').read_text(encoding='utf-8'))
    if quantiles != summary['conflict_quantiles_nearest_rank']:
        raise RuntimeError('Quantile mismatch')
    with (ROOT / 'evaluation/strata_independent.csv').open(encoding='utf-8-sig', newline='') as stream:
        strata = list(csv.DictReader(stream))
    if len(strata) != 10 or sum(int(r['groups']) for r in strata) != 100000:
        raise RuntimeError('Stratum count mismatch')
    for r in strata:
        saved = summary['strata'][r['stratum']]
        for a, b in [('groups','records'),('minimum_conflicts','min_conflicts'),
                     ('maximum_conflicts','max_conflicts'),('conflict_sum','conflict_sum'),('rejected','rejected')]:
            if int(r[a]) != saved[b]:
                raise RuntimeError('Stratum value mismatch')
    return {'passed': True, 'release_files': len(expected), 'preserved_source_files': len(preserved),
            'python_files_parsed_without_import': python_files, 'frozen_source': frozen,
            'saved_groups':100000, 'recomputed_conflict_sum':17372510,
            'quantiles':quantiles, 'candidate_executed':False, 'new_keys_or_seeds_generated':False}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
