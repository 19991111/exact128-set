"""Reproduce one original case or its known boundary on native Linux."""
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def recorded_case(case_id, records):
    if records is None:
        row = json.loads((ROOT / 'evaluation/example_case.json').read_text(encoding='utf-8'))
        if case_id != row['id']:
            raise ValueError('Only group 0 is bundled. Supply --records for another original group.')
        return row
    opener = gzip.open if records.suffix == '.gz' else open
    with opener(records, 'rt', encoding='utf-8-sig', newline='') as stream:
        for row in csv.DictReader(stream):
            if int(row['id']) == case_id:
                for key in ('id','variant','conflicts','rejected','accepted','member_queries','nonmember_probes','duplicates'):
                    row[key] = int(row[key])
                return row
    raise ValueError('Original group ID not found')


def main():
    if sys.platform != 'linux' or not __debug__:
        raise RuntimeError('Native Linux and enabled assertions are required. Integrity-only checks are portable.')
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--boundary', action='store_true')
    choice.add_argument('--case-id', type=int)
    parser.add_argument('--records', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError('Use a new output file outside the repository')
    if not output.parent.is_dir():
        raise ValueError('Output parent directory must already exist')
    from verify_release import verify
    verify()
    sys.path.insert(0, str(ROOT))
    import cases
    if args.boundary:
        if args.records or args.input:
            raise ValueError('The boundary mode does not use recorded-case arguments')
        result, blob = cases.boundary()
        expected = '849719b7c5719201f15230a4b52cdf044dd56d05ae710b0253b7b76fe5336c04'
        if result['input_sha256'] != expected:
            raise RuntimeError('Constructed boundary identity changed')
        result['expected_boundary_reproduced'] = True
    else:
        row = recorded_case(args.case_id, args.records)
        if args.input:
            blob = args.input.read_bytes()
            if len(blob) != 256000 * 16:
                raise RuntimeError('Recorded input byte count differs')
            keys = [int.from_bytes(blob[i:i+16], 'little') for i in range(0, len(blob),16)]
        else:
            keys = cases.generate(row['seed'], row['family'], row['variant'])
            blob = cases.input_blob(keys)
        if hashlib.sha256(blob).hexdigest() != row['input_sha256']:
            raise RuntimeError('Original recorded input hash differs')
        if len(keys) != 256000 or len(set(keys)) != 256000:
            raise RuntimeError('Original input cardinality differs')
        result = json.loads(json.dumps(cases.check(keys, row['seed'])))
        for name in ('conflicts','rejected','accepted','member_queries','nonmember_probes','duplicates'):
            if result[name] != row[name]:
                raise RuntimeError('Original semantic result differs: ' + name)
        for name in ('status_totals','access_by_operation','storage','actual_negative_probes'):
            if name in row and result[name] != row[name]:
                raise RuntimeError('Original worker detail differs: ' + name)
        if not result['passed']:
            raise RuntimeError('Recorded statistical group did not pass')
        result.update(id=row['id'], family=row['family'], variant=row['variant'],
                      seed=row['seed'], input_sha256=row['input_sha256'], recorded_case_reproduced=True)
    result['new_seed_generated'] = False
    result['full_100000_group_campaign_repeated'] = False
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
