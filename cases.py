"""Supplemental checks against the unchanged scalar model. Linux execution only."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback

N = 256000
FAMILIES = ('random', 'nowrap', 'odd_mod', 'bits', 'even_mod')
ACCESS_NAMES = ('main_reads', 'main_writes', 'aux_reads', 'aux_writes', 'cam_searches', 'cam_writes')


def model():
    if sys.platform != 'linux' or not __debug__:
        raise RuntimeError('Native cloud Linux and enabled assertions are required')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'frozen'))
    import reference
    return reference


def generate(seed_hex, family, variant):
    ref = model()
    seed = bytes.fromhex(seed_hex)
    material = hashlib.shake_256(seed + b'/parameters').digest(48)
    a = int.from_bytes(material[:16], 'little')
    d = int.from_bytes(material[16:32], 'little')
    if family == 'random':
        blob = hashlib.shake_256(seed + b'/random').digest(16 * (N + 128))
        keys, seen = [], set()
        for offset in range(0, len(blob), 16):
            key = int.from_bytes(blob[offset:offset+16], 'little')
            if key not in seen:
                keys.append(key)
                seen.add(key)
            if len(keys) == N:
                break
    else:
        if family == 'nowrap':
            d = 1 if variant == 0 else 1 + (d & ((1 << 64) - 1))
            a %= (1 << 128) - (N - 1) * d
        elif family == 'bits':
            d = 1 << (0 if variant == 0 else 110)
            a %= (1 << 128) - (N - 1) * d
        elif family == 'odd_mod':
            d |= 1
        elif family == 'even_mod':
            d = ((d | 1) << (1 if variant == 0 else 110)) & ref.MASK128
        else:
            raise ValueError(family)
        keys = [(a + i * d) & ref.MASK128 for i in range(N)]
    assert len(keys) == N and len(set(keys)) == N
    return keys


def check(keys, seed_hex):
    ref = model()
    table, truth, statuses = ref.Dictionary(), set(), Counter()
    maxima = {name: [0] * 6 for name in ('insert', 'member', 'probe', 'duplicate')}

    def observe(kind, access):
        row = [getattr(access, name) for name in ACCESS_NAMES]
        maxima[kind] = [max(x, y) for x, y in zip(maxima[kind], row)]

    for key in keys:
        status, access = table.insert(key)
        observe('insert', access)
        statuses[status] += 1
        assert status in (2, 4, 5, 6, 7, 8, 9), 'Duplicate or invalid insertion status'
        if 2 <= status <= 6:
            truth.add(key)
    for key in keys:
        found, access = table.contains(key)
        observe('member', access)
        assert found == (key in truth), 'Membership mismatch'
    duplicate_keys = [key for key in keys[::257] if key in truth]
    for key in duplicate_keys:
        before = (table.overflow_count, table.rejected_count)
        status, access = table.insert(key)
        observe('duplicate', access)
        assert status == 3 and before == (table.overflow_count, table.rejected_count)
    blob = hashlib.shake_256(bytes.fromhex(seed_hex) + b'/nonmembers').digest(16 * 4096)
    negative_count = 0
    for offset in range(0, len(blob), 16):
        key = int.from_bytes(blob[offset:offset+16], 'little')
        found, access = table.contains(key)
        observe('probe', access)
        assert found == (key in truth), 'Probe mismatch'
        negative_count += key not in truth
    storage = table.storage()
    assert storage['total_bits'] == 35725312 and storage['within_budget']
    assert table.overflow_count == sum(statuses[k] for k in (4, 5, 6))
    assert table.rejected_count == sum(statuses[k] for k in (7, 8, 9))
    return dict(n=len(keys), conflicts=table.conflict_count, rejected=table.rejected_count,
                overflow=table.overflow_count, accepted=len(truth), status_totals=dict(statuses),
                access_maxima=maxima['insert'], access_by_operation=maxima, storage=storage,
                member_queries=len(keys), nonmember_probes=4096, actual_negative_probes=negative_count,
                duplicates=len(duplicate_keys), passed=table.conflict_count <= 512 and
                table.rejected_count == 0 and len(truth) == len(keys))


def input_blob(keys):
    return b''.join(key.to_bytes(16, 'little') for key in keys)


def execute(case, attempt):
    started = time.monotonic()
    path = Path(attempt)
    path.mkdir(parents=True, exist_ok=False)
    report = dict(case)
    try:
        keys = generate(case['seed'], case['family'], case['variant'])
        blob = input_blob(keys)
        # Persist input before candidate execution; keep it on any failure/interruption.
        (path / 'input.bin').write_bytes(blob)
        report['input_sha256'] = hashlib.sha256(blob).hexdigest()
        report.update(check(keys, case['seed']))
        report['execution_status'] = 'completed'
    except BaseException as error:
        report.update(passed=False, execution_status='error', error=repr(error))
        (path / 'traceback.txt').write_text(traceback.format_exc(), encoding='utf-8')
    report['elapsed_seconds'] = time.monotonic() - started
    (path / 'worker.json').write_text(json.dumps(report, sort_keys=True) + '\n', encoding='utf-8')
    return report


def boundary():
    ref = model()
    keys = [ref.inverse_transform((q << 64) | (1 << 14)) for q in range(514)]
    assert len(set(keys)) == 514
    table = ref.Dictionary()
    statuses = [table.insert(key)[0] for key in keys]
    assert statuses == [2] + [5] * 512 + [8]
    assert table.conflict_count == 513 and table.rejected_count == 1
    assert all(table.contains(key)[0] for key in keys[:513])
    assert not table.contains(keys[513])[0]
    assert table.insert(keys[0])[0] == 3
    assert table.insert(keys[1])[0] == 3
    return {'check_passed': True, 'keys': 514, 'conflicts': 513, 'rejected': 1,
            'interpretation': 'Expected counterexample to unrestricted-input conflict guarantee; NOT a passing statistical case.',
            'input_sha256': hashlib.sha256(input_blob(keys)).hexdigest()}, input_blob(keys)
