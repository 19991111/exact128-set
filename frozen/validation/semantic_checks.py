"""Cloud-only oracle checks, differential traces, and fresh full-size cases."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import secrets
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from reference import Dictionary, MASK128, encode, inverse_transform, transform


def require_linux():
    if sys.platform != 'linux':
        raise RuntimeError('Algorithm execution and input generation require cloud Linux.')


def write_json(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def crafted(q, left, fingerprint):
    return inverse_transform((q << 64) | (fingerprint << 14) | left)


def development(out):
    require_linux()
    sys.path.insert(0, str(SOURCE/'validation/baseline'))
    import candidate1_power2_wide as baseline
    table = None
    truth = set()
    rows = []
    suites = []
    totals = Counter()
    equality_checks = 0

    def reset(name):
        nonlocal table, truth
        table, truth = Dictionary(), set()
        suites.append({'name':name, 'operations':0})
        rows.append('2 0 0 0 0 0 0 0 0 0 0 0\n')

    def command(key, insert):
        if insert:
            status, access = table.insert(key)
            assert (status == 3) == (key in truth)
            if 2 <= status <= 6:
                truth.add(key)
            else:
                assert status in (7,8,9)
        else:
            found, access = table.contains(key)
            assert found == (key in truth), '128-bit membership mismatch'
            status = int(found)
        totals[status] += 1
        suites[-1]['operations'] += 1
        rows.append(f'{int(insert)} {key:032x} {status} {access.main_reads} {access.main_writes} '
                    f'{access.aux_reads} {access.aux_writes} {access.cam_searches} {access.cam_writes} '
                    f'{table.overflow_count} {table.rejected_count} {len(rows)%4}\n')
        return status

    reset('both main segments, shared bucket words, capacity and signature spills, all rejections')
    retained=[]
    for left,right in ((0,12742),(1,12743),(2,16383)):
        for i in range(18):
            f=((i+1)<<14) | ((right-left)&16383)
            key=crafted(1+i,left,f)
            assert command(key,True)==2
            retained.append(key)
    first_f=(1<<14)|12742
    assert command(crafted(500,0,(60<<14)|12742),True)==6
    for q in range(600,1112):
        command(crafted(q,0,first_f),True)
    assert table.overflow_count==512
    assert command(crafted(2000,0,first_f),True)==8
    assert command(crafted(2000,0,(61<<14)|12742),True)==9
    assert command(crafted(2000,0,0),True)==7
    command(retained[0],True)
    command(crafted(600,0,first_f),True)
    for key in sorted(truth):
        assert command(key,False)==1
    for key in (crafted(2000,0,first_f),crafted(2000,0,(61<<14)|12742),crafted(2000,0,0)):
        assert command(key,False)==0

    reset('zero fingerprint, full overflow, exact priority, reset with stale main memory')
    for q in range(1,514):
        command(crafted(q,q&16383,0),True)
    for q in range(1,514):
        command(crafted(q,q&16383,0),False)
    command(crafted(1,1,0),True)
    command(0,True)
    command(0,False)
    command(MASK128,False)

    reset('independent scalar model versus prior 456-bit wide model')
    old=baseline.Dictionary()
    stream=hashlib.shake_256(b'huawei128-wide50-fixed-development-v1').digest(16*8192)
    keys=[int.from_bytes(stream[i:i+16],'little') for i in range(0,len(stream),16)]
    for key in keys:
        assert transform(key)==baseline.transform(key)
        assert encode(transform(key))==baseline.encode(baseline.transform(key))
        equality_checks += 2
        expected=old.insert(key)
        status=command(key,True)
        assert status==expected.rtl_status
        equality_checks += 1
    assert table.main==old.main_words
    for side in range(2):
        for row in range(16384):
            padded=int.from_bytes(table.aux[side][row*64:(row+1)*64],'little')
            old_word=int.from_bytes(old.aux_banks[side][row*57:(row+1)*57],'little')
            assert padded==old_word
    for key in keys:
        command(key,False)
        assert old.contains(key)[0]
    for key in keys[:128]:
        command(key,True)
    negatives=hashlib.shake_256(b'huawei128-wide50-fixed-nonmembers-v1').digest(16*1024)
    for i in range(0,len(negatives),16):
        command(int.from_bytes(negatives[i:i+16],'little'),False)
    for shift in (0,55,110):
        reset(f'no-wrap progression at bit {shift}')
        start=7*(1<<111)
        keys=[start+(i<<shift) for i in range(4096)]
        assert max(keys)<=MASK128
        for key in keys:
            command(key,True)
        for key in keys:
            command(key,False)
        command(start+(4096<<shift),False)
    assert all(totals[i] for i in range(10)), totals
    vectors=out/'vectors.txt'
    with vectors.open('x',encoding='ascii',newline='\n') as f:
        f.writelines(rows)
    result={'passed':True,'suites':suites,'command_rows':sum(s['operations'] for s in suites),
            'reset_rows':len(suites),'status_totals':dict(totals),
            'baseline_equality_checks':equality_checks,
            'vectors_sha256':hashlib.sha256(vectors.read_bytes()).hexdigest(),
            'scope':'Fixed development gates, independent oracle and prior-model comparison; not acceptance.'}
    write_json(out/'development_gate.json',result)
    return result


def fresh_cases(out):
    require_linux()
    assert (out/'all_required_gates_passed.json').exists()
    plan=[{'family':family,'index':i,'seed':secrets.token_hex(32)}
          for family in ('random','nowrap','odd_mod','bits','even_mod') for i in range(2)]
    assert len({p['seed'] for p in plan})==10
    write_json(out/'fresh_seeds.json',{'after_source_and_gates':True,'cases':plan})
    reports=[]
    n=256000
    for case in plan:
        seed=bytes.fromhex(case['seed'])
        family,index=case['family'],case['index']
        material=hashlib.shake_256(seed+b'/parameters').digest(48)
        a=int.from_bytes(material[:16],'little')
        d=int.from_bytes(material[16:32],'little')
        if family=='random':
            blob=hashlib.shake_256(seed+b'/random').digest(16*(n+128))
            keys=[]
            seen=set()
            for offset in range(0,len(blob),16):
                key=int.from_bytes(blob[offset:offset+16],'little')
                if key not in seen:
                    keys.append(key);seen.add(key)
                if len(keys)==n:
                    break
            assert len(keys)==n
        else:
            if family=='nowrap':
                d=1 if index==0 else 1+(d & ((1<<64)-1))
                a %= (1<<128)-(n-1)*d
            elif family=='bits':
                d=1 << (0 if index==0 else 110)
                a %= (1<<128)-(n-1)*d
            elif family=='odd_mod':
                d |= 1
            else:
                shift=1 if index==0 else 110
                d=((d | 1) << shift) & MASK128
            keys=[(a+i*d)&MASK128 for i in range(n)]
        assert len(set(keys))==n
        table=Dictionary()
        truth=set()
        statuses=Counter()
        access_max=[0]*6
        digest=hashlib.sha256()
        path=out/f'keys_{family}_{index}.bin'
        with path.open('xb') as key_file:
            for key in keys:
                raw=key.to_bytes(16,'little');key_file.write(raw);digest.update(raw)
                status,access=table.insert(key)
                statuses[status]+=1
                assert status!=3
                if 2<=status<=6:
                    truth.add(key)
                counts=(access.main_reads,access.main_writes,access.aux_reads,
                        access.aux_writes,access.cam_searches,access.cam_writes)
                access_max=[max(x,y) for x,y in zip(access_max,counts)]
        for key in keys:
            assert table.contains(key)[0]==(key in truth)
        duplicate_keys=[key for key in keys[::257] if key in truth]
        for key in duplicate_keys:
            old_counts=(table.overflow_count,table.rejected_count)
            status,_=table.insert(key)
            assert status==3 and old_counts==(table.overflow_count,table.rejected_count)
        miss_blob=hashlib.shake_256(seed+b'/nonmembers').digest(16*4096)
        for offset in range(0,len(miss_blob),16):
            key=int.from_bytes(miss_blob[offset:offset+16],'little')
            assert table.contains(key)[0]==(key in truth)
        report=dict(case,n=n,conflicts=table.conflict_count,rejected=table.rejected_count,
                    accepted=len(truth),status_totals=dict(statuses),access_maxima=access_max,
                    input_sha256=digest.hexdigest(),storage=table.storage(),
                    member_queries=n,nonmember_probes=4096,duplicates=len(duplicate_keys))
        report['passed']=report['conflicts']<=512 and report['rejected']==0 and len(truth)==n
        write_json(out/f'case_{family}_{index}.json',report)
        reports.append(report)
        print(json.dumps({'case':family,'index':index,'passed':report['passed'],
                          'conflicts':report['conflicts']}),flush=True)
    summary={'passed':all(r['passed'] for r in reports),'cases':reports,'case_count':len(reports),
             'scope':'Ten fresh self-built full-size 128-bit cases; not Huawei-designated data.',
             'old_100k_tests_relabelled':False,'official_acceptance':False}
    write_json(out/'fresh_case_summary.json',summary)
    assert summary['passed'], 'Fresh full-size budget or conflict requirement failed.'
    return summary
