"""Read-only verification of the public packaging manifest.

Algorithm and RTL files retain their frozen upstream bytes.
Only this packaging verifier and its file manifest have a new identity.
Never import or execute the algorithm here.
"""
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent


def verify():
    manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
    pinned={p['path'] for p in manifest['files']}
    present={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}
    assert present==pinned|{'manifest.json'}, sorted(present^(pinned|{'manifest.json'}))
    for entry in manifest['files']:
        path=ROOT/entry['path']
        assert not path.is_symlink()
        data=path.read_bytes()
        assert len(data)==entry['bytes']
        assert hashlib.sha256(data).hexdigest()==entry['sha256'], entry['path']
        if path.suffix=='.py':
            ast.parse(data.decode('utf-8'),filename=entry['path'])
    hashes=(ROOT/'rtl/huawei128_hash.v').read_text(encoding='utf-8')
    modules={}
    for name,body in re.findall(r'module\s+(\w+)\s*\((.*?)endmodule',hashes,re.S):
        nodes=re.findall(r'wire \[255:0\] h(\d+) = ([^;]+);',body)
        expected=24 if name=='hw128_hash_terminal' else 28
        assert [int(i) for i,_ in nodes]==list(range(expected+1)), name
        for i,rhs in nodes[1:]:
            assert re.findall(r"(?<!')\bh(\d+)\b",rhs)==[str(int(i)-1)], (name,i,rhs)
            assert len(re.findall(r'(?:>>|<<|\*|&|\^|\+|\-|\|)',rhs))==1
        outputs=re.findall(r'assign (\w+) = h(\d+)\[',body)
        assert outputs==([('value','24')] if expected==24 else [('address','28')])
        modules[name]={'single_predecessor_chain':True,'operations':expected,'terminal_output_only':True}
    assert set(modules)=={'hw128_hash_terminal','hw128_hash_right'}
    parts=dict(main_bits=147456*128,auxiliary_bits=2*16384*512,
               overflow_bits=512*128,state_bits=8192)
    total=sum(parts.values())
    assert total==35725312 and 10*total<=11*256000*128
    report={'source_files_verified':len(pinned),'python_parsed_without_import':True,
            'hash_chains':modules,'budget':dict(parts,total_bits=total,percent=109.025),
            'hardware_or_algorithm_executed':False,'controller_state_verified':False,
            'full_function_verified':False,'physical_chip_verified':False,
            'official_acceptance':False}
    return report


if __name__=='__main__':
    print(json.dumps(verify(),indent=2))
