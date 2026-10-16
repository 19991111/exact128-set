"""Execute a frozen Huawei verification package on native cloud Linux."""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True


def put(path,value):
    with path.open('x',encoding='utf-8') as f:
        json.dump(value,f,indent=2);f.write('\n')


def run(command,out,name,timeout=180):
    command=list(map(str,command))
    put(out/(name+'.command.json'),{'argv':command,'cwd':str(ROOT),'timeout_seconds':timeout})
    with (out/(name+'.log')).open('x',encoding='utf-8') as f:
        process=subprocess.run(command,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
    assert process.returncode==0, f'{name}: exit {process.returncode}'


def account(design,name):
    module=design['modules'][name]
    memory=registers=registered_reads=0
    entries=[]
    for cell in module.get('cells',{}).values():
        kind=cell['type']
        if kind=='$mem_v2':
            width=int(cell['parameters']['WIDTH'],2)
            size=int(cell['parameters']['SIZE'],2)
            memory+=width*size
            read_clock_flags=cell['parameters'].get('RD_CLK_ENABLE','0')
            registered_reads+=read_clock_flags.count('1')*width
            entries.append({'module':name,'width':width,'size':size,
                            'read_ports':int(cell['parameters']['RD_PORTS'],2),
                            'write_ports':int(cell['parameters']['WR_PORTS'],2)})
        elif kind in ('$dff','$dffe','$sdff','$sdffe','$sdffce','$adff','$adffe'):
            registers+=len(cell['connections']['Q'])
        elif kind in design['modules']:
            child=account(design,kind)
            memory+=child['memory_bits'];registers+=child['register_bits'];entries+=child['memories']
            registered_reads+=child['registered_read_bits']
    return {'memory_bits':memory,'register_bits':registers,
            'registered_read_bits':registered_reads,'memories':entries}


def formal_and_budget(yosys,out):
    rtl=' '.join((ROOT/'rtl'/f).as_posix() for f in ('huawei128_hash.v','huawei128_core.v','huawei128_memory.v'))
    harness=(ROOT/'validation/proofs.v').as_posix()
    legacy=(ROOT/'validation/legacy_hash.v').as_posix()
    proofs=[]
    for top in ('prove_main_update','prove_compare','prove_append','prove_match','prove_hash'):
        script=f'read_verilog {rtl} {harness} {legacy}; hierarchy -top {top}; proc; flatten; opt; '
        script+='sat -verify -timeout 90 -prove ok 1 -show-inputs'
        run([yosys,'-Q','-T','-p',script],out,top,180)
        assert 'SUCCESS!' in (out/(top+'.log')).read_text(encoding='utf-8')
        proofs.append({'module':top,'passed':True})
    cuts=('value','left_present','right_present','left_count','right_count','equal','cam_hit')
    selection=' '.join('prove_controller/w:dut.'+name for name in cuts)
    script=f'read_verilog {rtl} {harness}; hierarchy -top prove_controller; proc; flatten; '
    script+=f'select -assert-count {len(cuts)} {selection}; cutpoint {selection}; opt; '
    script+='sat -verify -timeout 120 -seq 16 -set-init-zero -set-init dut.phase 1 '
    script+='-set reset 0 -prove ok 1 -show-ports -tempinduct -maxsteps 24'
    run([yosys,'-Q','-T','-p',script],out,'prove_controller',240)
    assert 'Induction step proven: SUCCESS!' in (out/'prove_controller.log').read_text(encoding='utf-8')
    proofs.append({'module':'prove_controller','passed':True,'semantic_observations_cut':list(cuts),
                   'scope':'Unbounded control/access proof after initialization; not full-memory semantic induction.'})
    put(out/'formal_gates.json',{'passed':True,'proofs':proofs})
    budgets=[]
    for top in ('huawei128_core','huawei128_memory'):
        netlist=out/(top+'.json')
        script=f'read_verilog {rtl}; hierarchy -top {top}; proc; opt; memory_dff; opt; memory_collect; check; '
        script+=f'write_json {netlist.as_posix()}; stat'
        run([yosys,'-Q','-T','-p',script],out,'elaborate_'+top,240)
        report=account(json.loads(netlist.read_text(encoding='utf-8')),top)
        budgets.append(report)
    core,memory=budgets
    assert core['memory_bits']==65536, core
    assert memory['memory_bits']==18874368+16777216, memory
    assert len(memory['memories'])==4
    assert all(m['read_ports']==1 and m['write_ports']==1 for m in memory['memories'])
    registers=sum(r['register_bits']+r['registered_read_bits'] for r in budgets)
    assert registers<=4096, registers
    put(out/'memory_budget.json',{'passed':True,'core':core,'memory':memory,
                                'combined_register_bits':registers,'charged_fixed_parameters_bits':4096,
                                'charged_total_state_bits':8192,'total_charged_bits':35725312,
                                'baseline_bits':32768000,'percent':109.025,
                                'physical_chip_verified':False})


def main():
    if sys.platform!='linux' or platform.machine() not in ('x86_64','amd64'):
        raise RuntimeError('This entry requires native x86-64 cloud Linux.')
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve()
    assert not out.exists(), 'A run never overwrites an existing result directory.'
    assert not out.is_relative_to(ROOT), 'Results must be outside frozen source.'
    out.mkdir(parents=True)
    started=time.monotonic()
    completion={'status':'stopped','stage':'source','fresh_seeds_generated':False,
                'official_acceptance':False,'physical_chip_verified':False,
                'source_directory':str(ROOT),'started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        from verify_source import verify
        put(out/'source_verification.json',verify())
        tools={name:shutil.which(name) for name in ('iverilog','vvp','yosys')}
        assert all(tools.values()), f'Missing native verification tools: {tools}'
        compiler_sources=[ROOT/'rtl'/name for name in ('huawei128_hash.v','huawei128_core.v','huawei128_memory.v')]
        compiler_sources.append(ROOT/'validation/huawei128_testbench.v')
        tool_hashes={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in tools.items()}
        put(out/'environment.json',{'platform':platform.platform(),'machine':platform.machine(),
                                  'python':sys.version,'tools':tools,'tool_sha256':tool_hashes,
                                  'cpuinfo':Path('/proc/cpuinfo').read_text()})
        for name in tools:
            flag='-V'
            run([tools[name],flag],out,'version_'+name,30)
        completion['stage']='compile'
        executable=out/'simulation.vvp'
        run([tools['iverilog'],'-g2012','-s','huawei128_testbench','-o',executable,*compiler_sources],
            out,'compile',120)
        put(out/'compiled_program.json',{'sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
                                        'path':executable.name})
        completion['stage']='formal_and_budget'
        formal_and_budget(tools['yosys'],out)
        completion['stage']='semantic_and_rtl'
        sys.path.insert(0,str(ROOT/'validation'))
        from semantic_checks import development,fresh_cases
        gate=development(out)
        run([tools['vvp'],executable,'+vectors='+str(out/'vectors.txt'),
             '+report='+str(out/'simulation_summary.json')],out,'simulate',1200)
        rtl=json.loads((out/'simulation_summary.json').read_text(encoding='utf-8'))
        assert rtl['passed'] and rtl['operations']==gate['command_rows']
        assert all(rtl['status_totals'][i] for i in range(10))
        assert all(rtl['boundary_'+str(a)] for a in (131071,131072,147455))
        assert rtl['maximum_response_cycles']<=8
        verify()
        assert all(hashlib.sha256(Path(tools[name]).read_bytes()).hexdigest()==value for name,value in tool_hashes.items())
        put(out/'all_required_gates_passed.json',{'passed':True,'compiled_source_unchanged':True,
            'gates':['formal_datapath','control_access_induction','generic_state_and_memory_budget',
                     'independent_set_oracle','prior_wide_model_equivalence','complete_controller_rtl_trace']})
        verify()
        completion['stage']='fresh_full_size_cases'
        completion['fresh_seeds_generated']=True
        fresh_cases(out)
        verify()
        assert all(hashlib.sha256(Path(tools[name]).read_bytes()).hexdigest()==value for name,value in tool_hashes.items())
        completion.update(status='completed',stage='done')
    except BaseException as exc:
        completion.update(error_type=type(exc).__name__,error=str(exc))
        with (out/'failure_traceback.txt').open('x',encoding='utf-8') as f:
            traceback.print_exc(file=f)
    finally:
        completion['fresh_seeds_generated']=(out/'fresh_seeds.json').exists()
        completion['elapsed_seconds']=round(time.monotonic()-started,3)
        completion['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        put(out/'completion.json',completion)
        files=[{'path':p.relative_to(out).as_posix(),'bytes':p.stat().st_size,
                'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
               for p in sorted(out.rglob('*')) if p.is_file()]
        put(out/'result_manifest.json',{'files':files,'source_manifest_sha256':
                                     hashlib.sha256((ROOT/'manifest.json').read_bytes()).hexdigest()})
        print(json.dumps(completion,indent=2),flush=True)
    return 0 if completion['status']=='completed' else 3


if __name__=='__main__':
    raise SystemExit(main())
