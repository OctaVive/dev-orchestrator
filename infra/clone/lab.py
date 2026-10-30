#!/usr/bin/env python3
"""Explicit opt-in M06 lab extending the existing isolated M05 KVM host.

Creates separate state/binaries/images; never replaces M04/M05 configuration.
Temporary upstream trust/loopback aliases are restored in finally.
"""
import argparse
import hashlib
import importlib.machinery
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time

repo = Path(__file__).resolve().parents[2]
helper = importlib.machinery.SourceFileLoader('m05lab', str(repo/'infra/egress/m05-lab.py')).load_module()


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def source_hashes():
    return {str(p.relative_to(repo)):digest(p) for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts and (p.suffix in ('.go','.sql','.py','.sh') or p.name in ('go.mod','go.sum'))}


def firewall_hash():
    doc = json.loads(subprocess.check_output(['/usr/sbin/nft','-j','list','ruleset']))
    def strip(value):
        if isinstance(value,dict):
            return {k:(0 if k in ('packets','bytes') else strip(v)) for k,v in value.items()}
        if isinstance(value,list):
            return [strip(v) for v in value]
        return value
    return hashlib.sha256(json.dumps(strip(doc),sort_keys=True).encode()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab',required=True)
    ap.add_argument('--cases',help='development subset; never full acceptance')
    args=ap.parse_args()
    if os.geteuid()!=0 or os.environ.get('M06_LAB_APPROVED')!='YES-I-AUTHORIZE-CLONE-LAB':
        ap.error('requires root and M06_LAB_APPROVED=YES-I-AUTHORIZE-CLONE-LAB')
    if subprocess.check_output(['systemd-detect-virt'],text=True).strip() not in ('kvm','qemu','vmware','microsoft','oracle'):
        raise RuntimeError('disposable VM required')
    lab=Path(args.lab)
    if lab.parent!=Path('/var/lib/orchestrator-builder') or not lab.name.startswith('m05-lab.'):
        raise RuntimeError('requires existing scoped M05 lab')
    helper.trusted(lab);helper.trusted(repo)
    if list((lab/'host').glob('*.raw')):
        raise RuntimeError('M05 guest disks remain; investigate')
    if shutil.disk_usage(lab).free<12*1024**3:
        raise RuntimeError('requires at least 12 GiB free')
    os.umask(0o077)
    stamp=str(time.time_ns())
    work=lab/('m06.'+stamp);work.mkdir(mode=0o700)
    print('M06 evidence:',work,flush=True)
    log=(work/'run.log').open('w')
    def run(argv,**kwargs):
        return subprocess.run(argv,check=True,stdout=log,stderr=log,**kwargs)
    base=json.loads((lab/'host/backend.json').read_text())
    baselines={str(p):p.read_bytes() for p in (lab/'host/backend.json',Path('/var/lib/orchestrator-builder/host/backend.json'))}
    host=work/'host';host.mkdir(mode=0o700)
    bindir=Path('/usr/local/libexec')/('m06.'+stamp);bindir.mkdir(mode=0o755);bindir.chmod(0o755)
    build_sources=source_hashes()
    binaries={'broker':bindir/'egress-broker','provisioner':work/'provisioner','runner':work/'clone-runner','tests':work/'provisioner.test','adapter':work/'clonejob.test'}
    for key,target in [('broker','./cmd/egress-broker'),('provisioner','./cmd/provisioner'),('runner','./cmd/clone-runner'),('tests','./internal/provisioner'),('adapter','./internal/clonejob')]:
        action=['test','-c'] if key in ('tests','adapter') else ['build']
        run(['/usr/local/go/bin/go']+action+['-o',str(binaries[key]),target],cwd=repo,env=dict(os.environ,CGO_ENABLED='0'))
    binaries['broker'].chmod(0o755);binaries['runner'].chmod(0o755)
    for name in ('build','origin'):
        run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(work/(name+'-ca-key.pem')),'-out',str(work/(name+'-ca.pem')),'-days','2','-subj','/CN=M06 isolated '+name+' CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
    names=['ok','rebind','private','metadata','infra','mixed','mapped','v6','badcert','dnsfail']
    run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(work/'origin-key.pem'),'-out',str(work/'origin.csr'),'-subj','/CN=ok.m06.example'])
    for cert,sans in [('origin.pem',','.join('DNS:'+n+'.m06.example' for n in names)),('wrong.pem','DNS:wrong.m06.example')]:
        ext=work/(cert+'.ext');ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+sans+'\n')
        run(['openssl','x509','-req','-in',str(work/'origin.csr'),'-CA',str(work/'origin-ca.pem'),'-CAkey',str(work/'origin-ca-key.pem'),'-CAcreateserial','-out',str(work/cert),'-days','1','-extfile',str(ext)])
    policy=work/'policy.json'
    policy.write_text(json.dumps({'version':1,'hosts':[n+'.m06.example' for n in names],'deny':['11.0.0.3/32'],'max_connections':4,'max_bytes':32<<20,'duration_seconds':90,'bytes_per_second':8<<20}))
    pins=dict(line.split('=',1) for line in subprocess.check_output([str(binaries['broker']),'-inspect','-policy',str(policy),'-ca-cert',str(work/'build-ca.pem')],text=True).splitlines())
    before=set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))
    run(['bash',str(repo/'infra/builder/build-lab-fixture.sh'),'clone'],cwd=repo,env=dict(os.environ,M04_IMAGE_BUILD='YES-I-AUTHORIZE-LOOP-IMAGE',M06_CA_CERT=str(work/'build-ca.pem'),M06_RUNNER=str(binaries['runner'])))
    new=set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))-before
    if len(new)!=1:
        raise RuntimeError('ambiguous image inventory')
    image=new.pop()/'fixture.raw'
    config=dict(base,root=str(host),image=str(image),digest='sha256:'+digest(image),template_id='build-m06-v1',executable=str(binaries['provisioner']),clone_enabled=True,egress_policy=str(policy),egress_policy_hash=pins['policy_hash'],egress_ca=str(work/'build-ca.pem'),egress_key=str(work/'build-ca-key.pem'),egress_ca_hash=pins['ca_sha256'],egress_resolver='127.0.0.56:53',broker_executable=str(binaries['broker']))
    (host/'backend.json').write_text(json.dumps(config,indent=2))
    original_firewall=firewall_hash()
    bundle=Path('/etc/ssl/certs/ca-certificates.crt');original_bundle=bundle.read_bytes()
    trust=Path('/usr/local/share/ca-certificates')/('m06.'+stamp+'.crt')
    addresses=('11.0.0.1/32','11.0.0.2/32','11.0.0.3/32','2003::11/128')
    existing=json.loads(subprocess.check_output(['ip','-j','addr','show','dev','lo']))
    current={a['local'] for entry in existing for a in entry.get('addr_info',[])}
    if trust.exists() or any(str(ipaddress.ip_interface(a).ip) in current for a in addresses):
        raise RuntimeError('foreign fixture resources already exist')
    fixture=None;added=[];result=None
    try:
        trust.write_bytes((work/'origin-ca.pem').read_bytes());trust.chmod(0o644);run(['update-ca-certificates'])
        for address in addresses:
            run(['ip','addr','add',address,'dev','lo']);added.append(address)
        fixture=subprocess.Popen(['/usr/bin/python3',str(repo/'infra/clone/fixture.py'),'--root',str(work)],stdout=log,stderr=log)
        for _ in range(100):
            if (work/'fixture-ready').exists():break
            if fixture.poll() is not None:raise RuntimeError('fixture failed')
            time.sleep(.1)
        else:raise RuntimeError('fixture startup timeout')
        env=dict(os.environ,M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM',M05_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-NETWORK',M06_DISPOSABLE_HOST='YES-I-AUTHORIZE-CLONE-LAB',M04_HOST_CONFIG=str(host/'backend.json'),M06_CAPTURE_DIR=str(work),M06_EXPECTED_SHAS=str(work/'expected-shas.json'),M06_CANARY_LOG=str(work/'canary.jsonl'))
        if args.cases:env['M06_CASES']=args.cases
        result=subprocess.run([str(binaries['tests']),'-test.v','-test.timeout=30m','-test.run','^TestRealCloneCorpus$' if args.cases else '^TestReal(Clone|BrokerForeignNetworkPreserved|BrokerSetupCrashRecovery|BrokerCreateCancellationRace)'],cwd=repo,env=env,stdout=log,stderr=log)
        adapter_result=None
        if not args.cases:
            adapter_result=subprocess.run([str(binaries['adapter']),'-test.v','-test.timeout=5m','-test.run','^TestRealCloneDurableAdapter$'],cwd=repo,env=env,stdout=log,stderr=log)
        log.flush()
        test_log=(work/'run.log').read_text()
        required_cases=set(json.loads((work/'expected-shas.json').read_text()))-{'stall-fetch'}
        required_cases.update(names[1:])
        if args.cases:required_cases=set(args.cases.split(','))
        passed_cases=set(re.findall(r'--- PASS: TestRealCloneCorpus/([^ ]+)',test_log))
        missing_cases=sorted(required_cases-passed_cases)
        skipped=bool(re.search(r'--- SKIP: TestReal',test_log))
        required_roots=['TestRealCloneCorpus'] if args.cases else ['TestRealCloneCorpus','TestRealCloneLifecycle','TestRealCloneDurableAdapter','TestRealBrokerForeignNetworkPreserved','TestRealBrokerSetupCrashRecovery','TestRealBrokerCreateCancellationRace']
        missing_roots=[name for name in required_roots if not re.search(r'^--- PASS: '+name+r' ',test_log,re.M)]
        events=[json.loads(line) for line in (work/'canary.jsonl').read_text().splitlines()] if (work/'canary.jsonl').exists() else []
        unexpected_dns=[e for e in events if e.get('kind')=='dns' and e.get('name') not in [n+'.m06.example' for n in names]]
        forbidden=[e for e in events if e.get('listener')=='denied' or 'redirect-target' in e.get('path','')]
        evidence={'exit_code':result.returncode,'adapter_exit_code':None if adapter_result is None else adapter_result.returncode,'subset':args.cases,'forbidden_arrivals':len(forbidden),'unexpected_dns_queries':len(unexpected_dns),'events':len(events),'passed_cases':sorted(passed_cases),'missing_cases':missing_cases,'skipped':skipped,'missing_roots':missing_roots,'template_digest':config['digest'],'binary_sha256':{k:digest(v) for k,v in binaries.items()},'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'source_sha256':build_sources,'source_unchanged_since_build':source_hashes()==build_sources,'versions':{name:subprocess.check_output(argv,text=True).strip() for name,argv in {'git':['git','--version'],'go':['/usr/local/go/bin/go','version'],'kernel':['uname','-r'],'qemu':['qemu-system-x86_64','--version']}.items()}}
        (work/'evidence.json').write_text(json.dumps(evidence,indent=2))
        print('Test exit:',result.returncode,'forbidden arrivals:',len(forbidden),flush=True)
        if not evidence['source_unchanged_since_build'] or result.returncode or forbidden or unexpected_dns or missing_cases or missing_roots or skipped or (adapter_result is not None and adapter_result.returncode):raise SystemExit(1)
    finally:
        if fixture is not None:
            fixture.terminate()
            try:fixture.wait(timeout=5)
            except subprocess.TimeoutExpired:fixture.kill();fixture.wait()
        for address in reversed(added):run(['ip','addr','del',address,'dev','lo'])
        if trust.exists():
            if trust.read_bytes()!=(work/'origin-ca.pem').read_bytes():raise RuntimeError('trust file changed; preserve')
            trust.unlink();run(['update-ca-certificates'])
        cleanup={'trust_restored':bundle.read_bytes()==original_bundle,'aliases_removed':True,'fixture_stopped':fixture is None or fixture.poll() is not None,'host_firewall_unchanged':firewall_hash()==original_firewall,'base_configs_unchanged':all(Path(p).read_bytes()==b for p,b in baselines.items()),'guest_disks_absent':not list(host.glob('*.raw'))}
        (work/'cleanup.json').write_text(json.dumps(cleanup,indent=2));print('Cleanup:',cleanup,flush=True)
        if not all(cleanup.values()):raise RuntimeError('cleanup unconfirmed; preserve evidence')


if __name__=='__main__':
    main()
