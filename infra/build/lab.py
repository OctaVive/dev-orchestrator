#!/usr/bin/env python3
"""Opt-in isolated M07 pipeline lab; never enables production services."""
import argparse,hashlib,importlib.machinery,json,os,re,subprocess,time
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
clone=importlib.machinery.SourceFileLoader('m06',str(repo/'infra/clone/lab.py')).load_module()
def sources():
 result=clone.source_hashes();result['infra/build/tools.lock.json']=clone.digest(repo/'infra/build/tools.lock.json');return result
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--lab',required=True);ap.add_argument('--tools',required=True);ap.add_argument('--ingest-config',required=True);ap.add_argument('--debug',action='store_true');ap.add_argument('--cases');args=ap.parse_args()
 if os.geteuid()!=0 or os.environ.get('M07_LAB_APPROVED')!='YES-I-AUTHORIZE-BUILD-LAB':ap.error('root and explicit M07 lab opt-in required')
 if subprocess.check_output(['systemd-detect-virt'],text=True).strip() not in ('kvm','qemu','vmware','microsoft','oracle'):raise RuntimeError('disposable host required')
 lab=Path(args.lab);clone.helper.trusted(lab);clone.helper.trusted(repo)
 os.umask(0o077);work=lab/('m07.'+str(time.time_ns()));work.mkdir(mode=0o700);print('M07 evidence:',work,flush=True)
 source=sources();log=(work/'run.log').open('w');run=lambda argv,**kw:subprocess.run(argv,check=True,stdout=log,stderr=log,**kw)
 for name in ('builder','scanner','quarantine','artifacts'): (work/name).mkdir(mode=0o700)
 bindir=Path('/usr/local/libexec')/work.name;bindir.mkdir(mode=0o755);bindir.chmod(0o755)
 bins={name:(bindir/name if name=='egress-broker' else work/name) for name in ('provisioner','clone-runner','egress-broker','artifact-service','pipeline.test')}
 for name,target in [('provisioner','./cmd/provisioner'),('clone-runner','./cmd/clone-runner'),('egress-broker','./cmd/egress-broker'),('artifact-service','./cmd/artifact-service'),('pipeline.test','./internal/buildjob')]:
  run(['/usr/local/go/bin/go']+(['test','-c'] if name.endswith('.test') else ['build'])+['-o',str(bins[name]),target],cwd=repo,env=dict(os.environ,CGO_ENABLED='0'))
 bins['egress-broker'].chmod(0o755)
 for name in ('build','origin'):
  run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(work/(name+'-ca-key.pem')),'-out',str(work/(name+'-ca.pem')),'-days','2','-subj','/CN=M07 isolated '+name+' CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'])
 names=['ok','rebind','private','metadata','infra','mixed','mapped','v6','badcert','dnsfail','ingest']
 run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(work/'origin-key.pem'),'-out',str(work/'origin.csr'),'-subj','/CN=ok.m06.example'])
 for cert,sans in [('origin.pem',','.join('DNS:'+n+'.m06.example' for n in names)),('wrong.pem','DNS:wrong.m06.example')]:
  ext=work/(cert+'.ext');ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+sans+'\n')
  run(['openssl','x509','-req','-in',str(work/'origin.csr'),'-CA',str(work/'origin-ca.pem'),'-CAkey',str(work/'origin-ca-key.pem'),'-CAcreateserial','-out',str(work/cert),'-days','1','-extfile',str(ext)])
 policy=work/'policy.json';policy.write_text(json.dumps({'version':1,'hosts':[n+'.m06.example' for n in names],'deny':['11.0.0.3/32'],'max_connections':8,'max_bytes':256<<20,'duration_seconds':180,'bytes_per_second':8<<20}))
 pins=dict(line.split('=',1) for line in subprocess.check_output([str(bins['egress-broker']),'-inspect','-policy',str(policy),'-ca-cert',str(work/'build-ca.pem')],text=True).splitlines())
 before=set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))
 run(['bash',str(repo/'infra/builder/build-lab-fixture.sh'),'build'],cwd=repo,env=dict(os.environ,M04_IMAGE_BUILD='YES-I-AUTHORIZE-LOOP-IMAGE',M06_CA_CERT=str(work/'build-ca.pem'),M06_RUNNER=str(bins['clone-runner']),M07_TOOLS=args.tools,M07_BUILD_DEBUG='YES' if args.debug else 'NO'))
 new=set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))-before
 if len(new)!=1:raise RuntimeError('ambiguous template inventory')
 image=new.pop()/'fixture.raw'
 base=json.loads((lab/'host/backend.json').read_text());config=dict(base,root=str(work/'builder'),image=str(image),digest='sha256:'+clone.digest(image),template_id='build-m07-v1',executable=str(bins['provisioner']),clone_enabled=True,egress_policy=str(policy),egress_policy_hash=pins['policy_hash'],egress_ca=str(work/'build-ca.pem'),egress_key=str(work/'build-ca-key.pem'),egress_ca_hash=pins['ca_sha256'],egress_resolver='127.0.0.56:53',broker_executable=str(bins['egress-broker']))
 (work/'builder/backend.json').write_text(json.dumps(config))
 scanner=json.loads(Path(args.ingest_config).read_text());scanner.update(root=str(work/'scanner'),artifact_root=str(work/'quarantine'),executable=str(bins['provisioner']))
 (work/'scanner/backend.json').write_text(json.dumps(scanner));(work/'m07-enabled').write_text('yes')
 original_firewall=clone.firewall_hash();bundle=Path('/etc/ssl/certs/ca-certificates.crt');original_bundle=bundle.read_bytes();trust=Path('/usr/local/share/ca-certificates')/(work.name+'.crt')
 addresses=('11.0.0.1/32','11.0.0.2/32','11.0.0.3/32','11.0.0.4/32','2003::11/128');added=[];fixture=None;service=None;capture=None
 try:
  trust.write_bytes((work/'origin-ca.pem').read_bytes());trust.chmod(0o644);run(['update-ca-certificates'])
  for address in addresses:run(['ip','addr','add',address,'dev','lo']);added.append(address)
  fixture=subprocess.Popen(['/usr/bin/python3',str(repo/'infra/clone/fixture.py'),'--root',str(work)],stdout=log,stderr=log)
  service=subprocess.Popen([str(bins['artifact-service']),'-quarantine',str(work/'quarantine'),'-artifacts',str(work/'artifacts'),'-control',str(work/'control.sock'),'-listen','11.0.0.4:443','-cert',str(work/'origin.pem'),'-key',str(work/'origin-key.pem')],stdout=log,stderr=log)
  for _ in range(100):
   if (work/'fixture-ready').exists() and (work/'control.sock').exists():break
   if fixture.poll() is not None or service.poll() is not None:raise RuntimeError('fixture/service startup failure')
   time.sleep(.1)
  else:raise RuntimeError('fixture startup timeout')
  capture=subprocess.Popen([str(Path(args.tools)/'pcap/usr/bin/tcpdump'),'-Z','root','-i','any','-U','-c','20000','-w',str(work/'traffic.pcap'),'net 192.0.2.0/30 or net 11.0.0.0/24'],stdout=log,stderr=log,env=dict(os.environ,LD_LIBRARY_PATH=str(Path(args.tools)/'pcap/usr/lib/x86_64-linux-gnu')))
  env=dict(os.environ,M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM',M07_DISPOSABLE_HOST='YES-I-AUTHORIZE-BUILD-LAB',M04_HOST_CONFIG=str(work/'builder/backend.json'),M07_INGEST_CONFIG=str(work/'scanner/backend.json'),M07_CONTROL=str(work/'control.sock'),M07_ARTIFACT_ROOT=str(work/'artifacts'),M07_TOOLS_LOCK=str(repo/'infra/build/tools.lock.json'),M07_TRIVY=str(Path(args.tools)/'trivy/trivy'))
  result=subprocess.run([str(bins['pipeline.test']),'-test.v','-test.timeout=10m','-test.run','^TestRealM07Pipeline$' if not args.cases else '^TestRealM07Pipeline/('+args.cases.replace(',','|')+')$'],cwd=repo,env=env,stdout=log,stderr=log);log.flush()
  events=[json.loads(line) for line in (work/'canary.jsonl').read_text().splitlines()] if (work/'canary.jsonl').exists() else []
  forbidden=[e for e in events if e.get('listener')=='denied' or 'remote-target' in e.get('path','')];registry=[e for e in events if e.get('kind')=='registry']
  evidence={'debug':args.debug,'development_cases':args.cases,'exit_code':result.returncode,'source_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'source_sha256':source,'source_unchanged':source==sources(),'binary_sha256':{k:clone.digest(v) for k,v in bins.items()},'builder_template':config['digest'],'scanner_template':scanner['digest'],'database_image':scanner['ingest_database_digest'],'forbidden_arrivals':len(forbidden),'registry_requests':len(registry),'skipped':'--- SKIP:' in (work/'run.log').read_text()}
  evidence['versions']={name:subprocess.check_output(argv,text=True).strip() for name,argv in {'go':['/usr/local/go/bin/go','version'],'kernel':['uname','-r'],'qemu':['/usr/bin/qemu-system-x86_64','--version'],'buildkit':[str(Path(args.tools)/'buildkit/bin/buildkitd'),'--version'],'trivy':[str(Path(args.tools)/'trivy/trivy'),'--version']}.items()}
  (work/'evidence.json').write_text(json.dumps(evidence,indent=2));print(evidence['exit_code'],flush=True)
  if args.cases or result.returncode or forbidden or not registry or evidence['skipped'] or not evidence['source_unchanged']:raise SystemExit(1)
 finally:
  for proc in (capture,service,fixture):
   if proc is not None:
    proc.terminate()
    try:proc.wait(timeout=5)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
  for address in reversed(added):run(['ip','addr','del',address,'dev','lo'])
  if trust.exists():trust.unlink();run(['update-ca-certificates'])
  cleanup={'trust_restored':bundle.read_bytes()==original_bundle,'firewall_unchanged':clone.firewall_hash()==original_firewall,'guest_disks_absent':not list((work/'builder').glob('*.raw')) and not list((work/'scanner').glob('*.raw'))}
  (work/'cleanup.json').write_text(json.dumps(cleanup,indent=2));print('Cleanup:',cleanup,flush=True)
  if not all(cleanup.values()):raise RuntimeError('cleanup unconfirmed')
if __name__=='__main__':main()
