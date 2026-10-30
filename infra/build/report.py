#!/usr/bin/env python3
"""Fail-closed M07 acceptance ledger from actual software/KVM outputs."""
import argparse,hashlib,json,re
from pathlib import Path
SOFTWARE={
 'internal/contracts':['TestBuildContractStrictness','TestBuildResultBoundIdentity','TestBuildAuthorizationStrict'],
 'internal/artifacts':['TestUploadQuarantine','TestUploadLimitsAndFencing','TestArtifactServiceControlAndUpload','TestQuarantineRetentionAndReservation','TestArtifactHostReserve'],
 'internal/builder':['TestDockerfileFixturePolicy'],
 'internal/storage':['TestBuildDurableAdmission','TestBuildTransactionFences','TestBuildExportRecoveryAndOutbox','TestBuildFailureAfterDeadline','TestCloneSchemaUpgradeRequiresVerifiedBackup'],
 'internal/buildjob':['TestWorkflowAdmissionAndFailure'],
 'internal/provisioner':['TestBuildSerialFrameFencing','TestBuildBoottimeTimerRearm']}
OCI=['plain','gzip','internal-symlink','internal-hardlink','safe-whiteout','traversal','absolute','duplicate','symlink','device','fifo','bad-digest','truncated','extra-blob','trailing','platform','root-user','diff-id','external-url','layer-traversal','layer-cycle','layer-ancestor','whiteout-link','suid','upload-limit','expanded-limit','entries','ratio','json-duplicate','blob-size','media-type','pax','gzip-truncated','gzip-concatenated','unreferenced-valid','case-alias','zero-user','uid-overflow']
SCAN=['clean','high-unfixed','critical','exception','wrong-digest','expired','unknown','missing-coverage','eol','stale-db','malformed']
PIPELINE=['success','build-timeout','cancelled','controller-loss','scanner-timeout','log-flood','disk-exhaustion','memory-exhaustion','pid-exhaustion','remote-source']
def statuses(log):
 result={}
 for outcome,name in re.findall(r'--- (PASS|FAIL|SKIP): ([A-Za-z0-9_/.-]+)',log):result.setdefault(name,set()).add(outcome)
 return result

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--software',required=True);ap.add_argument('--ingest-log',required=True);ap.add_argument('--pipeline',required=True);ap.add_argument('--output',required=True);ap.add_argument('--checks',required=True);args=ap.parse_args();cases=[]
 def case(name,passed,evidence):cases.append({'case':name,'status':'PASS' if passed else 'FAIL','evidence':str(evidence)})
 events=[json.loads(line) for line in Path(args.software).read_text().splitlines() if line.strip()]
 case('software-suite',not any(e.get('Action','').endswith('fail') for e in events),args.software)
 for package,roots in SOFTWARE.items():
  actual={e['Test']:e['Action'] for e in events if e.get('Package')=='dev-orchestrator/'+package and e.get('Test') and e.get('Action') in ('pass','fail','skip')}
  for root in roots:case(package+'/'+root,actual.get(root)=='pass',args.software)
  for name,outcome in actual.items():
   if '/' in name and name.split('/')[0] in roots:case(package+'/'+name,outcome=='pass',args.software)
 ingest=Path(args.ingest_log).read_text();istatus=statuses(ingest)
 for name in ['TestRealM07Ingest']+['TestRealM07Ingest/'+name for name in ('clean','vulnerable','malformed')]+['TestGuestOCIValidation/'+name for name in OCI]+['TestGuestScanPolicy/'+name for name in SCAN]+['TestGuestRealTrivy/'+name for name in ('clean','vulnerable')]:case(name,istatus.get(name)=={'PASS'},args.ingest_log)
 case('isolated-OCI-fuzz',any(int(n)>0 for n in re.findall(r'execs: (\d+)',ingest)) and 'fuzzcachedir must be set' not in ingest and 'not built with coverage instrumentation' not in ingest,args.ingest_log)
 work=Path(args.pipeline);pipeline=(work/'run.log').read_text();pstatus=statuses(pipeline)
 for name in ['TestRealM07Pipeline']+['TestRealM07Pipeline/'+name for name in PIPELINE]:case(name,pstatus.get(name)=={'PASS'},work/'run.log')
 evidence=json.loads((work/'evidence.json').read_text());cleanup=json.loads((work/'cleanup.json').read_text())
 for name,passed in {'pipeline-exit':evidence['exit_code']==0,'source-unchanged':evidence['source_unchanged'],'no-debug-wrapper':not evidence['debug'] and not evidence.get('development_cases'),'no-forbidden-arrivals':evidence['forbidden_arrivals']==0,'actual-registry-pulls':evidence['registry_requests']>0,'no-required-skips':not evidence['skipped'],'owned-cleanup':all(cleanup.values()),'packet-capture':(work/'traffic.pcap').stat().st_size>24}.items():case(name,passed,work/'evidence.json')
 checks=json.loads(Path(args.checks).read_text())
 for name in ('software-suite','go-vet','targeted-race','contract-fuzz','script-validation'):
  entry=checks.get(name,{});path=Path(entry.get('log','/nonexistent'));passed=entry.get('exit_code')==0 and path.is_file()
  if passed:
   with path.open('rb') as f:passed=hashlib.file_digest(f,'sha256').hexdigest()==entry.get('sha256')
  case(name,passed,args.checks)
 failed=[c['case'] for c in cases if c['status']!='PASS'];result={'milestone':'P1-M07','status':'PASS' if not failed else 'PENDING','cases':cases,'counts':{'PASS':len(cases)-len(failed),'FAIL':len(failed)},'missing_or_failed':failed}
 Path(args.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'counts':result['counts'],'failed':failed},indent=2));raise SystemExit(bool(failed))
if __name__=='__main__':main()
