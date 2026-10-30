#!/usr/bin/env python3
"""Fail closed: M08 acceptance requires every named gate and executed subcase."""
import argparse, hashlib, json, re
from pathlib import Path
SOFTWARE={
 'internal/contracts':['TestConfigurationProtocolVersions'],
 'internal/policy':['TestNormalizationAndCanonicalIdentity','TestPlanSemanticDenials','TestFinalizationAdmissionAndOwnership','TestIndependentAgentPolicy','TestRuntimeInputsRemainOutsideBuild','TestBuiltImageSourceBinding'],
 'internal/storage':['TestConfigurationDurabilityAndFences'],
 'internal/provisioner':['TestBuildSerialFrameFencing','TestBuildBoottimeTimerRearm','TestConfigurationSerialFrameFencing'],
}
GUEST=['TestGuestComposeAccepted','TestGuestComposeDenials','TestGuestDockerfile','TestGuestRepositoryPaths','TestGuestServiceCount','TestGuestParserBudgetAndDiagnostics','TestGuestRepositoryCorpus','TestGuestPathRace','TestGuestNestedComposeContext']
M07=['success','build-timeout','cancelled','controller-loss','scanner-timeout','log-flood','disk-exhaustion','memory-exhaustion','pid-exhaustion','remote-source']
M08=['m08-dockerfile','m08-compose','m08-denied']
def status(log):
    result={}
    for outcome,name in re.findall(r'--- (PASS|FAIL|SKIP): ([A-Za-z0-9_/.-]+)',log):result.setdefault(name,set()).add(outcome)
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('software','checks','pipeline','output'):ap.add_argument('--'+name,required=True)
    args=ap.parse_args();cases=[]
    def case(name,passed,evidence):cases.append(dict(case=name,status='PASS' if passed else 'FAIL',evidence=str(evidence)))
    events=[json.loads(line) for line in Path(args.software).read_text().splitlines() if line.strip()]
    case('software-suite',not any(e.get('Action')=='fail' for e in events) and any(e.get('Action')=='pass' and not e.get('Test') for e in events),args.software)
    for package,roots in SOFTWARE.items():
        actual={e['Test']:e['Action'] for e in events if e.get('Package')=='dev-orchestrator/'+package and e.get('Test') and e.get('Action') in ('pass','fail','skip')}
        for root in roots:case(package+'/'+root,actual.get(root)=='pass',args.software)
        for name,outcome in actual.items():
            if '/' in name and name.split('/')[0] in roots:case(package+'/'+name,outcome=='pass',args.software)
    work=Path(args.pipeline);log=(work/'run.log').read_text();actual=status(log)
    for name in ['TestRealM07Pipeline','TestRealM08Pipeline']+['TestRealM07Pipeline/'+s for s in M07]+['TestRealM08Pipeline/'+s for s in M08]+GUEST:
        case(name,actual.get(name)=={'PASS'},work/'run.log')
    for name,outcomes in sorted(actual.items()):
        if '/' in name and name.split('/')[0] in GUEST:case(name,outcomes=={'PASS'},work/'run.log')
    case('guest-corpus-complete',log.count('M08-GUEST-EXIT tests=0 yaml=0 dockerfile=0')>=2 and 'M08-GUEST-EXIT tests=1' not in log,work/'run.log')
    case('isolated-parser-fuzzing',len(re.findall(r'execs: [1-9][0-9]*',log))>=4 and 'not built with coverage instrumentation' not in log and 'fuzzcachedir must be set' not in log,work/'run.log')
    evidence=json.loads((work/'evidence.json').read_text());cleanup=json.loads((work/'cleanup.json').read_text())
    for name,passed in {'pipeline-exit':evidence['exit_code']==0,'source-unchanged':evidence['source_unchanged'],'complete-nondebug-run':not evidence['debug'] and not evidence.get('development_cases'),'no-forbidden-arrivals':evidence['forbidden_arrivals']==0,'registry-pulls':evidence['registry_requests']>0,'no-required-skips':not evidence['skipped'],'owned-cleanup':bool(cleanup) and all(cleanup.values()),'packet-capture':(work/'traffic.pcap').stat().st_size>24,'one-service-spec':bool(re.search(r'M08 normalized spec sha256:[a-f0-9]{64} services 1',log)),'two-service-spec':bool(re.search(r'M08 normalized spec sha256:[a-f0-9]{64} services 2',log))}.items():case(name,passed,work/'evidence.json')
    checks=json.loads(Path(args.checks).read_text())
    for name in ('software-suite','go-vet','targeted-race','agent-fuzz','script-validation'):
        e=checks.get(name,{});p=Path(e.get('log','/nonexistent'));passed=e.get('exit_code')==0 and p.is_file()
        if passed:
            with p.open('rb') as f:passed=hashlib.file_digest(f,'sha256').hexdigest()==e.get('sha256')
        case(name,passed,args.checks)
    # A suite that silently drops whole subcase groups must not pass.
    case('minimum-corpus-coverage',sum(c['case'].startswith('TestGuestComposeDenials/') for c in cases)>=50 and sum(c['case'].startswith('TestGuestDockerfile/') for c in cases)>=18,work/'run.log')
    failed=[c['case'] for c in cases if c['status']!='PASS'];result=dict(milestone='P1-M08',status='PASS' if not failed else 'PENDING',cases=cases,counts={'PASS':len(cases)-len(failed),'FAIL':len(failed)},missing_or_failed=failed)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('status','counts','missing_or_failed')},indent=2));raise SystemExit(bool(failed))
if __name__=='__main__':main()
