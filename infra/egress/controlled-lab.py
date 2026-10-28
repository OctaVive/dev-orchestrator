#!/usr/bin/env python3
"""Opt-in controlled M05 lab. Synthetic public aliases never leave this VM.

Temporarily adds an owned CA to this isolated host's trust store, then removes
it and its loopback aliases in finally. Does not modify host firewall rules.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from importlib.machinery import SourceFileLoader
helper = SourceFileLoader('m05lab', str(Path(__file__).with_name('m05-lab.py'))).load_module()

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--lab', required=True)
a = ap.parse_args()
if os.geteuid() != 0 or os.environ.get('M05_LAB_APPROVED') != 'YES-I-AUTHORIZE-REAL-NETWORK':
    ap.error('requires explicit isolated-VM network lab approval and root')
lab = Path(a.lab)
if lab.parent != Path('/var/lib/orchestrator-builder') or not lab.name.startswith('m05-lab.'):
    ap.error('requires an existing scoped M05 lab')
helper.trusted(lab)
repo = Path(__file__).resolve().parents[2]
helper.trusted(repo)
host = lab / 'host'
if list(host.glob('*.raw')):
    raise RuntimeError('guest disk remains; recover before controlled tests')
config = json.loads((host / 'backend.json').read_text())
for journal in host.glob('*.json'):
    if journal.name == 'backend.json':
        continue
    network = json.loads(journal.read_text()).get('Value', {}).get('Network')
    if network and (Path('/run/netns') / network['Namespace']).exists():
        raise RuntimeError('owned namespace remains; investigate before reconfiguring lab')
os.umask(0o077)
work = lab / ('controlled.' + str(time.time_ns()))
work.mkdir(mode=0o700)
print('Controlled evidence:', work, flush=True)
log = (work / 'run.log').open('w')

def run(argv, **kwargs):
    return subprocess.run(argv, check=True, stdout=log, stderr=log, **kwargs)

def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def firewall_hash():
    doc = json.loads(subprocess.check_output(['/usr/sbin/nft', '-j', 'list', 'ruleset']))
    def strip(v):
        if isinstance(v, dict):
            return {k: (0 if k in ('packets', 'bytes') else strip(x)) for k, x in v.items()}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v
    return hashlib.sha256(json.dumps(strip(doc), sort_keys=True).encode()).hexdigest()

original_firewall = firewall_hash()
original_m04 = Path('/var/lib/orchestrator-builder/host/backend.json').read_bytes()
bundle_path = Path('/etc/ssl/certs/ca-certificates.crt')
original_bundle = bundle_path.read_bytes()
trust = Path('/usr/local/share/ca-certificates') / (lab.name + '-' + work.name + '.crt')
if trust.exists():
    raise RuntimeError('trust file collision')
addresses = ('11.0.0.1/32', '11.0.0.2/32', '11.0.0.3/32', '2003::11/128')
existing = json.loads(subprocess.check_output(['/usr/bin/ip', '-j', 'addr', 'show', 'dev', 'lo']))
current = {x['local'] for entry in existing for x in entry.get('addr_info', [])}
if any(str(ipaddress.ip_interface(x).ip) in current for x in addresses):
    raise RuntimeError('synthetic alias already exists; preserve foreign resources')
added, fixture = [], None
result = None
try:
    # Separate CA for upstream validation. The guest receives the existing
    # build CA only. Production trust policy has no test bypass or override.
    origin_ca, origin_key = work / 'origin-ca.pem', work / 'origin-ca-key.pem'
    run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(origin_key), '-out', str(origin_ca), '-days', '2', '-subj', '/CN=M05 controlled upstream fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    names = ['ok', 'v6', 'private', 'infra', 'mixed', 'mapped', 'rebind', 'dnsfail', 'badcert']
    run(['/usr/bin/openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(work / 'origin-key.pem'), '-out', str(work / 'origin.csr'), '-subj', '/CN=ok.m05.test'])
    for cert, sans in [('origin.pem', ','.join('DNS:' + x + '.m05.test' for x in names)), ('wrong.pem', 'DNS:wrong.m05.test')]:
        ext = work / (cert + '.ext')
        ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=' + sans + '\n')
        run(['/usr/bin/openssl', 'x509', '-req', '-in', str(work / 'origin.csr'), '-CA', str(origin_ca), '-CAkey', str(origin_key), '-CAcreateserial', '-out', str(work / cert), '-days', '1', '-extfile', str(ext)])
    trust.write_bytes(origin_ca.read_bytes())
    trust.chmod(0o644)
    run(['/usr/sbin/update-ca-certificates'])
    for address in addresses:
        run(['/usr/bin/ip', 'addr', 'add', address, 'dev', 'lo'])
        added.append(address)
    fixture = subprocess.Popen(['/usr/bin/python3', str(repo / 'infra/egress/controlled-fixture.py'), '--root', str(work)], stdout=log, stderr=log)
    for _ in range(100):
        if (work / 'fixture-ready').exists():
            break
        if fixture.poll() is not None:
            raise RuntimeError('controlled DNS/HTTPS fixture failed')
        time.sleep(.1)
    else:
        raise RuntimeError('fixture startup timed out')
    broker, provisioner, testbin = Path(config['broker_executable']), Path(config['executable']), lab / 'provisioner.test'
    for binary, target, action in ((broker, './cmd/egress-broker', ['build']), (provisioner, './cmd/provisioner', ['build']), (testbin, './internal/provisioner', ['test', '-c'])):
        helper.trusted(binary)
        run(['/usr/local/go/bin/go'] + action + ['-o', str(binary), target], cwd=repo)
    broker.chmod(0o755)
    raw = work / 'm05-raw-probe'
    run(['/usr/local/go/bin/go', 'build', '-o', str(raw), './tests/fixtures/egress-probe'], cwd=repo, env=dict(os.environ, CGO_ENABLED='0'))
    policy = work / 'policy.json'
    policy.write_text(json.dumps({'version': 1, 'hosts': [x + '.m05.test' for x in names], 'deny': ['11.0.0.3/32'], 'max_connections': 4, 'max_bytes': 1048576, 'duration_seconds': 30, 'bytes_per_second': 1048576}))
    pins = dict(line.split('=', 1) for line in subprocess.check_output([str(broker), '-inspect', '-policy', str(policy), '-ca-cert', config['egress_ca']], text=True).splitlines())
    before = set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))
    env = dict(os.environ, M04_IMAGE_BUILD='YES-I-AUTHORIZE-LOOP-IMAGE', M05_CA_CERT=config['egress_ca'], M05_PROBE_HOST='ok.m05.test', M05_CONTROL_IP='11.0.0.1', M05_CONTROLLED='YES', M05_RAW_PROBE=str(raw))
    run(['bash', str(repo / 'infra/builder/build-lab-fixture.sh'), 'egress'], cwd=repo, env=env)
    new = set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*')) - before
    if len(new) != 1:
        raise RuntimeError('ambiguous fixture image inventory')
    image = new.pop() / 'fixture.raw'
    config.update(image=str(image), digest='sha256:' + digest(image), egress_policy=str(policy), egress_policy_hash=pins['policy_hash'], egress_resolver='127.0.0.55:53')
    (host / 'backend.json').write_text(json.dumps(config, indent=2))
    env = dict(os.environ, M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM', M05_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-NETWORK', M04_HOST_CONFIG=str(host / 'backend.json'), M05_CAPTURE_DIR=str(work), M05_CANARY_LOG=str(work / 'canary.jsonl'), M05_LAB_MODE_FILE=str(work / 'guest-mode.json'))
    result = subprocess.run([str(testbin), '-test.v', '-test.run', '^TestRealBroker(NetworkLifecycle|IndependentExpiry|SetupCrashRecovery|ForeignNetworkPreserved|PolicyFailureAndGuardRecovery|CreateCancellationRace|TransferCancellation)$'], cwd=repo, env=env, stdout=log, stderr=log)
    events = [json.loads(x) for x in (work / 'canary.jsonl').read_text().splitlines()]
    forbidden = [e for e in events if e['kind'] == 'udp' or e.get('listener') in ('private-denied', 'infra-denied') or (e['kind'] == 'http' and any(x in e.get('path', '') for x in ('rebound-target', 'mixed-target', 'mapped-target', 'redirect-target', 'infra-target', 'private-target', 'during-dns-outage', 'after-broker-stop', 'reuse-second', 'wrong-authority-target', 'oversized-request')))]
    evidence = {'exit_code': result.returncode, 'canary_events': len(events), 'forbidden_arrivals': len(forbidden), 'controlled_origin': True, 'policy_hash': pins['policy_hash'], 'template_digest': config['digest'], 'binary_sha256': {str(p): digest(p) for p in (broker, provisioner, testbin)}, 'original_m04_config_unchanged': Path('/var/lib/orchestrator-builder/host/backend.json').read_bytes() == original_m04}
    if forbidden:
        evidence['result'] = 'FAIL: forbidden destination arrivals'
    (work / 'evidence.json').write_text(json.dumps(evidence, indent=2))
    print('Controlled test exit:', result.returncode, 'forbidden arrivals:', len(forbidden), flush=True)
    if result.returncode or forbidden:
        raise SystemExit(1)
finally:
    if fixture is not None:
        fixture.terminate()
        try:
            fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.wait()
    for address in reversed(added):
        run(['/usr/bin/ip', 'addr', 'del', address, 'dev', 'lo'])
    if trust.exists():
        if trust.read_bytes() != (work / 'origin-ca.pem').read_bytes():
            raise RuntimeError('trust file changed; preserve and investigate')
        trust.unlink()
        run(['/usr/sbin/update-ca-certificates'])
    restored = bundle_path.read_bytes() == original_bundle
    (work / 'cleanup.json').write_text(json.dumps({'temporary_trust_removed': not trust.exists(), 'trust_bundle_restored': restored, 'loopback_aliases_removed': True, 'fixture_stopped': fixture is None or fixture.poll() is not None, 'host_firewall_unchanged': firewall_hash() == original_firewall}, indent=2))
    print('Temporary trust restored:', restored, 'evidence:', work, flush=True)
    if not restored:
        raise RuntimeError('trust bundle differs from baseline; investigate')
