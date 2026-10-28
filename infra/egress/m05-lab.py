#!/usr/bin/env python3
"""Explicit opt-in M05 KVM smoke; separate state, keys, binaries, no M04 overwrite.

Run only after reviewing this script on the approved disposable Debian KVM host.
No packages are installed, existing service/config files are never replaced.
All lab artifacts and logs are retained for operator review.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def trusted(path):
    p = Path(path)
    while True:
        s = p.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise RuntimeError('untrusted lab path')
        if p == p.parent:
            break
        p = p.parent


def retest(repo, lab):
    lab = Path(lab)
    if lab.parent != Path('/var/lib/orchestrator-builder') or not lab.name.startswith('m05-lab.'):
        raise RuntimeError('only a scoped M05 lab can be retested')
    trusted(lab)
    host = lab / 'host'
    config = json.loads((host / 'backend.json').read_text())
    if config['root'] != str(host) or config['executable'] != str(lab / 'orchestrator-provisioner') or config['broker_executable'] != str(Path('/usr/local/libexec') / lab.name / 'egress-broker'):
        raise RuntimeError('lab executable identity mismatch')
    if list(host.glob('*.raw')):
        raise RuntimeError('guest disks remain; investigate before rebuilding lab binaries')
    for journal in host.glob('*.json'):
        if journal.name == 'backend.json':
            continue
        record = json.loads(journal.read_text())
        network = record.get('Value', {}).get('Network')
        if network and (Path('/run/netns') / network['Namespace']).exists():
            raise RuntimeError('lab namespace remains; recover before retest')
    stamp = str(time.time_ns())
    logpath = lab / ('retest.' + stamp + '.log')
    print('Retest log:', logpath, flush=True)
    original_path = Path('/var/lib/orchestrator-builder/host/backend.json')
    original = original_path.read_bytes()
    binaries = [Path(config['broker_executable']), Path(config['executable']), lab / 'provisioner.test']
    with logpath.open('w') as log:
        for binary, target in zip(binaries, ('./cmd/egress-broker', './cmd/provisioner', './internal/provisioner')):
            trusted(binary)
            action = ['test', '-c'] if target == './internal/provisioner' else ['build']
            run(['/usr/local/go/bin/go'] + action + ['-o', str(binary), target], cwd=repo, stdout=log, stderr=log)
        binaries[0].chmod(0o755)
        env = dict(os.environ, M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM', M05_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-NETWORK', M04_HOST_CONFIG=str(host / 'backend.json'))
        result = subprocess.run([str(binaries[2]), '-test.v', '-test.run', '^TestRealBroker(NetworkLifecycle|IndependentExpiry|SetupCrashRecovery|ForeignNetworkPreserved)$'], cwd=repo, env=env, stdout=log, stderr=log)
    evidence = {'binary_sha256': {str(p): hashlib.file_digest(p.open('rb'), 'sha256').hexdigest() for p in binaries}, 'exit_code': result.returncode, 'original_m04_config_unchanged': original_path.read_bytes() == original, 'acceptance': 'pending full capture/canary matrix'}
    (lab / ('retest.' + stamp + '.json')).write_text(json.dumps(evidence, indent=2))
    print('Retest exit:', result.returncode, 'log:', logpath, flush=True)
    raise SystemExit(result.returncode)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--configure-and-test', action='store_true')
    ap.add_argument('--retest', help='rebuild and retest a clean scoped M05 lab')
    ap.add_argument('--origin', help='approved public HTTPS smoke origin')
    ap.add_argument('--resolver', help='dedicated public resolver IPv4, TCP/53')
    args = ap.parse_args()
    if not (args.configure_and_test or args.retest) or os.geteuid() != 0 or os.environ.get('M05_LAB_APPROVED') != 'YES-I-AUTHORIZE-REAL-NETWORK':
        ap.error('requires root, --configure-and-test and M05_LAB_APPROVED=YES-I-AUTHORIZE-REAL-NETWORK')
    if subprocess.check_output(['systemd-detect-virt'], text=True).strip() not in ('kvm', 'qemu', 'vmware', 'microsoft', 'oracle'):
        raise RuntimeError('disposable VM required')
    repo = Path(__file__).resolve().parents[2]
    trusted(repo)
    if args.retest:
        retest(repo, args.retest)
    if not args.origin or not args.resolver:
        ap.error("--origin and --resolver are required for new lab setup")
    for path in ('/dev/kvm', '/dev/net/tun', '/usr/bin/ip', '/usr/sbin/nft', '/usr/bin/curl', '/usr/bin/openssl', '/usr/sbin/grub-install'):
        if not Path(path).exists():
            raise RuntimeError('missing prerequisite: ' + path)
    # Fail before installation if the explicitly selected resolver is unreachable.
    import ipaddress
    resolver = ipaddress.IPv4Address(args.resolver)
    if not resolver.is_global:
        raise RuntimeError('smoke resolver must be an explicitly selected public resolver')
    with socket.create_connection((str(resolver), 53), timeout=5):
        pass
    public = [x[4][0] for x in socket.getaddrinfo(args.origin, 443, socket.AF_INET, socket.SOCK_STREAM)]
    if not public or not all(ipaddress.ip_address(x).is_global for x in public):
        raise RuntimeError('origin must resolve to public IPv4 controls')
    parent = Path('/var/lib/orchestrator-builder')
    trusted(parent)
    if shutil.disk_usage(parent).free < 12 * 1024**3:
        raise RuntimeError("requires at least 12 GiB free for the fixed guest disk")
    os.umask(0o077)
    lab = Path(tempfile.mkdtemp(prefix='m05-lab.', dir=parent))
    print('Retained private lab:', lab, flush=True)
    log = (lab / 'run.log').open('w')
    original_config = Path('/var/lib/orchestrator-builder/host/backend.json')
    original = original_config.read_bytes()
    base = json.loads(original)
    host = lab / 'host'
    host.mkdir(mode=0o700)
    binparent = Path('/usr/local/libexec')
    if not binparent.exists():
        binparent.mkdir(mode=0o755)
        binparent.chmod(0o755)
    trusted(binparent)
    bindir = binparent / lab.name
    bindir.mkdir(mode=0o755)
    bindir.chmod(0o755)
    broker = bindir / 'egress-broker'
    provisioner = lab / 'orchestrator-provisioner'
    testbin = lab / 'provisioner.test'
    for argv in (
        ['/usr/local/go/bin/go', 'build', '-o', str(broker), './cmd/egress-broker'],
        ['/usr/local/go/bin/go', 'build', '-o', str(provisioner), './cmd/provisioner'],
        ['/usr/local/go/bin/go', 'test', '-c', '-o', str(testbin), './internal/provisioner'],
    ):
        run(argv, cwd=repo, stdout=log, stderr=log)
    broker.chmod(0o755)
    for p in (provisioner, testbin):
        p.chmod(0o700)
    # Dedicated account only; never modify an existing account's ownership/groups.
    import pwd
    try:
        account = pwd.getpwnam('orchestrator-egress')
    except KeyError:
        run(['/usr/sbin/adduser', '--system', '--group', '--no-create-home', '--home', '/nonexistent', '--shell', '/usr/sbin/nologin', 'orchestrator-egress'], stdout=log, stderr=log)
        account = pwd.getpwnam('orchestrator-egress')
    if account.pw_uid < 100 or account.pw_uid == base['uid']:
        raise RuntimeError('invalid dedicated broker account')
    ca = lab / 'ca.pem'
    key = lab / 'ca-key.pem'
    run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(key), '-out', str(ca), '-days', '3', '-subj', '/CN=M05 disposable lab build CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], stdout=log, stderr=log)
    ca.chmod(0o600)
    key.chmod(0o600)
    policy = lab / 'policy.json'
    policy.write_text(json.dumps({'version': 1, 'hosts': [args.origin], 'deny': [], 'max_connections': 4, 'max_bytes': 1048576, 'duration_seconds': 30, 'bytes_per_second': 1048576}))
    pins = dict(line.split('=', 1) for line in subprocess.check_output([str(broker), '-inspect', '-policy', str(policy), '-ca-cert', str(ca)], text=True).splitlines())
    before = set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*'))
    env = dict(os.environ, M04_IMAGE_BUILD='YES-I-AUTHORIZE-LOOP-IMAGE', M05_CA_CERT=str(ca), M05_PROBE_HOST=args.origin, M05_CONTROL_IP=public[0])
    run(['bash', str(repo / 'infra/builder/build-lab-fixture.sh'), 'egress'], cwd=repo, env=env, stdout=log, stderr=log)
    new = set(Path('/var/lib/orchestrator-builder/image-build').glob('fixture.*')) - before
    if len(new) != 1:
        raise RuntimeError('ambiguous fixture inventory; retain all artifacts')
    image = new.pop() / 'fixture.raw'
    digest = hashlib.file_digest(image.open("rb"), "sha256").hexdigest()
    ns = Path('/run/netns')
    if not ns.exists():
        ns.mkdir(mode=0o755)
        ns.chmod(0o755)
    trusted(ns)
    config = dict(base, root=str(host), image=str(image), digest='sha256:' + digest, template_id='build-m05-lab-v1', executable=str(provisioner), network_mode='broker-v1', egress_policy=str(policy), egress_policy_hash=pins['policy_hash'], egress_ca=str(ca), egress_key=str(key), egress_ca_hash=pins['ca_sha256'], egress_resolver=str(resolver)+':53', broker_executable=str(broker), broker_uid=account.pw_uid, broker_gid=account.pw_gid)
    (host / 'backend.json').write_text(json.dumps(config, indent=2))
    evidence = {'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'origin': args.origin, 'controlled_origin': False, 'resolver': str(resolver), 'template_digest': digest, 'policy_hash': pins['policy_hash'], 'binary_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (broker, provisioner, testbin)}, 'acceptance': 'pending full capture/canary matrix'}
    (lab / 'evidence.json').write_text(json.dumps(evidence, indent=2))
    env = dict(os.environ, M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM', M05_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-NETWORK', M04_HOST_CONFIG=str(host / 'backend.json'))
    result = subprocess.run([str(testbin), '-test.v', '-test.run', '^TestRealBroker(NetworkLifecycle|IndependentExpiry|SetupCrashRecovery|ForeignNetworkPreserved)$'], cwd=repo, env=env, stdout=log, stderr=log)
    evidence['smoke_exit_code'] = result.returncode
    evidence['original_m04_config_unchanged'] = original_config.read_bytes() == original
    (lab / 'evidence.json').write_text(json.dumps(evidence, indent=2))
    print('Smoke exit:', result.returncode, 'log:', lab / 'run.log', flush=True)
    print('M04 config unchanged:', evidence['original_m04_config_unchanged'], flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
