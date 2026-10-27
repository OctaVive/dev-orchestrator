#!/usr/bin/env python3
"""Provision a FRESH disposable Debian/Ubuntu VM and run automated M04 cases.

Run as normal user: python3 infra/builder/m04-auto-lab.py --configure-and-test
Requires sudo, working Linux Go >= go.mod on PATH, nested KVM, and a bootable
running kernel with matching modules. This is NOT the complete V01–V16 matrix.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    if sys.argv[1:] != ['--configure-and-test'] or os.geteuid() == 0:
        raise SystemExit(__doc__)
    os.umask(0o077)
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    virt = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True)
    if virt.returncode or virt.stdout.strip() in ('', 'none'):
        raise SystemExit('Refusing setup outside a detected VM. Create a disposable lab VM first.')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('Requires systemd PID 1.')
    if os.uname().machine != 'x86_64' or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('Requires x86-64 and user-accessible nested /dev/kvm.')
    if not shutil.which('apt-get') or not shutil.which('go'):
        raise SystemExit('Requires apt-get and Go >= go.mod on PATH; compiler runs without sudo.')
    kernel = os.uname().release
    if not Path('/lib/modules', kernel, 'kernel').is_dir():
        raise SystemExit('Missing running-kernel modules. Install a distribution kernel and reboot first.')
    if os.cpu_count() < 4:
        raise SystemExit('Allocate at least four vCPUs.')
    mem = int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text())[1])
    if mem < 7_500_000 or shutil.disk_usage('/var/lib').free < 30 * 1024**3:
        raise SystemExit('Requires approximately 8 GiB RAM and 30 GiB free /var/lib storage.')
    evidence = Path(tempfile.mkdtemp(prefix='m04-auto-', dir=Path.home()))
    print('Private evidence:', evidence, flush=True)
    env = os.environ.copy()
    env.update(GOTOOLCHAIN='local', CGO_ENABLED='0')
    counter = 0

    def run(*args, privileged=False):
        nonlocal counter
        counter += 1
        cmd = (['sudo', '--'] if privileged else []) + list(map(str, args))
        print('+', ' '.join(cmd), flush=True)
        with (evidence / f'{counter:02d}.log').open('w') as log:
            log.write('+ ' + ' '.join(cmd) + '\n'); log.flush()
            result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
            log.write(f'\nexit_code={result.returncode}\n')
        if result.returncode:
            raise RuntimeError(f'Command failed; inspect {log.name}. No global cleanup attempted.')
        return Path(log.name).read_text()

    run('git', 'rev-parse', 'HEAD')
    run('git', 'status', '--short')
    run('go', 'version')
    run('go', 'mod', 'download')
    run('go', 'mod', 'verify')
    binaries = evidence / 'bin'; binaries.mkdir(mode=0o700)
    run('go', 'build', '-o', binaries / 'orchestrator-provisioner', './cmd/provisioner')
    run('go', 'test', '-c', '-o', binaries / 'm04-host.test', './internal/provisioner')
    print('This installs packages and privileged test files in this disposable VM.', flush=True)
    run('true', privileged=True)
    # Refuse reuse BEFORE installing anything. Existing or partial labs need review.
    run('python3', '-c', "import os; paths=['/var/lib/orchestrator-builder','/usr/local/sbin/orchestrator-provisioner','/usr/local/libexec/m04-host.test','/usr/local/libexec/m04-build-lab-fixture']; assert not any(os.path.lexists(p) for p in paths), 'Existing lab detected; refusing overwrite'", privileged=True)
    run('apt-get', 'update', privileged=True)
    run('apt-get', 'install', '-y', 'qemu-system-x86', 'qemu-utils', 'systemd',
        'busybox-static', 'grub-pc-bin', 'grub2-common', 'fdisk', 'e2fsprogs',
        'cpio', 'kmod', 'python3', 'fio', privileged=True)
    run('test', '-f', f'/boot/vmlinuz-{kernel}', privileged=True)
    run('adduser', '--system', '--group', '--no-create-home', '--home', '/nonexistent',
        '--shell', '/usr/sbin/nologin', 'orchestrator-qemu', privileged=True)
    base = Path('/var/lib/orchestrator-builder')
    run('install', '-d', '-m', '0700', base, base / 'host', base / 'images', base / 'ledger', privileged=True)
    run('install', '-d', '-m', '0755', '/usr/local/sbin', '/usr/local/libexec', privileged=True)
    for source, target, mode in [
        (binaries / 'orchestrator-provisioner', '/usr/local/sbin/orchestrator-provisioner', '0755'),
        (binaries / 'm04-host.test', '/usr/local/libexec/m04-host.test', '0755'),
        (root / 'infra/builder/build-lab-fixture.sh', '/usr/local/libexec/m04-build-lab-fixture', '0700'),
    ]:
        run('install', '-o', 'root', '-g', 'root', '-m', mode, source, target, privileged=True)
        run('sha256sum', target, privileged=True)
    run('env', 'M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE',
        '/usr/local/libexec/m04-build-lab-fixture', 'idle', privileged=True)
    # Locate exactly one newly built image; never accept a path from guest output.
    setup = '''import glob, hashlib, json, os, pwd, shutil
from pathlib import Path
images=glob.glob('/var/lib/orchestrator-builder/image-build/fixture.*/fixture.raw')
assert len(images)==1, images
image=Path('/var/lib/orchestrator-builder/images/build-linux-v1.raw')
shutil.copyfile(images[0], image); image.chmod(0o600)
account=pwd.getpwnam('orchestrator-qemu')
assert account.pw_uid != 0 and account.pw_gid != 0
config=dict(root='/var/lib/orchestrator-builder/host', image=str(image),
 digest='sha256:'+hashlib.sha256(image.read_bytes()).hexdigest(), template_id='build-linux-v1',
 executable='/usr/local/sbin/orchestrator-provisioner', qemu='/usr/bin/qemu-system-x86_64',
 uid=account.pw_uid, gid=account.pw_gid, kvm_gid=os.stat('/dev/kvm').st_gid)
path=Path('/var/lib/orchestrator-builder/host/backend.json')
with path.open('x') as f: json.dump(config,f,indent=2)
path.chmod(0o600)
print(json.dumps(config,indent=2))
'''
    run('python3', '-c', setup, privileged=True)
    env.update(EVIDENCE=str(evidence), M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM')
    run('bash', root / 'infra/builder/m04-acceptance.sh', 'host-tests')
    (evidence / 'RESULT.txt').write_text(
        'Automated four-case real-host subset PASS. Full M04 NOT PASSED: '
        'remaining V01–V16 workload/fault matrix and sign-off required.\n')
    print('Automated subset passed. Full M04 still requires the V01–V16 matrix.', flush=True)
    print('Lab packages, configuration, images and audit tombstones retained:', evidence)


if __name__ == '__main__':
    main()
