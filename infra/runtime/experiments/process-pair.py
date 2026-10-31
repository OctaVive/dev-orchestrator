#!/usr/bin/env python3
"""Run two disposable VMs over an inherited socketpair, with no host NIC/route.
Roots must already contain reviewed binaries/config and real M07 handoff records.
This development lifecycle diagnostic is not the full M09 acceptance driver.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time


def stop_disposable_vm(path):
    # This is a fresh snapshot VM. Product stop/remove and a final signed clean
    # probe precede teardown; no guest disk is reused or adopted after quit.
    with socket.socket(socket.AF_UNIX) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(path))
        response = b''
        while b'(qemu)' not in response:
            chunk=monitor.recv(4096)
            if not chunk or len(response)>8192:
                raise RuntimeError('monitor greeting missing')
            response+=chunk
        monitor.sendall(b'quit\n')
        # QEMU exits instead of returning a prompt. wait() verifies termination.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root', required=True)
    parser.add_argument('--controller-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--kernel', required=True)
    parser.add_argument('--initrd', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0 or shutil.disk_usage('/').free < 8 << 30:
        raise RuntimeError('root and at least 8GiB free required')
    out = Path(args.output)
    out.mkdir(mode=0o700)
    roots = [Path(args.runtime_root), Path(args.controller_root)]
    for root in roots:
        if not (root/'etc/m09-disposable-guest').is_file():
            raise RuntimeError('disposable guest root required')
    sockets = socket.socketpair()
    processes = []
    errors = []
    lifecycle_complete=False
    try:
        for index, (role, root) in enumerate(zip(('runtime', 'controller'), roots)):
            if index == 1:
                deadline = time.monotonic()+100
                while time.monotonic() < deadline:
                    serial = (out/'runtime.log').read_text(errors='replace')
                    lines = [line for line in serial.splitlines() if line.startswith('M09-PROCESS-ENROLLMENTS ')]
                    if lines:
                        raw = lines[-1].removeprefix('M09-PROCESS-ENROLLMENTS ')
                        if len(raw) > 65536:
                            raise RuntimeError('oversized root enrollment')
                        records = json.loads(raw)
                        if not isinstance(records, list) or not 1 <= len(records) <= 16:
                            raise RuntimeError('invalid root enrollment')
                        target = root/'var/lib/m09-process/enrollments.json'
                        target.write_text(json.dumps({"enrollments": records}))
                        target.chmod(0o600)
                        os.chown(target,1002,1002)
                        break
                    if processes[0].poll() is not None:
                        raise RuntimeError('runtime exited before enrollment')
                    time.sleep(.2)
                else:
                    raise RuntimeError('runtime enrollment timeout')
            image = out/(role+'.raw')
            with image.open('xb') as stream:
                stream.truncate(4 << 30)
            subprocess.run(['mkfs.ext4','-q','-F','-d',str(root),str(image)],check=True)
            serial = out/(role+'.log')
            serial.touch(mode=0o600)
            command = ['qemu-system-x86_64','-enable-kvm','-machine','q35','-cpu','host','-smp','2','-m','2560' if index == 0 else '1024',
                       '-kernel',args.kernel,'-initrd',args.initrd,'-append','root=/dev/vda rw noresume console=ttyS0 apparmor=1 security=apparmor',
                       '-drive',f'file={image},format=raw,if=virtio,snapshot=on','-netdev',f'socket,id=lab,fd={sockets[index].fileno()}',
                       '-device',f'virtio-net-pci,netdev=lab,mac=52:54:00:09:00:{10+index:02x}','-display','none','-serial',f'file:{serial}','-monitor','unix:'+str(out/(role+'.monitor'))+',server=on,wait=off','-no-reboot']
            stderr = (out/(role+'.stderr')).open('wb')
            process = subprocess.Popen(command,pass_fds=(sockets[index].fileno(),),stdout=stderr,stderr=stderr)
            stderr.close()
            processes.append(process)
            sockets[index].close()
        deadline = time.monotonic()+260
        while processes[1].poll() is None and time.monotonic() < deadline:
            time.sleep(.5)
        if processes[1].poll() is None:
            raise RuntimeError('controller lifecycle timeout')
        report = (out/'controller.log').read_text(errors='replace')
        if 'M09-PROCESS-COMPLETE scope=real-M07-stateless-lifecycle-only' not in report or 'M09-PROCESS-CONTROLLER-END rc=0' not in report:
            raise RuntimeError('controller lifecycle incomplete')
        lifecycle_complete=True
        stop_disposable_vm(out/'runtime.monitor')
        processes[0].wait(timeout=15)
        print('M09-PROCESS-PAIR-COMPLETE scope=development-lifecycle-not-full-acceptance')
    except Exception as error:
        errors.append(str(error))
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                role='runtime' if process is processes[0] else 'controller'
                try:
                    stop_disposable_vm(out/(role+'.monitor'))
                    process.wait(timeout=12)
                except (OSError,subprocess.TimeoutExpired):
                    pass
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for connection in sockets:
            connection.close()
        (out/'result.json').write_text(json.dumps({'scope':'development lifecycle only','teardown':'exact owned snapshot QEMU quit','final_signed_clean_probe_verified':lifecycle_complete,'errors':errors,'qemu_exit_codes':[p.returncode for p in processes]},indent=2)+'\n')


if __name__ == '__main__':
    main()
