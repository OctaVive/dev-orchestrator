#!/usr/bin/env python3
"""TEST ONLY: bounded Git smart-HTTP bytes and controlled DNS in the KVM lab.

Constructs known object bytes/packets directly; never invokes Git or parses a
repository on the host. The untrusted Git parser runs only inside the guest.
"""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import threading
import time
import zlib


def registry_fixture(onbuild=False):
    config=json.dumps({'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[]},'config':{'OnBuild':['ADD https://ok.m06.example/remote-target /remote']} if onbuild else {}},separators=(',',':')).encode()
    config_digest='sha256:'+hashlib.sha256(config).hexdigest()
    manifest=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':config_digest,'size':len(config)},'layers':[]},separators=(',',':')).encode()
    return config,config_digest,manifest,'sha256:'+hashlib.sha256(manifest).hexdigest()

def pkt(data):
    return f'{len(data)+4:04x}'.encode() + data


def object_id(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def pack(objects):
    result = b'PACK' + struct.pack('!II', 2, len(objects))
    types = {'commit': 1, 'tree': 2, 'blob': 3}
    for kind, data in objects:
        size = len(data)
        first = (types[kind] << 4) | (size & 15)
        size >>= 4
        header = bytes([first | (128 if size else 0)])
        while size:
            value = size & 127
            size >>= 7
            header += bytes([value | (128 if size else 0)])
        result += header + zlib.compress(data)
    return result + hashlib.sha1(result).digest()


def repository(scenario, external=None):
    files = [(b'100644', b'Dockerfile', b'FROM scratch\n'), (b'100644', b'app.txt', b'bounded clone fixture\n')]
    if scenario in ('build','build-cpu','build-flood','build-disk','build-memory','build-pids','build-remote','m08-dockerfile','m08-compose','m08-denied'):
        base=registry_fixture(scenario=='build-remote')[3]
        dockerfile=('FROM ok.m06.example/base@'+base+'\nCOPY rootfs /\nRUN ["/bin/sh","-c","test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/"]\nUSER 1000\n').encode()
        if scenario=='build-cpu':dockerfile=dockerfile.replace(b'test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/',b'while :; do :; done')
        if scenario=='build-flood':dockerfile=dockerfile.replace(b'test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/',b'while :; do echo M07-inert-log-flood; done')
        if scenario=='build-memory':dockerfile=dockerfile.replace(b'test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/',b"awk 'BEGIN{s=1;for(i=0;i<33;i++)s=s s;print length(s)}'")
        if scenario=='build-pids':dockerfile=dockerfile.replace(b'test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/',b'while :; do sleep 30 & done')
        if scenario=='build-disk':dockerfile=dockerfile.replace(b'test ! -e /var/run/docker.sock && ! wget -T 2 -q -O /dev/null http://169.254.169.254/',b'dd if=/dev/zero of=/big bs=1048576 count=5000')
        files = [(b'100644', b'Dockerfile', dockerfile),
                 (b'100755', b'rootfs/bin/sh', Path('/usr/bin/busybox').read_bytes()),
                 (b'100644', b'rootfs/etc/os-release', b'NAME=Alpine\nID=alpine\nVERSION_ID=3.23.0\n'),
                 (b'100644', b'rootfs/lib/apk/db/installed', b'P:m07-inert\nV:1.0.0-r0\nA:x86_64\nS:0\nI:0\nT:Inert acceptance fixture\nL:MIT\no:m07-inert\nm:fixture\nt:0\nc:0000000000000000000000000000000000000000\n\n')]
    # Explicit M09 handoff fixture: actual cloned/built/scanned HTTP workload.
    # Only trusted source bytes are constructed here; the guest runs the parser.
    if scenario in ('m08-dockerfile', 'm08-compose') and os.environ.get('M09_HANDOFF_DIRECTORY'):
        files = [(mode, name, data.replace(b'USER 1000\n', b'USER 1000:1000\nCMD ["/bin/busybox","httpd","-f","-p","8080","-h","/srv"]\n') if name == b'Dockerfile' else data)
                 for mode, name, data in files]
        files.extend([(b'100755', b'rootfs/bin/busybox', Path('/usr/bin/busybox').read_bytes()),
                      (b'100644', b'rootfs/srv/health', b'ready')])
    if scenario in ('m08-compose','m08-denied'):
        image=external or 'registry.example.org/apps/db@sha256:'+('a'*64)
        compose='services:\n  web:\n    build: {context: ., dockerfile: Dockerfile}\n    expose: ["8080"]\n    depends_on: [db]\n  db:\n    image: '+image+'\n'
        if scenario == 'm08-compose' and os.environ.get('M09_HANDOFF_DIRECTORY'):
            web = ['/bin/busybox', 'sh', '-c', 'for i in 1 2 3 4 5; do if /bin/busybox wget -q -T 1 -O /tmp/db http://db:8081/health; then exec /bin/busybox httpd -f -p 8080 -h /srv; fi; /bin/busybox sleep 1; done; exit 1']
            limits = '    deploy: {resources: {limits: {cpus: "0.5", memory: "256m", pids: 64}}}\n'
            compose = ('services:\n  web:\n    build: {context: ., dockerfile: Dockerfile}\n    expose: ["8080"]\n    depends_on: [db]\n    command: ' + json.dumps(web) + '\n' + limits +
                       '  db:\n    image: ' + image + '\n    expose: ["8081"]\n    command: ["/bin/busybox", "httpd", "-f", "-p", "8081", "-h", "/srv"]\n' + limits)
        if scenario=='m08-denied': compose+='    privileged: false\n'
        files.append((b'100644', b'compose.yaml', compose.encode()))
    if scenario == 'executable':
        files.append((b'100755', b'run.sh', b'#!/bin/sh\nexit 0\n'))
    if scenario == 'symlink':
        files.append((b'120000', b'link', b'app.txt'))
    if scenario in ('modules', 'attributes'):
        files.append((b'100644', b'.gitmodules' if scenario == 'modules' else b'.gitattributes', b'* filter=evil\n' if scenario=='attributes' else b'[submodule \"helper\"]\n path = sub\n url = ext::sh -c touch /work/helper-ran\n'))
    if scenario == 'submodule':
        files.append((b'100644',b'.gitmodules',b'[submodule \"evil\"]\n path = sub\n url = https://private.m06.example/submodule-target\n'))
    if scenario == 'lfs':
        files.append((b'100644', b'large.dat', b'version https://git-lfs.github.com/spec/v1\noid sha256:' + b'a'*64 + b'\nsize 12\n'))
    if scenario == 'escape':
        files.append((b'120000', b'escape', b'../../etc/passwd'))
    if scenario == 'cycle':
        files += [(b'120000', b'a', b'b'), (b'120000', b'b', b'a')]
    if scenario == 'collision':
        files.append((b'100644', b'APP.TXT', b'collision'))
    if scenario == 'metadata-path':
        files.append((b'100644', b'.GiT', b'metadata alias'))
    if scenario in ('nested','context-escape','context-return','deep-tree'):
        files = [(mode,b'src/'+name,data) for mode,name,data in files]
    if scenario == 'context-escape':
        files += [(b'120000',b'src/link',b'../outside.txt'),(b'100644',b'outside.txt',b'outside context')]
    if scenario == 'context-return':
        files.append((b'120000',b'src/link',b'../src/app.txt'))
    if scenario == 'config-symlink':
        files = [(b'120000',b'Dockerfile',b'app.txt'),(b'100644',b'app.txt',b'FROM scratch\n')]
    if scenario == 'directory-link':
        files += [(b'100644',b'dir/file.txt',b'file'),(b'120000',b'dir-link',b'dir')]
    if scenario == 'directory-cycle':
        files += [(b'120000',b'a/to-b',b'../b'),(b'120000',b'b/to-a',b'../a')]
    if scenario == 'huge-object':
        files.append((b'100644',b'large.dat',b'Z'*(65<<20)))
    objects = {}
    hierarchy = {}
    for mode,name,data in files:
        parts=name.split(b'/'); parent=hierarchy
        for component in parts[:-1]:
            parent=parent.setdefault(component,{})
        oid=object_id('blob',data); objects[oid]=('blob',data)
        parent[parts[-1]]=(mode,oid)
    def tree_bytes(children):
        result=b''
        for name,value in sorted(children.items(), key=lambda item: item[0]+(b'/' if isinstance(item[1],dict) else b'')):
            if isinstance(value,dict):
                data=tree_bytes(value); oid=object_id('tree',data);objects[oid]=('tree',data);mode=b'40000'
            else:
                mode,oid=value
            result+=mode+b' '+name+b'\0'+bytes.fromhex(oid)
        return result
    tree=tree_bytes(hierarchy)
    if scenario == 'submodule':
        tree += b'160000 sub\0' + bytes.fromhex('d'*40)
    tree_id = object_id('tree', tree)
    commit = f'tree {tree_id}\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\nfixture {scenario}\n'.encode()
    objects[tree_id]=('tree',tree)
    commit_id=object_id('commit',commit);objects[commit_id]=('commit',commit)
    return commit_id,pack(list(objects.values()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', required=True)
    args = ap.parse_args()
    root = Path(args.root)
    lock = threading.Lock()
    rebound = False
    advertisements = {}
    cases = ['good','executable','symlink','moving','mismatch','submodule','modules','attributes','lfs','escape','cycle','collision','metadata-path','malformed','sha256','redirect','redirect-same','timeout','object-limit','context-limit','entry-limit','ref-limit','transfer-limit','adv-limit','corrupt','stall-fetch','nested','context-escape','config-symlink','deep-tree','long-path','object-count','expanded-limit','huge-object','huge-ref-list','log-flood','redirect-301','redirect-303','redirect-307','redirect-308','directory-link','directory-cycle','context-return']
    if (root/'m07-enabled').exists(): cases.extend(['build','build-cpu','build-flood','build-disk','build-memory','build-pids','build-remote'])
    if (root/'m08-enabled').exists(): cases.extend(['m08-dockerfile','m08-compose','m08-denied'])
    repos = {name: repository(name if name not in ('moving','mismatch') else 'good') for name in cases}
    (root / 'expected-shas.json').write_text(json.dumps({k: v[0] for k, v in repos.items()}))

    def log(kind, **fields):
        with lock:
            with (root/'canary.jsonl').open('a') as f:
                f.write(json.dumps(dict(kind=kind, time=time.time(), **fields))+'\n')

    class TCP(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        def handle_error(self,request,client_address):
            log('fixture_disconnect',peer=str(client_address[0]))

    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            def read(n):
                data = b''
                while len(data) < n:
                    chunk = self.request.recv(n-len(data))
                    if not chunk:
                        raise ValueError('short DNS')
                    data += chunk
                return data
            try:
                size = struct.unpack('!H', read(2))[0]
                data = read(size)
                pos, labels = 12, []
                while data[pos]:
                    n = data[pos]; labels.append(data[pos+1:pos+1+n].decode('ascii')); pos += n+1
                pos += 1
                qtype, qclass = struct.unpack('!HH', data[pos:pos+4]); end = pos+4
                name = '.'.join(labels)
                log('dns', name=name, qtype=qtype)
                if name == 'dnsfail.m06.example':
                    return
                address = '11.0.0.1' if qtype == 1 else None
                if name == 'ingest.m06.example':
                    address = '11.0.0.4' if qtype == 1 else None
                if name == 'v6.m06.example':
                    address = '2003::11' if qtype == 28 else None
                if name == 'private.m06.example' or (name == 'rebind.m06.example' and rebound):
                    address = '127.0.0.77' if qtype == 1 else None
                if name == 'metadata.m06.example':
                    address = '169.254.169.254' if qtype == 1 else None
                if name == 'infra.m06.example':
                    address = '11.0.0.3' if qtype == 1 else None
                if name == 'badcert.m06.example':
                    address = '11.0.0.2' if qtype == 1 else None
                if name in ('mixed.m06.example','mapped.m06.example'):
                    address = '11.0.0.1' if qtype == 1 else ('::1' if name.startswith('mixed') else '::ffff:11.0.0.1')
                record = b''
                if address:
                    raw = ipaddress.ip_address(address).packed
                    record = b'\xc0\x0c'+struct.pack('!HHIH',qtype,qclass,0,len(raw))+raw
                response = data[:2]+struct.pack('!HHHHH',0x8180,1,int(bool(record)),0,0)+data[12:end]+record
                self.request.sendall(struct.pack('!H',len(response))+response)
            except (ValueError, IndexError, OSError):
                return

    class HTTP(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args):
            pass
        def send(self, data, content, status=200):
            self.send_response(status)
            self.send_header('Content-Type',content)
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def scenario(self):
            name=self.path.split('/')[1].removesuffix('.git')
            if name=='m08-compose' and (root/'m08-image').exists(): repos[name]=repository(name,(root/'m08-image').read_text().strip())
            return name
        def registry(self, head=False):
            config,cd,manifest,md=registry_fixture()
            mapping={'/v2/':(b'{}','application/json'),'/v2/base/manifests/'+md:(manifest,'application/vnd.oci.image.manifest.v1+json'),'/v2/base/blobs/'+cd:(config,'application/octet-stream')}
            config,cd,manifest,md=registry_fixture(True)
            mapping['/v2/base/manifests/'+md]=(manifest,'application/vnd.oci.image.manifest.v1+json')
            mapping['/v2/base/blobs/'+cd]=(config,'application/octet-stream')
            if self.path not in mapping:return False
            data,media=mapping[self.path]
            log('registry',listener=self.server.label,path=self.path,method='HEAD' if head else 'GET')
            self.send_response(200);self.send_header('Content-Type',media);self.send_header('Content-Length',str(len(data)));self.send_header('Docker-Distribution-Api-Version','registry/2.0');self.end_headers()
            if not head:self.wfile.write(data)
            return True
        def do_HEAD(self):
            if not self.registry(True):self.send(b'', 'text/plain',404)
        def do_GET(self):
            nonlocal rebound
            if self.registry():return
            host = self.headers.get('Host','')
            scenario = self.scenario()
            log('http', listener=self.server.label, method='GET', host=host, path=self.path)
            if self.server.label == 'denied':
                self.send(b'denied canary','text/plain'); return
            if scenario == 'timeout':
                time.sleep(10)
            if scenario in ('redirect','redirect-same','redirect-301','redirect-303','redirect-307','redirect-308'):
                self.send_response(int(scenario.split('-')[1]) if scenario.startswith('redirect-') and scenario!='redirect-same' else 302)
                self.send_header('Location',('https://private.m06.example' if scenario=='redirect' else 'https://ok.m06.example')+'/redirect-target')
                self.send_header('Content-Length','0');self.end_headers();return
            if scenario not in repos:
                self.send(b'missing','text/plain',404);return
            sha, _ = repos[scenario]
            advertisements[scenario] = advertisements.get(scenario, 0)+1
            if scenario == 'moving' and advertisements[scenario]>1:
                sha, _ = repository('executable')
                log('branch_moved', advertised_sha=sha)
            if scenario == 'malformed':
                self.send(b'garbage advertisement','application/x-git-upload-pack-advertisement');return
            if scenario == 'sha256':
                sha = 'a'*64
            caps = b'multi_ack_detailed no-done side-band-64k thin-pack ofs-delta shallow object-format=' + (b'sha256' if scenario == 'sha256' else b'sha1') + b' agent=m06-fixture'
            advertisement = pkt(b'# service=git-upload-pack\n')+b'0000'+pkt(sha.encode()+b' HEAD\0'+caps+b'\n')+pkt(sha.encode()+b' refs/heads/main\n')
            if scenario == 'ref-limit':
                advertisement += pkt(sha.encode()+b' refs/heads/other\n')
            if scenario in ('adv-limit','huge-ref-list'):
                for n in range(5000 if scenario=='huge-ref-list' else 100):
                    advertisement += pkt(sha.encode()+f' refs/heads/branch{n}\n'.encode())
            advertisement += b'0000'
            self.send(advertisement,'application/x-git-upload-pack-advertisement')
            if host.startswith('rebind.'):
                rebound = True
        def do_POST(self):
            scenario = self.scenario()
            n = int(self.headers.get('Content-Length','0'))
            if n < 0 or n > 65536:
                self.send(b'denied','text/plain',400);return
            body = self.rfile.read(n)
            log('http',listener=self.server.label,method='POST',host=self.headers.get('Host',''),path=self.path,done=b'done\n' in body)
            if scenario not in repos:
                self.send(b'missing','text/plain',404);return
            sha, packed = repos[scenario]
            if scenario == 'stall-fetch':
                time.sleep(30)
            if scenario == 'mismatch':
                _, packed = repository('executable')
            if scenario == 'corrupt':
                packed = packed[:-20]+b'X'*20
            prefix = pkt(b'shallow '+sha.encode()+b'\n')+b'0000'
            if b'done\n' not in body:
                self.send(prefix,'application/x-git-upload-pack-result');return
            response = prefix+pkt(b'NAK\n')
            if scenario=='log-flood':
                for _ in range(100):response+=pkt(b'\x02'+b'X'*2000+b'\n')
            for pos in range(0,len(packed),32000):
                response += pkt(b'\x01'+packed[pos:pos+32000])
            response += b'0000'
            self.send(response,'application/x-git-upload-pack-result')

    servers = [TCP(('127.0.0.56',53),DNS)]
    for address, label, cert in [('11.0.0.1','approved','origin.pem'),('11.0.0.2','badcert','wrong.pem'),('11.0.0.3','denied','origin.pem'),('127.0.0.77','denied','origin.pem')]:
        server = TCP((address,443),HTTP);server.label=label
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(root/cert),str(root/'origin-key.pem'));server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
    class TCP6(TCP):
        address_family=socket.AF_INET6
    server=TCP6(('2003::11',443),HTTP);server.label='approved-v6'
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(root/'origin.pem'),str(root/'origin-key.pem'));server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
    for server in servers:
        threading.Thread(target=server.serve_forever,daemon=True).start()
    (root/'fixture-ready').write_text('ready\n')
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
