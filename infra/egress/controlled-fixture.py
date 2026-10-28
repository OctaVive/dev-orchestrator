#!/usr/bin/env python3
"""TEST ONLY: deterministic TCP DNS, HTTPS origins and denied-destination canaries.

Run only in the isolated M05 VM. Never installed as a platform service.
All network addresses are synthetic local aliases owned by the lab harness.
"""
import argparse
import http.server
import ipaddress
import json
import socket
import socketserver
import ssl
import struct
import threading
import time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--root', required=True)
a = ap.parse_args()
root = Path(a.root)
lock = threading.Lock()
mode = {'rebind': False, 'dns_outage_until': 0}

def log(kind, **fields):
    with lock:
        with (root / 'canary.jsonl').open('a') as f:
            f.write(json.dumps(dict(kind=kind, time=time.time(), **fields)) + '\n')

def answer(packet):
    if len(packet) < 17:
        raise ValueError('short query')
    pos, labels = 12, []
    while packet[pos]:
        n = packet[pos]
        if n > 63 or pos + n + 1 >= len(packet):
            raise ValueError('invalid question')
        labels.append(packet[pos+1:pos+1+n].decode('ascii'))
        pos += n + 1
    pos += 1
    qtype, qclass = struct.unpack('!HH', packet[pos:pos+4])
    end = pos + 4
    name = '.'.join(labels).lower()
    log('dns', name=name, qtype=qtype)
    with lock:
        outage = mode['dns_outage_until'] > time.time()
        rebind = mode['rebind']
    if outage:
        # An actual resolver connection failure, not an NXDOMAIN fallback.
        return None
    address = '11.0.0.1' if qtype == 1 else None
    if name == 'v6.m05.test':
        address = '2003::11' if qtype == 28 else None
    elif name in ('mixed.m05.test', 'mapped.m05.test'):
        address = '11.0.0.1' if qtype == 1 else ('::ffff:11.0.0.1' if name.startswith('mapped') else '::1')
    elif name == 'rebind.m05.test' and rebind:
        address = '127.0.0.77' if qtype == 1 else None
    elif name == 'private.m05.test':
        address = '127.0.0.77' if qtype == 1 else None
    elif name == 'infra.m05.test':
        address = '11.0.0.3' if qtype == 1 else None
    elif name == 'badcert.m05.test':
        address = '11.0.0.2' if qtype == 1 else None
    elif name == 'dnsfail.m05.test':
        return packet[:2] + struct.pack('!HHHHH', 0x8182, 1, 0, 0, 0) + packet[12:end]
    elif not name.endswith('.m05.test'):
        return packet[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + packet[12:end]
    records = b''
    if address:
        data = ipaddress.ip_address(address).packed
        records = b'\xc0\x0c' + struct.pack('!HHIH', qtype, qclass, 0, len(data)) + data
    return packet[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(records)), 0, 0) + packet[12:end] + records

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        data = self.request.recv(2)
        if len(data) != 2:
            return
        size = struct.unpack('!H', data)[0]
        packet = b''
        while len(packet) < size:
            chunk = self.request.recv(size-len(packet))
            if not chunk:
                return
            packet += chunk
        try:
            response = answer(packet)
            if response is not None:
                self.request.sendall(struct.pack('!H', len(response)) + response)
        except (ValueError, IndexError, UnicodeDecodeError):
            return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def do_GET(self):
        log('http', listener=self.server.label, host=self.headers.get('Host', ''), path=self.path)
        path = self.path.split('?', 1)[0]
        if path == '/prime':
            with lock:
                mode['rebind'] = True
        if path == '/dns-outage':
            with lock:
                mode['dns_outage_until'] = time.time() + 4
            # Actually close the dedicated resolver listener. A delayed fresh
            # listener models restart without changing the production broker.
            current = servers[0]
            current.shutdown()
            current.server_close()
            def restart_dns():
                time.sleep(4)
                replacement = Server(('127.0.0.55', 53), DNS)
                servers[0] = replacement
                threading.Thread(target=replacement.serve_forever, daemon=True).start()
            threading.Thread(target=restart_dns, daemon=True).start()
        status = 302 if path.startswith('/redirect') else (101 if path == '/upgrade' else 200)
        self.send_response(status)
        if status == 302:
            self.send_header('Location', 'https://private.m05.test/redirect-target')
        if status == 101:
            self.send_header('Upgrade', 'websocket')
        data = b'A' * (3 * 1024 * 1024) if path == '/large' else b'M05 controlled response\n'
        if path == '/lease-mode':
            state = json.loads((root / 'guest-mode.json').read_text()) if (root / 'guest-mode.json').exists() else {'mode': 'normal'}
            data = (state['mode'] + '|' + state.get('job', '')).encode()
        if path == '/stream':
            data = b'S' * 65536
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            if path == '/stream':
                for pos in range(0, len(data), 1024):
                    self.wfile.write(data[pos:pos+1024])
                    self.wfile.flush()
                    time.sleep(1)
                log('stream-complete', path=self.path)
            else:
                self.wfile.write(data)
        except (OSError, ssl.SSLError):
            if path == '/stream':
                log('stream-interrupted', path=self.path)

    def do_POST(self):
        self.do_GET()

class HTTPS(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def get_request(self):
        c, peer = super().get_request()
        log('accept', listener=self.label, peer=peer[0])
        return c, peer

class HTTPS6(HTTPS):
    address_family = socket.AF_INET6

def serve_http(ip, label, cert):
    cls = HTTPS6 if ':' in ip else HTTPS
    server = cls((ip, 443), HTTP)
    server.label = label
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / cert, root / 'origin-key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

servers = [Server(('127.0.0.55', 53), DNS)]
threading.Thread(target=servers[0].serve_forever, daemon=True).start()
for ip, label, cert in (
    ('11.0.0.1', 'public-v4', 'origin.pem'),
    ('2003::11', 'public-v6', 'origin.pem'),
    ('11.0.0.2', 'bad-cert', 'wrong.pem'),
    ('11.0.0.3', 'infra-denied', 'origin.pem'),
    ('127.0.0.77', 'private-denied', 'origin.pem'),
):
    servers.append(serve_http(ip, label, cert))
# TCP connection canaries for direct DNS bypass and UDP/QUIC destinations.
def udp_canary(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('11.0.0.1', port))
    while True:
        data, peer = s.recvfrom(65536)
        log('udp', port=port, peer=peer[0], size=len(data))
for port in (53, 443):
    threading.Thread(target=udp_canary, args=(port,), daemon=True).start()
(root / 'fixture-ready').write_text('ready\n')
while True:
    time.sleep(1)
