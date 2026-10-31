#!/usr/bin/env python3
"""Package a trusted locally built static canary into a deterministic OCI archive.
This never opens, parses or extracts a workload archive. Inputs are operator paths.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def tar_bytes(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in files:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = 0
            entry.uid = entry.gid = 0
            tar.addfile(entry, io.BytesIO(data))
    return out.getvalue()


def build(binary):
    if len(binary) > 16 << 20 or not binary.startswith(b'\x7fELF'):
        raise ValueError('trusted static canary binary required')
    layer = tar_bytes([('runtime-canary', binary, 0o755)])
    config = encoded({'architecture': 'amd64', 'os': 'linux',
                      'config': {'User': '1000:1000', 'Entrypoint': ['/runtime-canary'],
                                 'Cmd': ['serve'], 'Env': ['GOMAXPROCS=1', 'GOMEMLIMIT=16777216',
                                                         'TAP_CANARY_CONTAINER=1']},
                      'rootfs': {'type': 'layers', 'diff_ids': [digest(layer)]}})
    manifest = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                        'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                   'digest': digest(config), 'size': len(config)},
                        'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                                    'digest': digest(layer), 'size': len(layer)}]})
    index = encoded({'schemaVersion': 2, 'manifests': [
        {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
         'digest': digest(manifest), 'size': len(manifest),
         'platform': {'architecture': 'amd64', 'os': 'linux'},
         'annotations': {'org.opencontainers.image.ref.name': 'docker.io/library/tap-runtime-canary:profile-v1'}}]})
    archive = tar_bytes([('oci-layout', encoded({'imageLayoutVersion': '1.0.0'}), 0o644),
                         ('index.json', index, 0o644)] +
                        [('blobs/sha256/' + digest(value)[7:], value, 0o644)
                         for value in (config, manifest, layer)])
    descriptor = {'archive_digest': digest(archive), 'bytes': len(archive),
                  'image_id': digest(config), 'manifest_digest': digest(manifest),
                  'binary_digest': digest(binary)}
    return archive, descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    archive, descriptor = build(Path(args.binary).read_bytes())
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'canary.oci.tar').write_bytes(archive)
    (out / 'canary.json').write_text(json.dumps(descriptor, indent=2) + '\n')
    for name in ('canary.oci.tar', 'canary.json'):
        (out / name).chmod(0o644)


if __name__ == '__main__':
    main()
