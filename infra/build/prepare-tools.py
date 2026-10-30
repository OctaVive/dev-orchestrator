#!/usr/bin/env python3
"""Fetch pinned public M07 tools into a new private directory; no services enabled."""
import argparse,hashlib,json,os,shutil,subprocess,tarfile,urllib.request
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',required=True);ap.add_argument('--database-source',required=True,help='trusted frozen Trivy cache directory with db/trivy.db');args=ap.parse_args();os.umask(0o077)
 root=Path(args.root)
 if root.exists():ap.error('--root must be a new directory')
 root.mkdir(mode=0o700);pins=json.loads((repo/'infra/build/tools.lock.json').read_text())
 for name in ('buildkit','trivy'):
  pin=pins[name];archive=root/(name+'.tar.gz');urllib.request.urlretrieve(pin['archive_url'],archive)
  if sha(archive)!=pin['archive_sha256']:raise RuntimeError('tool checksum mismatch')
  dest=root/name;dest.mkdir(mode=0o700)
  with tarfile.open(archive) as tar:tar.extractall(dest,filter='data')
 source=Path(args.database_source)/'db'
 if sha(source/'trivy.db')!=pins['vulnerability_database']['sha256']:raise RuntimeError('database snapshot mismatch; review refresh separately')
 (root/'cache/db').mkdir(parents=True,mode=0o700)
 for file in ('trivy.db','metadata.json'):shutil.copyfile(source/file,root/'cache/db'/file)
 debs=root/'debs';debs.mkdir(mode=0o700)
 packages=['rootlesskit=2.0.2-2+b9','uidmap=1:4.17.4-2','libsubid5=1:4.17.4-2','tcpdump=4.99.5-2','libpcap0.8t64=1.10.5-2']
 subprocess.run(['apt-get','download']+packages,cwd=debs,check=True)
 for file in debs.glob('*.deb'):
  if pins['debian_sha256'].get(file.name)!=sha(file):raise RuntimeError('Debian tool checksum mismatch')
  dest=root/('pcap' if file.name.startswith(('tcpdump','libpcap')) else 'uidmap');dest.mkdir(mode=0o700,exist_ok=True);subprocess.run(['dpkg-deb','-x',str(file),str(dest)],check=True)
 manifest={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
 (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(root)
if __name__=='__main__':main()
