#!/usr/bin/env python3
"""Fetches the pinned rqbit release for one platform into derived/share/, for the build to bundle (engine/setup/share.py).

  python3 -I -B packaging/share/fetch_rqbit.py win-x64|mac-universal|linux-x64|linux-arm64 [--out derived/share] [--from FILE]

The file must match the size and SHA-256 in packaging/share/rqbit.json (GitHub's own digests for the release), or nothing is
written. --from checks and copies a file already downloaded instead. A build tool: the app itself never fetches rqbit.
"""
import argparse
import hashlib
import json
import shutil
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RELEASES = 'https://github.com/ikatson/rqbit/releases/download'


def main():
    pins = json.loads((HERE / 'rqbit.json').read_text(encoding='utf-8'))
    ap = argparse.ArgumentParser()
    ap.add_argument('platform', choices=sorted(pins['files']))
    ap.add_argument('--out', default=str(ROOT / 'derived' / 'share'))
    ap.add_argument('--from', dest='src', help='a copy already downloaded, to check and use')
    a = ap.parse_args()
    pin = pins['files'][a.platform]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        got = Path(tmp) / pin['name']
        if a.src:
            shutil.copyfile(a.src, got)
        else:
            url = f'{RELEASES}/v{pins["version"]}/{pin["asset"]}'
            print(f'fetching {url}', file=sys.stderr)
            with urllib.request.urlopen(url, context=ssl.create_default_context(), timeout=60) as r, open(got, 'wb') as f:
                shutil.copyfileobj(r, f, 1 << 20)
        h = hashlib.sha256(got.read_bytes()).hexdigest()
        if got.stat().st_size != pin['size'] or h != pin['sha256']:
            sys.exit(f'{pin["asset"]} is not the pinned file: {got.stat().st_size} bytes, sha256 {h}')
        got.chmod(0o755)
        dest = out / pin['name']
        shutil.move(str(got), dest)
    print(f'{dest}: rqbit {pins["version"]} for {a.platform}, sha256 {h}')


if __name__ == '__main__':
    main()
