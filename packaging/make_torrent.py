#!/usr/bin/env python3
"""Makes the hybrid (BitTorrent v1 and v2) torrent of a published file, and pins it in the manifest (docs/DOWNLOAD-SHARING.md).

  python3 -I -B packaging/make_torrent.py derived/release/<release>/Lastbook-All.zip --url https://downloads.lastbook.org/Lastbook-All.zip
                                          [--piece-mib 32] [--tracker udp://...] [--manifest derived/release/manifest-v1.json]

Writes <zip>.torrent beside the zip. Its web seed (BEP 19) is the file's own address, so a swarm always has a seed, and it has no
creation date, so the same file always gives the same torrent. Upload it next to the zip, at <url>.torrent.

Prints the file entry's pin, {"url": <url>.torrent, "pieces_root", "infohash_v2", "piece_length"}. With --manifest it is also written into that
file's entry there (found by name) for packaging/release_manifest.py. The app trusts the torrent only as far as it adds up to that
pieces root, and the file only as far as its SHA-256, so neither the torrent nor any mirror or peer can change a byte.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT)]
from engine.setup import download, torrent        # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('zip', help='the published file')
    ap.add_argument('--url', required=True, help='where the file is published (its web seed); the torrent goes at <url>.torrent')
    ap.add_argument('--piece-mib', type=int, default=download.SEGMENT // 2 ** 20,
                    help='piece length in MiB, a power of two (default: the downloader\'s segment, so its pieces line up)')
    ap.add_argument('--tracker', action='append', default=[], help='a tracker to list (peers are also found through the DHT)')
    ap.add_argument('--manifest', help='a manifest JSON whose entry for this file gets the "torrent" pin')
    a = ap.parse_args()
    path = Path(a.zip)
    if not download.url_allowed(a.url):
        sys.exit(f'{a.url} is not on an allowed host (engine/setup/download.py)')
    length = a.piece_mib * 2 ** 20
    torrent.check_piece_length(length)

    def progress(done, total):
        print(f'\r{done / total:6.1%} of {total / 1e9:.1f} GB', end='', file=sys.stderr, flush=True)
    data, pin = torrent.make(path, path.name, length, web_seeds=[a.url], trackers=a.tracker, progress=progress)
    print(file=sys.stderr)
    out = path.with_name(path.name + '.torrent')
    out.write_bytes(data)
    entry = {'url': a.url + '.torrent', 'pieces_root': pin['pieces_root'], 'infohash_v2': pin['infohash_v2'], 'piece_length': length}
    print(f'{out}: {len(data):,} bytes, infohash v1 {pin["infohash_v1"]}, v2 {pin["infohash_v2"]}')
    print(f'magnet:?xt=urn:btih:{pin["infohash_v1"]}&xt=urn:btmh:1220{pin["infohash_v2"]}&dn={path.name}')
    print(json.dumps({'torrent': entry}, indent=1))
    if a.manifest:
        m = json.loads(Path(a.manifest).read_text(encoding='utf-8'))
        hits = [f for key in ('packs', 'maps', 'address_indexes') for x in m.get(key) or [] for f in x.get('files') or [] if f.get('name') == path.name]
        if len(hits) != 1:
            sys.exit(f'{a.manifest}: {len(hits)} entries for {path.name}, not one')
        if hits[0].get('size') != pin['size']:
            sys.exit(f'{a.manifest}: {path.name} is {hits[0].get("size")} bytes there and {pin["size"]} here')
        hits[0]['torrent'] = entry
        Path(a.manifest).write_text(json.dumps(m, indent=1) + '\n', encoding='utf-8')
        print(f'{a.manifest}: pinned')


if __name__ == '__main__':
    main()
