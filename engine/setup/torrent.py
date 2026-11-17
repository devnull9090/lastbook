"""BitTorrent v2 hashes (BEP 52) and hybrid v1+v2 torrents, for one file. Only computing and reading: no network here.

v2 hashes a file in 16 KiB blocks, each with SHA-256, built up into a merkle tree. A piece's hash is the root of its part of
the tree, and the file's `pieces root` is the root of the whole. The manifest pins a file's pieces root and piece length
(32 bytes and a number), and so every piece: a list of piece hashes (the torrent's `piece layers`) is used only once it adds
up to that root (piece_hashes). Then a piece from any source, a mirror or a peer, can be checked on its own before it counts.

A hybrid torrent also carries the v1 SHA-1 piece hashes, so clients that only speak v1 (aria2c, rqbit) can share the same file.
packaging/make_torrent.py makes them; tests check the hashes against libtorrent's for the same file.
"""
import hashlib

BLOCK = 16 * 1024
ZERO = bytes(32)
MAX_TORRENT = 64 * 1024 * 1024        # bytes: a torrent of one 388 GB file with 32 MiB pieces is under 1 MB


class Bad(ValueError):
    """A torrent that is not what the manifest pinned."""


# --------------------------------------------------------------------------------------------------------------- bencode --
def bencode(x):
    if isinstance(x, bool):
        raise TypeError('bencode: no booleans')
    if isinstance(x, int):
        return b'i%de' % x
    if isinstance(x, str):
        x = x.encode('utf-8')
    if isinstance(x, (bytes, bytearray)):
        return b'%d:%s' % (len(x), bytes(x))
    if isinstance(x, (list, tuple)):
        return b'l' + b''.join(bencode(i) for i in x) + b'e'
    if isinstance(x, dict):
        items = sorted(((k.encode('utf-8') if isinstance(k, str) else bytes(k)), v) for k, v in x.items())
        return b'd' + b''.join(bencode(k) + bencode(v) for k, v in items) + b'e'
    raise TypeError(f'bencode: {type(x).__name__}')


def bdecode(data, max_depth=64):
    """Strict: the whole input is one value, integers in canonical form, dictionary keys sorted and unique. Keys and strings come
    back as bytes."""
    data = bytes(data)

    def value(i, depth):
        if depth > max_depth:
            raise Bad('nested too deep')
        c = data[i:i + 1]
        if c == b'i':
            end = data.index(b'e', i)
            s = data[i + 1:end]
            if not s or s == b'-0' or (s.lstrip(b'-').startswith(b'0') and s.lstrip(b'-') != b'0') or not s.lstrip(b'-').isdigit():
                raise Bad('bad integer')
            return int(s), end + 1
        if c == b'l':
            out, i = [], i + 1
            while data[i:i + 1] != b'e':
                v, i = value(i, depth + 1)
                out.append(v)
            return out, i + 1
        if c == b'd':
            out, i, last = {}, i + 1, None
            while data[i:i + 1] != b'e':
                k, i = value(i, depth + 1)
                if not isinstance(k, bytes) or (last is not None and k <= last):
                    raise Bad('dictionary keys out of order')
                last = k
                out[k], i = value(i, depth + 1)
            return out, i + 1
        if c.isdigit():
            colon = data.index(b':', i)
            n = int(data[i:colon])
            if data[i:colon] != str(n).encode() or colon + 1 + n > len(data):
                raise Bad('bad string')
            return data[colon + 1:colon + 1 + n], colon + 1 + n
        raise Bad('not bencoded')

    try:
        v, end = value(0, 0)
    except (IndexError, ValueError) as e:
        raise Bad(str(e)) from None
    if end != len(data):
        raise Bad('bytes after the end')
    return v


# ------------------------------------------------------------------------------------------------------------ v2 hashing --
def _up(layer):
    return [hashlib.sha256(layer[i] + layer[i + 1]).digest() for i in range(0, len(layer), 2)]


def _root(layer, width, pad):
    """The root over `layer` widened to `width` nodes (a power of two) with `pad`."""
    layer = list(layer) + [pad] * (width - len(layer))
    while len(layer) > 1:
        layer = _up(layer)
    return layer[0]


def _pow2(n):
    p = 1
    while p < n:
        p *= 2
    return p


def _zero_root(leaves):
    """The root of a subtree of `leaves` zero leaves."""
    h = ZERO
    while leaves > 1:
        h = hashlib.sha256(h + h).digest()
        leaves //= 2
    return h


def check_piece_length(n):
    if not isinstance(n, int) or n < BLOCK or n & (n - 1):
        raise Bad('the piece length must be a power of two of at least 16 KiB')
    return n


class PieceHasher:
    """The v2 hash of one piece, fed its bytes in any chunks. width: leaves in the piece's subtree (piece length / 16 KiB), or
    for a file of one piece or less, None (the tree is as wide as its blocks need)."""

    def __init__(self, width=None):
        self.width, self.leaves, self.buf = width, [], bytearray()

    def update(self, b):
        self.buf += b
        while len(self.buf) >= BLOCK:
            self.leaves.append(hashlib.sha256(self.buf[:BLOCK]).digest())
            del self.buf[:BLOCK]

    def digest(self):
        leaves = self.leaves + ([hashlib.sha256(self.buf).digest()] if self.buf else [])
        return _root(leaves, self.width or _pow2(len(leaves)), ZERO)


class Pieces:
    """What a file's piece hashes say: `count` pieces of `length` bytes (the last may be shorter), `hashes[k]` for piece k."""

    def __init__(self, size, length, hashes):
        self.size, self.length, self.hashes = size, length, hashes
        self.count = len(hashes)

    def hasher(self, k):
        return PieceHasher(None if self.count == 1 else self.length // BLOCK)

    def span(self, k):
        return k * self.length, min((k + 1) * self.length, self.size)


def file_hashes(path, length, progress=None):
    """(pieces root, [piece hashes]) of a file on disk, for a piece length."""
    check_piece_length(length)
    size = _size(path)
    hashes = []
    single = size <= length
    with open(path, 'rb') as f:
        done = 0
        while True:
            h = PieceHasher(None if single else length // BLOCK)
            n = 0
            while n < length:
                b = f.read(min(4 * 1024 * 1024, length - n))
                if not b:
                    break
                h.update(b)
                n += len(b)
            if not n:
                break
            hashes.append(h.digest())
            done += n
            if progress:
                progress(done, size)
    if not hashes:
        raise Bad('an empty file has no pieces root')
    return (hashes[0] if single else _root(hashes, _pow2(len(hashes)), _zero_root(length // BLOCK))), hashes


def _size(path):
    import os
    return os.path.getsize(path)


# --------------------------------------------------------------------------------------------------------------- torrents --
def make(path, name, length, web_seeds=(), trackers=(), progress=None):
    """A hybrid (v1 and v2) torrent of one file, as bytes, and what the manifest pins: {pieces_root (hex), piece_length, size,
    infohash_v1, infohash_v2}. No creation date or creator, so the same file always gives the same torrent."""
    check_piece_length(length)
    size = _size(path)
    root, hashes = file_hashes(path, length, progress)
    sha1 = bytearray()
    with open(path, 'rb') as f:
        while True:
            b = f.read(length)
            if not b:
                break
            sha1 += hashlib.sha1(b).digest()
    info = {'file tree': {name: {'': {'length': size, 'pieces root': root}}}, 'length': size, 'meta version': 2,
            'name': name, 'piece length': length, 'pieces': bytes(sha1)}
    t = {'info': info}
    if len(hashes) > 1:
        t['piece layers'] = {root: b''.join(hashes)}
    if web_seeds:
        t['url-list'] = list(web_seeds)
    if trackers:
        t['announce'] = trackers[0]
        t['announce-list'] = [[tr] for tr in trackers]
    encoded_info = bencode(info)
    return bencode(t), {'pieces_root': root.hex(), 'piece_length': length, 'size': size,
                        'infohash_v1': hashlib.sha1(encoded_info).hexdigest(), 'infohash_v2': hashlib.sha256(encoded_info).hexdigest()}


def piece_hashes(data, name, size, pieces_root, length, infohash_v2=None):
    """The piece hashes of `name` in a torrent, used only if they add up to the pinned pieces root and the torrent agrees on
    the name, size and piece length. infohash_v2 (pinned too): the SHA-256 of the torrent's whole info, which holds the v1 SHA-1
    piece hashes that v1-only clients check against, so a torrent with the right v2 part and another v1 part is refused.
    Raises Bad otherwise. A file of one piece or less has no list: its one hash is the root."""
    check_piece_length(length)
    root = bytes.fromhex(pieces_root)
    if len(root) != 32:
        raise Bad('a pieces root is 32 bytes')
    if len(data) > MAX_TORRENT:
        raise Bad('the torrent is too big')
    t = bdecode(data)
    try:
        info = t[b'info']
        entry = info[b'file tree'][name.encode('utf-8')][b'']
        ok = (info[b'piece length'] == length and entry[b'length'] == size and entry[b'pieces root'] == root
              and info.get(b'meta version') == 2 and len(info[b'file tree']) == 1
              and info.get(b'name') == name.encode('utf-8') and info.get(b'length') == size)
    except (KeyError, TypeError, AttributeError):
        raise Bad('the torrent does not describe that file') from None
    if not ok:
        raise Bad('the torrent does not match the pinned pieces root, name, size or piece length')
    if infohash_v2 is not None and hashlib.sha256(bencode(info)).hexdigest() != infohash_v2.lower():
        raise Bad('the torrent is not the pinned one (its v2 info-hash differs)')
    count = max(1, -(-size // length))
    if count == 1:
        return Pieces(size, length, [root])
    layer = (t.get(b'piece layers') or {}).get(root)
    if not isinstance(layer, bytes) or len(layer) != 32 * count:
        raise Bad('the torrent has no piece hashes for that file')
    hashes = [layer[i:i + 32] for i in range(0, len(layer), 32)]
    if _root(hashes, _pow2(count), _zero_root(length // BLOCK)) != root:
        raise Bad('the piece hashes do not add up to the pinned pieces root')
    return Pieces(size, length, hashes)
