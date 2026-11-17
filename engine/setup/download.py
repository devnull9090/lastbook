"""The one way out: downloads for setup. This is the only module in Lastbook that opens a network connection.

  - HTTPS only, to the hosts in ALLOWED_HOSTS (or a subdomain of ALLOWED_SUFFIXES), port 443.
  - No proxy: http.client never reads the system's or the environment's proxy settings (urllib would), so a request goes
    straight to the host named, or nowhere.
  - A redirect is followed only to another allowed address, at most MAX_REDIRECTS times. Every request starts again from the
    file's own address, so a signed address a CDN redirects to is never kept.
  - Resuming uses HTTP Range on the ETag saved beside the partial file. R2 ignores If-Range (it answers 206 whatever the ETag),
    so the check is made here: another ETag on a 206, or another total size, starts that file over. (Not If-Match: on a
    redirect chain the first host's ETag is not the file's, so it would refuse every resume.) A 200 with the same ETag and size
    to a resume means the server ignored Range for a while: it is waited out, never answered by throwing the file away.
  - A large file comes in segments over several connections at once (Segments), nearly in order, so the file grows from the
    front and its SHA-256 is still fed in order. Each server gets a few connections, shared by every file being downloaded,
    the smallest file first, and fewer while it answers 503 (Hosts).
  - The SHA-256 is computed from what is on the disk, or kept in step with it: after a write that failed part way, the hash and
    the file are made to agree again before going on. A file that does not match at the end is not thrown away at once: it is
    read back from the disk and checked again, and a zip (every pack and map is one) is checked member by member against the
    CRC-32s in its central directory, and only the members that are wrong are fetched again (Download._repair_zip).
  - A file whose BitTorrent v2 pieces root is pinned in the manifest (engine/setup/torrent.py) has each piece checked against the
    torrent's piece hashes as it is read back, so its pieces may also come from mirrors: any https host, chosen by Lastbook's
    manifest or by the person. A mirror that sends one wrong piece is not used again; the file's SHA-256 is still the last word.
  - Nothing here runs unless the person started or resumed a download (or opened setup: one GET of the manifest).

Tests pass their own `allowed` and `context` to reach a local test server. The product never does.
"""
import errno
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import zipfile
import zlib
from pathlib import Path

ALLOWED_HOSTS = frozenset({
    'downloads.lastbook.org',
    'huggingface.co',
    'cas-bridge.xethub.hf.co',
})
ALLOWED_SUFFIXES = ('.hf.co',)      # Hugging Face's download hosts (cas-bridge.xethub.hf.co and its siblings)
MAX_REDIRECTS = 5
TIMEOUT = 30                        # seconds without a byte before the connection counts as broken
CHUNK = 1024 * 1024
SAVE_EVERY = 2.0                    # seconds between saves of the partial file's .json
NETWORK_TRIES = 8                   # broken connections in a row, with no progress between them, before giving up
BACKOFF = (2, 4, 8, 15, 30, 60, 120, 120)
USER_AGENT = 'Lastbook-setup/1'

# Several connections at once. Measured on downloads.lastbook.org (2026-11-17): about 1.2 MB/s per connection, several
# connections adding up, and 503 for some once more than a few are open. So each server starts with a few, gains one per RAMP
# seconds without a 503, loses one at each 503, and never has more than CONNECTIONS.
CONNECTIONS = 6
START_CONNECTIONS = 3
RAMP = 60
SEGMENT = 32 * 1024 * 1024          # a file larger than SEGMENTED_MIN comes in pieces of this size, several at once
SEGMENTED_MIN = 4 * SEGMENT
WINDOW = 4                          # segments per connection that may be done ahead of the first one not yet done
WHOLE_GAP = 10                      # seconds: 200s to pieces within this count as one (all the connections see the same hiccup)
PIECE_TRIES = 3                     # a piece that does not stay on the disk as it arrived this many times: the disk is failing
STALL = 600                         # seconds with no byte from any connection before 503s count as failures
REPAIR_MIN = 256 * 1024 * 1024      # a zip at least this big that fails its check is repaired in place, not downloaded again
TAIL = 1024 * 1024                  # the end of a zip fetched first when repairing: its end-of-central-directory records


class Stopped(Exception):
    """The person paused or cancelled. .why is 'paused' or 'cancelled'."""

    def __init__(self, why):
        super().__init__(why)
        self.why = why


class Failed(Exception):
    """A plain sentence for the person, and a code from docs/SETUP-API.md."""

    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra


class BadChecksum(Failed):
    def __init__(self, message):
        super().__init__('checksum', message)


def disk_full(e):
    return isinstance(e, OSError) and (e.errno in (errno.ENOSPC, getattr(errno, 'EDQUOT', -1)) or getattr(e, 'winerror', None) in (112, 39))


def host_allowed(host, allowed=None):
    host = (host or '').lower().rstrip('.')
    if allowed is not None:
        return host in allowed
    return host in ALLOWED_HOSTS or any(host.endswith(s) and len(host) > len(s) for s in ALLOWED_SUFFIXES)


def url_allowed(url, allowed=None):
    """An https address on an allowed host, with no user name or password in it, on port 443 (a test's own hosts: any port)."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return False
    if u.scheme != 'https' or not u.hostname or u.username or u.password:
        return False
    if allowed is None and port not in (None, 443):
        return False
    return host_allowed(u.hostname, allowed)


def roots_path():
    """engine/setup/roots.pem, beside this file (in the packaged app, where the packaging puts it: engine/setup/ under _MEIPASS)."""
    here = Path(__file__).with_name('roots.pem')
    if not here.is_file() and getattr(sys, 'frozen', False):
        here = Path(getattr(sys, '_MEIPASS', '')) / 'engine' / 'setup' / 'roots.pem'
    return here


def tls_context():
    """TLS 1.2 or later, hostname checked, and trust in the roots of roots.pem only: never the system's store (see
    packaging/setup_roots.py for why and which). With the file missing, nothing is downloaded."""
    roots = roots_path()
    if not roots.is_file():
        raise Failed('network', 'This copy of Lastbook is missing its list of trusted download servers, so it cannot download. '
                                'Download Lastbook again.')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # check_hostname on and CERT_REQUIRED; no default certificates loaded
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(roots))
    return ctx


class Control:
    """Pause and cancel, from any thread. The download notices within one chunk or one second of waiting."""

    def __init__(self):
        self.ev = threading.Event()
        self.why = None

    def stop(self, why):
        if self.why != 'cancelled':
            self.why = why
        self.ev.set()

    def check(self):
        if self.ev.is_set():
            raise Stopped(self.why or 'paused')

    def sleep(self, s):
        if self.ev.wait(s):
            raise Stopped(self.why or 'paused')


class Hosts:
    """Connections to each server, shared by every file one job downloads. At most `limit` to one host at once; the file with the
    fewest bytes still to come gets the next free connection, so small items finish early while a large one goes on. A 503 or 429
    lowers that host's limit to the connections that were working; RAMP seconds without one raise it by one, up to `most`."""

    def __init__(self, most=None, start=None):
        self.most = most or CONNECTIONS
        self.start = min(start or START_CONNECTIONS, self.most)
        self.cv = threading.Condition()
        self.hosts = {}
        self.waiting = []
        self.seq = 0

    def _h(self, host):
        return self.hosts.setdefault(host, {'limit': self.start, 'busy': 0, 'calm': time.time()})

    def limit(self, host):
        with self.cv:
            return self._h(host)['limit']

    def acquire(self, host, priority, control, halt=None):
        """Blocks until this host has a free connection and no file with fewer bytes to come is waiting for one."""
        with self.cv:
            h = self._h(host)
            self.seq += 1
            me = (priority, self.seq, host)
            self.waiting.append(me)
            try:
                while True:
                    if h['limit'] < self.most and time.time() - h['calm'] >= RAMP:
                        h['limit'] += 1
                        h['calm'] = time.time()
                    first = min(w for w in self.waiting if w[2] == host)
                    if first == me and h['busy'] < h['limit']:
                        h['busy'] += 1
                        return
                    control.check()
                    if halt is not None and halt.is_set():
                        raise _Halt()
                    self.cv.wait(0.5)
            finally:
                self.waiting.remove(me)
                self.cv.notify_all()

    def release(self, host):
        with self.cv:
            self._h(host)['busy'] -= 1
            self.cv.notify_all()

    def busy_signal(self, host):
        """The host answered 503 or 429 to one of `busy` connections: the others are what it takes."""
        with self.cv:
            h = self._h(host)
            h['limit'] = max(1, min(h['limit'], h['busy']) - 1)
            h['calm'] = time.time()


def _same_etag(a, b):
    """Cloudflare may weaken a strong ETag (W/"...") on the way: the same value either way is the same file."""
    norm = lambda e: (e or '').strip().removeprefix('W/')
    return norm(a) == norm(b)


def _mirror_allowed(url, mirrors):
    """An https address on one of this file's mirrors (host and port as listed), with no user name or password."""
    try:
        u = urllib.parse.urlsplit(url)
        return u.scheme == 'https' and not u.username and not u.password and u.netloc.lower() in mirrors
    except ValueError:
        return False


def _open(url, start, etag, allowed, context, timeout, end=None, mirrors=()):
    """(connection, response, final url) for a GET from byte `start` (to byte `end`, inclusive, if given), after following
    allowed redirects. mirrors: the hosts (host:port) of this file's mirrors, which may be asked as well."""
    for _ in range(MAX_REDIRECTS + 1):
        if not (url_allowed(url, allowed) or _mirror_allowed(url, mirrors)):
            raise Failed('network', 'Lastbook refused to download from an address it does not know.')
        u = urllib.parse.urlsplit(url)
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=context)
        headers = {'User-Agent': USER_AGENT, 'Accept-Encoding': 'identity'}
        if start or end is not None:
            headers['Range'] = f'bytes={start}-' + ('' if end is None else str(end))
            if etag:
                headers['If-Range'] = etag
        conn.request('GET', (u.path or '/') + ('?' + u.query if u.query else ''), headers=headers)
        r = conn.getresponse()
        if r.status in (301, 302, 303, 307, 308):
            loc = r.getheader('Location')
            r.close()
            conn.close()
            if not loc:
                raise Failed('network', 'The download server answered with a move to nowhere.')
            url = urllib.parse.urljoin(url, loc)
            continue
        return conn, r, url
    raise Failed('network', 'The download server sent Lastbook round in circles.')


def fetch_small(url, limit=1 << 20, allowed=None, context=None, timeout=10):
    """One small GET (the manifest). Bytes, or None on any failure."""
    try:
        conn, r, _ = _open(url, 0, None, allowed, context or tls_context(), timeout)
        try:
            if r.status != 200:
                return None
            data = r.read(limit + 1)
            return data if len(data) <= limit else None
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, Failed, ValueError):
        return None


def _load_meta(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_meta(path, d):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f)
    os.replace(tmp, path)


def _content_range(v):
    """(start, total) from 'bytes 100-199/1000', or None."""
    try:
        unit, _, rest = (v or '').partition(' ')
        span, _, total = rest.partition('/')
        return int(span.split('-')[0]), int(total)
    except ValueError:
        return None


def _write_all(f, b):
    """Every byte of b to an unbuffered file, or an exception: a raw write may take only part."""
    view = memoryview(b)
    while view:
        n = f.write(view)
        if not n:
            raise OSError(errno.EIO, 'the disk took no bytes')
        view = view[n:]


def done_on_disk(dest):
    """Bytes of <dest> downloaded so far, from its .part and .part.json (the whole size once it is complete)."""
    dest = str(dest)
    try:
        return os.path.getsize(dest)
    except OSError:
        pass
    meta = _load_meta(dest + '.part.json')
    try:
        size = os.path.getsize(dest + '.part')
    except OSError:
        return 0
    if meta.get('segment'):
        return min(Segments.from_meta(meta, int(meta.get('size') or 0)).received(), size)
    return size


class Download:
    """One file: <dest>.part grows, with <dest>.part.json beside it (url, size, sha256, ETag, and for a file in segments which
    segments are done). run() returns once the whole file is there and its SHA-256 matches, renamed to <dest>. Raises Stopped,
    Failed or BadChecksum. progress(done, total, phase) is called as bytes arrive; phase is 'downloading' or 'verifying'.
    connections: most at once for this file (1: one stream, as before); hosts: the Hosts shared with the job's other files."""

    def __init__(self, url, dest, size, sha256, control, progress=lambda d, t, p: None, allowed=None, context=None, timeout=TIMEOUT,
                 connections=1, hosts=None, pieces=None, mirrors=()):
        """pieces: the file's torrent.Pieces (its piece hashes, already checked against the pinned pieces root), or None. mirrors:
        other https addresses of the same file, used only with pieces."""
        self.url, self.dest, self.size, self.sha256 = url, str(dest), int(size), sha256.lower()
        self.part, self.meta = self.dest + '.part', self.dest + '.part.json'
        self.control, self.progress = control, progress
        self.allowed, self.context, self.timeout = allowed, context, timeout
        self.connections = max(1, int(connections or 1))
        self.hosts = hosts
        self.host = _netloc(url)
        self.pieces = pieces if pieces is not None and pieces.size == self.size else None
        self.sources = [url] + ([m for m in dict.fromkeys(mirrors) if m != url] if self.pieces else [])
        self.mirror_hosts = frozenset(_netloc(m) for m in self.sources[1:])
        self.banned = set()
        self.seg = max(SEGMENT, self.pieces.length) if self.pieces else SEGMENT     # a segment holds whole torrent pieces
        self._pos = 0

    @property
    def name(self):
        return os.path.basename(self.dest)

    def done_bytes(self):
        try:
            return min(os.path.getsize(self.part), self.size)
        except OSError:
            return 0

    def discard(self):
        for p in (self.part, self.meta, self.meta + '.tmp'):
            try:
                os.unlink(p)
            except OSError:
                pass

    def _rehash(self, n, h=None, start=0):
        """The SHA-256 of bytes start..n already on disk, added to h (a new hash from byte 0 if None)."""
        h = h or hashlib.sha256()
        done = start
        with open(self.part, 'rb') as f:
            f.seek(start)
            while done < n:
                self.control.check()
                b = f.read(min(8 * CHUNK, n - done))
                if not b:
                    break
                h.update(b)
                done += len(b)
                self.progress(done, n, 'verifying')
        return h, done

    def run(self):
        if os.path.isfile(self.dest) and os.path.getsize(self.dest) == self.size and not os.path.exists(self.part):
            return self.dest     # finished and checked before a restart
        os.makedirs(os.path.dirname(self.dest) or '.', exist_ok=True)
        meta = _load_meta(self.meta)
        if meta and (meta.get('sha256') != self.sha256 or meta.get('size') != self.size):
            self.discard()       # left by another version of this file
            meta = {}
        ctx = self.context or tls_context()
        own = self.hosts is None
        if own:
            self.hosts = Hosts(most=self.connections, start=self.connections)
        try:
            if self.connections > 1 and self.size > SEGMENTED_MIN:
                h, fetched = self._run_segments(meta, ctx)
            else:
                h, fetched = self._run_stream(meta, ctx)
        finally:
            if own:
                self.hosts = None
        if fetched:              # judged on what the disk holds, not on what arrived: a network share can lose or change bytes
            h = self._rehash(self.size)[0]
        if h.hexdigest() != self.sha256:
            self._recheck(ctx)
        os.replace(self.part, self.dest)
        try:
            os.unlink(self.meta)
        except OSError:
            pass
        return self.dest

    # ------------------------------------------------------------------------------------------------- one stream --
    def _run_stream(self, meta, ctx, h=None, start=None):
        """The file in order over one connection. Returns (hash of the whole file, whether any byte came from the network)."""
        if h is None:
            start = self.done_bytes()
            if meta.get('segment'):          # left by a download in segments: what is done from the front is the start
                start = min(start, Segments.from_meta(meta, self.size).front())
            if start and not meta.get('etag'):
                start = 0            # nothing to tell the server which file those bytes came from
            with open(self.part, 'ab') as f:
                f.truncate(start)
            h, start = self._rehash(start) if start else (hashlib.sha256(), 0)
        etag = meta.get('etag')
        tries = 0
        ignored = 0              # 200s in a row to a resume, from a server that says the file is the same
        fetched = False
        self.hosts.acquire(self.host, self.size - start, self.control)
        try:
            while start < self.size:
                self.control.check()
                self._pos = start
                fetched = True
                try:
                    start, etag = self._fetch(start, etag, h, ctx, check_front=ignored >= NETWORK_TRIES)
                    tries = ignored = 0
                except (Stopped, Failed):
                    raise
                except _Restart as r:
                    if r.whole:      # same ETag and size: the server ignored Range for now. Wait, and keep every byte.
                        ignored += 1
                        print(f'setup: the server sent the whole of {self.name} to a resume at {start}; waiting, then asking again', flush=True)
                        self.control.sleep(BACKOFF[min(ignored - 1, len(BACKOFF) - 1)])
                        continue
                    print(f'setup: the file on the server changed; starting {self.name} over', flush=True)
                    with open(self.part, 'r+b') as f:
                        f.truncate(0)
                    h, start, etag = hashlib.sha256(), 0, None
                    continue
                except ssl.SSLCertVerificationError:
                    raise _untrusted()
                except (OSError, http.client.HTTPException, ValueError) as e:
                    if disk_full(e):
                        raise Failed('no_space', 'The disk filled up while downloading. Free some space, then try again.')
                    h, now = self._settle(h)
                    tries = 0 if now > start else tries + 1
                    start = now
                    etag = _load_meta(self.meta).get('etag') or etag
                    if tries >= NETWORK_TRIES:
                        raise Failed('network', f'The connection kept breaking ({type(e).__name__}). Check the internet connection, then try again.')
                    print(f'setup: download broke at {start} of {self.size}: {type(e).__name__}: {e}; trying again', flush=True)
                    self.control.sleep(BACKOFF[min(tries, len(BACKOFF) - 1)])
        finally:
            self.hosts.release(self.host)
        return h, fetched

    def _settle(self, h):
        """After a break: the hash and the file agree again. self._pos is what was both written and hashed. A write that failed
        part way may have left bytes beyond it, which are cut off (the next fetch writes there anyway); a disk that lost bytes
        the hash has (a network share) has what is on it read back. Returns (hash, bytes done)."""
        pos = self._pos
        try:
            size = os.path.getsize(self.part)
        except OSError:
            size = pos
        if size > pos:
            print(f'setup: {self.name} has {size - pos} bytes past what was checked; cutting them off', flush=True)
            try:
                with open(self.part, 'r+b') as f:
                    f.truncate(pos)
            except OSError:
                pass
            return h, pos
        if size < pos:
            print(f'setup: {self.name} is {pos - size} bytes shorter on the disk than what was written; reading it back', flush=True)
            return self._rehash(size)
        return h, pos

    def _fetch(self, start, etag, h, ctx, check_front=False):
        """Reads until the end or a break. Returns (bytes done, etag). Raises _Restart when the server's file is not the one begun.
        check_front: a server that keeps ignoring Range is read from byte 0, and the bytes already here are compared, not written."""
        conn, r, final = _open(self.url, start, etag, self.allowed, ctx, self.timeout)
        try:
            if r.status == 416 or r.status >= 400:
                if 500 <= r.status < 600 or r.status == 429:
                    raise OSError(f'HTTP {r.status}')
                raise Failed('network', f'The download server refused the file (HTTP {r.status}).')
            new_etag = r.getheader('ETag')
            length = r.getheader('Content-Length')
            front = 0
            if r.status == 206:
                cr = _content_range(r.getheader('Content-Range'))
                if not cr or cr[0] != start or cr[1] != self.size or (etag and new_etag and not _same_etag(new_etag, etag)):
                    raise _Restart(new_etag)
            elif r.status == 200:
                if length is not None and length.isdigit() and int(length) != self.size:
                    if start:
                        raise _Restart(new_etag)
                    raise BadChecksum(f'The file on the server is {int(length):,} bytes, not the {self.size:,} Lastbook expects.')
                if start:
                    if etag and new_etag and not _same_etag(new_etag, etag):
                        raise _Restart(new_etag)
                    if not check_front:
                        raise _Restart(new_etag, whole=True)
                    front = start
            else:
                raise OSError(f'HTTP {r.status}')
            if front:
                self._compare_front(r, front, h)
            etag = new_etag or etag
            meta = {'url': self.url, 'size': self.size, 'sha256': self.sha256, 'etag': etag, 'bytes_done': start}
            _save_meta(self.meta, meta)
            saved = time.time()
            with open(self.part, 'r+b', buffering=0) as f:
                f.seek(start)
                while start < self.size:
                    self.control.check()
                    b = r.read1(min(CHUNK, self.size - start))    # what has arrived, up to CHUNK: progress and pause stay quick on a slow line
                    if not b:
                        raise ConnectionError('the connection closed early')
                    _write_all(f, b)
                    h.update(b)            # only after every byte is written: h and the file agree at self._pos
                    start += len(b)
                    self._pos = start
                    self.progress(start, self.size, 'downloading')
                    if time.time() - saved > SAVE_EVERY:
                        meta['bytes_done'] = start
                        _save_meta(self.meta, meta)
                        saved = time.time()
                os.fsync(f.fileno())
            meta['bytes_done'] = start
            _save_meta(self.meta, meta)
            return start, etag
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _compare_front(self, r, front, h):
        """The first `front` bytes of a whole-file answer, which are on the disk already: hashed, not written. They must be what
        is on the disk (h holds exactly those), or the file changed after all."""
        print(f'setup: the server keeps ignoring Range; reading {self.name} from the start and comparing {front} bytes already here', flush=True)
        h2, n = hashlib.sha256(), 0
        while n < front:
            self.control.check()
            b = r.read1(min(CHUNK, front - n))
            if not b:
                raise ConnectionError('the connection closed early')
            h2.update(b)
            n += len(b)
            self.progress(n, self.size, 'verifying')
        if h2.digest() != h.copy().digest():
            raise _Restart(None)

    # ----------------------------------------------------------------------------------------------------- segments --
    def _run_segments(self, meta, ctx):
        """The file in SEGMENT pieces over up to self.connections connections, the lowest pieces first. Each piece's SHA-256 is
        taken as it arrives; this thread reads the pieces back from the disk in order, checks each against what arrived (a piece
        the disk did not keep is fetched again), and feeds the file's SHA-256. Returns (hash of the whole file, False: every
        byte of it was read back from the disk)."""
        open(self.part, 'ab').close()
        on_disk = os.path.getsize(self.part)
        if meta.get('etag') and meta.get('segment') == self.seg:
            st = Segments.from_meta(meta, self.size)
        else:
            st = Segments(self.size, self.seg)
            if meta.get('etag'):     # a .part from one stream, or from pieces of another size: its bytes from the front are done
                st.adopt_front(Segments.from_meta(meta, self.size).front() if meta.get('segment') else self.done_bytes())
        st.clip(on_disk)             # nothing counts as done that is not on the disk
        self.etag = meta.get('etag') if st.received() else None
        self.st, self.halt, self.error, self.ranges_ignored = st, threading.Event(), None, False
        self.whole_answers, self.last_byte = 0, time.time()     # 200s in a row to a piece; when a byte last arrived
        self.last_whole = 0.0
        h, cursor = hashlib.sha256(), 0
        last_save = last_progress = 0
        workers = []
        try:
            while True:
                if not workers and not st.complete():
                    self.halt.clear()
                    workers = [threading.Thread(target=self._worker, args=(ctx, src), daemon=True, name=f'setup-dl-{n}-{i}')
                               for n, src in enumerate(self.sources) if src not in self.banned for i in range(self.connections)]
                    for w in workers:
                        w.start()
                self.control.check()
                cursor_moved = False
                slice_end = time.time() + 1.0      # a second of reading back at a time: saving, progress and the connections are seen to between
                while cursor < st.count and st.is_done(cursor) and time.time() < slice_end:   # read back, check, and hash pieces done from the front
                    a, b = st.span(cursor)
                    h2 = h.copy()
                    got, wrong = self._hash_range(h2, a, b)
                    expected = st.digests.get(cursor)
                    if expected is not None and got != expected:
                        print(f'setup: piece {cursor} of {self.name} is not on the disk as it arrived; fetching it again', flush=True)
                        if st.redo(cursor) > PIECE_TRIES:
                            raise Failed('checksum', f'Part of {self.name} did not stay on the disk as it was downloaded, {PIECE_TRIES} times in a row. '
                                                     'The disk, or the connection to it, may be failing. What was downloaded is kept.', kept=True)
                        if not any(w.is_alive() for w in workers):
                            workers = []
                        break
                    if wrong:                      # on the disk as it arrived, but not what the torrent pins: its source sent wrong bytes
                        src = st.source.get(cursor)
                        print(f'setup: piece {cursor} of {self.name} does not match its torrent piece hash; fetching it again', flush=True)
                        if src and src != self.url and src not in self.banned:
                            self.banned.add(src)
                            print(f'setup: not using the mirror {_netloc(src)} for {self.name} again: it sent a wrong piece', flush=True)
                        if st.redo(cursor) > PIECE_TRIES:
                            raise Failed('checksum', f'Part of {self.name} kept coming out different from its published hash. '
                                                     'What was downloaded is kept.', kept=True)
                        if not any(w.is_alive() for w in workers):
                            workers = []
                        break
                    h = h2
                    st.digests.pop(cursor, None)
                    cursor += 1
                    cursor_moved = True
                now = time.time()
                if now - last_save > SAVE_EVERY or cursor_moved and cursor == st.count:
                    self._save_segments()
                    last_save = now
                if now - last_progress > 0.25:
                    if st.received() < self.size:
                        self.progress(st.received(), self.size, 'downloading')
                    else:
                        self.progress(cursor * st.size_of_piece if cursor < st.count else self.size, self.size, 'verifying')
                    last_progress = now
                if cursor == st.count:
                    break
                if workers and not any(w.is_alive() for w in workers):
                    if self.ranges_ignored:
                        return self._fall_back_to_stream(h, cursor, ctx)
                    if isinstance(self.error, _Restart):
                        print(f'setup: the file on the server changed; starting {self.name} over', flush=True)
                        with open(self.part, 'r+b') as f:
                            f.truncate(0)
                        st.reset()
                        self.etag, self.error, h, cursor, workers = None, None, hashlib.sha256(), 0, []
                        continue
                    if self.error:
                        raise self.error
                    if not st.complete():
                        raise Failed('network', 'The connection kept breaking. Check the internet connection, then try again.')
                    workers = []
                if cursor < st.count and st.is_done(cursor):
                    continue                       # more to read back now: no waiting
                with st.cv:
                    st.cv.wait(0.2)
        finally:
            self.halt.set()
            for w in workers:
                w.join(5)
            self._save_segments()
        return h, False

    def _save_segments(self):
        try:
            _save_meta(self.meta, {'url': self.url, 'size': self.size, 'sha256': self.sha256, 'etag': self.etag,
                                   'bytes_done': self.st.received(), **self.st.to_meta()})
        except OSError as e:
            print(f'setup: could not save the state of {self.name}: {e}', flush=True)

    def _hash_range(self, h, a, b):
        """Bytes a..b-1 from the disk, added to h. Returns (their own SHA-256, whether a torrent piece among them that ends here
        does not match its piece hash)."""
        own, P, piece, k, wrong = hashlib.sha256(), self.pieces, None, None, False
        with open(self.part, 'rb') as f:
            f.seek(a)
            while a < b:
                self.control.check()
                n = min(8 * CHUNK, b - a)
                if P:
                    k = a // P.length
                    n = min(n, P.span(k)[1] - a)          # never across a torrent piece
                chunk = f.read(n)
                if not chunk:
                    break
                h.update(chunk)
                own.update(chunk)
                if P:
                    if a == P.span(k)[0]:
                        piece = P.hasher(k)
                    if piece is not None:
                        piece.update(chunk)
                        if a + len(chunk) == P.span(k)[1]:
                            wrong = wrong or piece.digest() != P.hashes[k]
                            piece = None
                a += len(chunk)
        return own.digest(), wrong

    def _worker(self, ctx, src=None):
        src = src or self.url
        host, mirror = _netloc(src), src != self.url
        st, tries, busy_in_row = self.st, 0, 0
        while not self.halt.is_set() and src not in self.banned:
            try:
                self.hosts.acquire(host, self.size - st.received(), self.control, self.halt)
            except (Stopped, _Halt):
                return
            k, progressed, busy = None, False, False
            try:
                k = st.claim(self.connections * WINDOW)
                if k is None:
                    if st.complete() or not st.unclaimed():
                        return
                else:
                    progressed = self._fetch_piece(k, ctx, src)
                    tries = 0
                    if progressed and not mirror:
                        self.whole_answers = 0
            except Stopped:
                return
            except _Busy:
                self.hosts.busy_signal(host)
                busy = True
            except (_NoRanges, _Restart, Failed, ssl.SSLCertVerificationError) as e:
                if mirror:
                    self.banned.add(src)       # a mirror that will not send pieces of this very file: the others go on without it
                    print(f'setup: not using the mirror {host} for {self.name}: {type(e).__name__}', flush=True)
                    return
                if isinstance(e, _NoRanges):
                    with st.cv:                # the same hiccup hits every connection at once: within WHOLE_GAP it counts once
                        if time.time() - self.last_whole >= WHOLE_GAP:
                            self.whole_answers += 1
                            self.last_whole = time.time()
                        give_up = self.whole_answers >= NETWORK_TRIES
                    if give_up:                # not a passing hiccup: this server will not send pieces
                        self.ranges_ignored = True
                        self.halt.set()
                        return
                    tries += 1
                    print(f'setup: the server sent the whole of {self.name} for piece {k}; asking again', flush=True)
                elif isinstance(e, ssl.SSLCertVerificationError):
                    self.error = self.error or _untrusted()
                    self.halt.set()
                    return
                else:
                    self.error = self.error or e
                    self.halt.set()
                    return
            except (OSError, http.client.HTTPException, ValueError) as e:
                if disk_full(e):
                    self.error = self.error or Failed('no_space', 'The disk filled up while downloading. Free some space, then try again.')
                    self.halt.set()
                    return
                tries = 0 if getattr(e, 'progressed', False) else tries + 1
                print(f'setup: piece {k} of {self.name} broke: {type(e).__name__}: {e}; trying again', flush=True)
            finally:
                if k is not None:
                    st.release(k)
                self.hosts.release(host)
            if k is None:
                if self.halt.wait(0.5):
                    return
                continue
            if busy:
                busy_in_row += 1
                if time.time() - self.last_byte > STALL:    # a busy server only counts against a connection when nothing comes at all
                    tries += 1
                if tries >= NETWORK_TRIES:
                    print(f'setup: a connection for {self.name} gave up: the server stayed busy', flush=True)
                    return
                if self.halt.wait(BACKOFF[min(busy_in_row - 1, len(BACKOFF) - 1)]):
                    return
                continue
            busy_in_row = 0
            if tries:
                if tries >= NETWORK_TRIES:
                    print(f'setup: a connection for {self.name} gave up after {tries} tries', flush=True)
                    return
                if self.halt.wait(BACKOFF[min(tries, len(BACKOFF) - 1)]):
                    return

    def _fetch_piece(self, k, ctx, src=None):
        """Piece k from where it stands to its end, over one connection to src (the file's address, or a mirror). Returns True when
        it is done."""
        st, src = self.st, src or self.url
        a0, b = st.span(k)
        got = st.got.get(k, 0)
        conn, r, _ = _open(src, a0 + got, None, self.allowed, ctx, self.timeout, end=b - 1, mirrors=self.mirror_hosts)
        n = 0
        try:
            if r.status in (429, 503):
                raise _Busy()
            if r.status == 200:
                raise _NoRanges()
            if r.status >= 400 and r.status != 416 and r.status < 500:
                raise Failed('network', f'The download server refused the file (HTTP {r.status}).')
            if r.status != 206:
                raise OSError(f'HTTP {r.status}')
            cr = _content_range(r.getheader('Content-Range'))
            new_etag = r.getheader('ETag')
            with st.cv:
                if not cr or cr[0] != a0 + got or cr[1] != self.size:
                    raise _Restart(new_etag)
                if src == self.url:            # a mirror's ETag is its own; its pieces are checked against the torrent instead
                    if self.etag and new_etag and not _same_etag(new_etag, self.etag):
                        raise _Restart(new_etag)
                    if new_etag and not self.etag:
                        self.etag = new_etag
            hasher = st.hashers.get(k)
            if hasher is None and got == 0:
                hasher = st.hashers[k] = hashlib.sha256()
            with open(self.part, 'r+b', buffering=0) as f:
                f.seek(a0 + got)
                while a0 + got < b:
                    if self.halt.is_set():
                        raise _Halt()
                    self.control.check()
                    chunk = r.read1(min(CHUNK, b - a0 - got))
                    if not chunk:
                        raise ConnectionError('the connection closed early')
                    _write_all(f, chunk)
                    if hasher is not None:
                        hasher.update(chunk)
                    got += len(chunk)
                    n += len(chunk)
                    st.advance(k, got)
                    self.last_byte = time.time()
            st.finish(k, src)
            return True
        except _Halt:
            return False
        except (OSError, http.client.HTTPException, ValueError) as e:
            if n:
                e.progressed = True
            raise
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _fall_back_to_stream(self, h, cursor, ctx):
        """The server answered a Range with the whole file: one stream from the front, from where the pieces in order end."""
        st = self.st
        front = st.front()
        print(f'setup: the server ignores Range for {self.name}; going on in one stream from {front}', flush=True)
        a = cursor * st.size_of_piece
        if a < front:
            self._hash_range(h, a, front)
        with open(self.part, 'r+b') as f:
            f.truncate(front)
        meta = {'url': self.url, 'size': self.size, 'sha256': self.sha256, 'etag': self.etag, 'bytes_done': front}
        _save_meta(self.meta, meta)
        return self._run_stream(meta, ctx, h=h, start=front)

    # ------------------------------------------------------------------------------------------------ when it fails --
    def _recheck(self, ctx):
        """The file on the disk did not match. It is not thrown away on that alone: a zip is repaired from its central directory.
        Only a file that cannot be repaired, and is not big, is downloaded again (BadChecksum: the job tries once more). A big zip
        that still does not match is kept (Failed 'checksum', kept): Retry checks it again."""
        print(f'setup: {self.name} on the disk does not match its published checksum', flush=True)
        if self.size >= REPAIR_MIN:
            damaged = self._repair_zip(ctx)
            if damaged is not None:
                if self._rehash(self.size)[0].hexdigest() == self.sha256:
                    print(f'setup: {self.name} repaired ({damaged} damaged members fetched again)', flush=True)
                    return
                raise Failed('checksum', f'{self.name} still does not match its published checksum, so it was not used. '
                                         'What was downloaded is kept: Retry checks it again and fetches only what is wrong.',
                             kept=True)
        self.discard()
        raise BadChecksum('The downloaded file did not match its published checksum.')

    def _repair_zip(self, ctx):
        """A zip that does not match: its end (with the central directory) is fetched again from the server, every member is read
        back and checked against its CRC-32, and only the members that fail, with their headers, are fetched again. The central
        directory is the server's, so a member that passes is the server's member (a damaged one passing its CRC-32 is a chance
        of one in four billion), and the file's SHA-256 is still the final check. Returns the number of damaged members, or None if
        this is not a zip or the server will not send parts of it."""
        etag = _load_meta(self.meta).get('etag')
        tail = min(self.size, TAIL)
        print(f'setup: checking {self.name} member by member against its central directory', flush=True)
        if not self._fetch_range(self.size - tail, self.size, ctx, etag):
            return None
        try:
            with zipfile.ZipFile(self.part) as z:
                start_dir = z.start_dir
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return None
        if start_dir < self.size - tail and not self._fetch_range(start_dir, self.size - tail, ctx, etag):
            return None
        try:
            z = zipfile.ZipFile(self.part)
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return None
        bad, damaged = [], 0
        with z, open(self.part, 'rb') as raw:
            infos = sorted(z.infolist(), key=lambda i: i.header_offset)
            ends = [i.header_offset for i in infos[1:]] + [z.start_dir]
            total, done = sum(i.compress_size for i in infos) or 1, 0
            if infos and infos[0].header_offset > 0:
                bad.append((0, infos[0].header_offset))
            for info, end in zip(infos, ends):
                data_end = self._member_end(z, raw, info)
                if data_end is None:
                    damaged += 1
                    bad.append((info.header_offset, end))
                elif data_end < end:         # a data descriptor, or bytes between members: a few bytes, fetched again
                    bad.append((data_end, end))
                done += info.compress_size
                self.progress(min(done, total), total, 'verifying')
        merged = []
        for a, b in sorted(bad):
            if merged and a <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            elif b > a:
                merged.append((a, b))
        print(f'setup: {damaged} damaged members in {self.name}; fetching {sum(b - a for a, b in merged)} bytes again', flush=True)
        for a, b in merged:
            if not self._fetch_range(a, b, ctx, etag):
                return None
        return damaged

    def _member_end(self, z, raw, info):
        """Where a member's data ends, if its local header is sound and its data matches its CRC-32; None if not."""
        try:
            raw.seek(info.header_offset)
            head = raw.read(30)
            if len(head) < 30 or head[:4] != b'PK\x03\x04':
                return None
            n, e = struct.unpack('<HH', head[26:30])
            with z.open(info) as m:
                while m.read(8 * CHUNK):
                    self.control.check()
            return info.header_offset + 30 + n + e + info.compress_size
        except Stopped:
            raise
        except (zipfile.BadZipFile, zlib.error, OSError, EOFError, ValueError, NotImplementedError, RuntimeError):
            return None

    def _fetch_range(self, a, b, ctx, etag):
        """Bytes a..b-1 from the server, written where they belong. False if the server will not send just those bytes of the same
        file."""
        tries = 0
        while a < b:
            self.control.check()
            try:
                conn, r, _ = _open(self.url, a, None, self.allowed, ctx, self.timeout, end=b - 1)
                try:
                    if r.status in (429,) or 500 <= r.status < 600:
                        raise OSError(f'HTTP {r.status}')
                    cr = _content_range(r.getheader('Content-Range'))
                    if r.status != 206 or not cr or cr[0] != a or cr[1] != self.size or (etag and r.getheader('ETag') and not _same_etag(r.getheader('ETag'), etag)):
                        return False
                    with open(self.part, 'r+b', buffering=0) as f:
                        f.seek(a)
                        while a < b:
                            self.control.check()
                            chunk = r.read1(min(CHUNK, b - a))
                            if not chunk:
                                raise ConnectionError('the connection closed early')
                            _write_all(f, chunk)
                            a += len(chunk)
                            tries = 0
                finally:
                    conn.close()
            except ssl.SSLCertVerificationError:
                raise _untrusted()
            except (OSError, http.client.HTTPException, ValueError) as e:
                if disk_full(e):
                    raise Failed('no_space', 'The disk filled up while downloading. Free some space, then try again.')
                tries += 1
                if tries >= NETWORK_TRIES:
                    raise Failed('network', f'The connection kept breaking ({type(e).__name__}). Check the internet connection, then try again.')
                self.control.sleep(BACKOFF[min(tries, len(BACKOFF) - 1)])
        return True


class Segments:
    """Which pieces of a file are done, claimed by a connection, or part done. Shared by the connections of one Download."""

    def __init__(self, size, piece):
        self.size, self.size_of_piece = size, piece
        self.count = max(1, -(-size // piece))
        self.cv = threading.Condition()
        self.reset()

    def reset(self):
        with self.cv:
            self.done = bytearray(self.count)
            self.got = {}            # piece -> bytes of it on the disk, from its start (pieces part done)
            self.claimed = set()
            self.hashers = {}        # piece -> SHA-256 of what arrived, for a piece begun in this run
            self.digests = {}        # piece -> that SHA-256, once the piece is done, until it is read back and checked
            self.redos = {}          # piece -> times it was fetched again because the disk did not keep it
            self.source = {}         # piece -> the address it came from in this run
            self.cv.notify_all()

    @classmethod
    def from_meta(cls, meta, size):
        try:
            piece = int(meta.get('segment') or 0)
        except (ValueError, TypeError):
            piece = 0
        if piece <= 0 or size <= 0:
            return cls(max(size, 0), SEGMENT)
        s = cls(size, piece)
        try:
            bits = bytes.fromhex(meta.get('done') or '')
            for k in range(s.count):
                if k // 8 < len(bits) and bits[k // 8] >> (k % 8) & 1:
                    s.done[k] = 1
            s.got = {int(k): int(v) for k, v in (meta.get('got') or {}).items() if 0 <= int(k) < s.count and not s.done[int(k)]}
        except (ValueError, TypeError, AttributeError):
            s.reset()
        return s

    def to_meta(self):
        with self.cv:
            bits = bytearray(-(-self.count // 8))
            for k in range(self.count):
                if self.done[k]:
                    bits[k // 8] |= 1 << (k % 8)
            return {'segment': self.size_of_piece, 'done': bits.hex(), 'got': {str(k): v for k, v in self.got.items() if v}}

    def adopt_front(self, n):
        """The first n bytes are on the disk already (a .part from one stream)."""
        with self.cv:
            for k in range(self.count):
                a, b = self.span(k)
                if b <= n:
                    self.done[k] = 1
                elif a < n:
                    self.got[k] = n - a

    def clip(self, n):
        """Only the first n bytes are on the disk."""
        with self.cv:
            for k in range(self.count):
                a, b = self.span(k)
                if b > n and self.done[k]:
                    self.done[k] = 0
                    if a < n:
                        self.got[k] = n - a
                elif self.got.get(k) and a + self.got[k] > n:
                    self.got[k] = max(0, n - a)

    def span(self, k):
        return k * self.size_of_piece, min((k + 1) * self.size_of_piece, self.size)

    def is_done(self, k):
        return bool(self.done[k])

    def complete(self):
        return all(self.done)

    def front(self):
        """Bytes done without a gap from the start."""
        with self.cv:
            for k in range(self.count):
                if not self.done[k]:
                    return self.span(k)[0] + self.got.get(k, 0)
            return self.size

    def received(self):
        with self.cv:
            return sum(self.span(k)[1] - self.span(k)[0] for k in range(self.count) if self.done[k]) + sum(self.got.values())

    def unclaimed(self):
        with self.cv:
            return any(not self.done[k] and k not in self.claimed for k in range(self.count))

    def claim(self, window):
        """The lowest piece not done and not taken, if it is within `window` pieces of the first one not done."""
        with self.cv:
            first = next((k for k in range(self.count) if not self.done[k]), None)
            if first is None:
                return None
            for k in range(first, min(self.count, first + window)):
                if not self.done[k] and k not in self.claimed:
                    self.claimed.add(k)
                    return k
            return None

    def advance(self, k, got):
        with self.cv:
            self.got[k] = got

    def finish(self, k, src=None):
        with self.cv:
            self.done[k] = 1
            self.got.pop(k, None)
            if src:
                self.source[k] = src
            h = self.hashers.pop(k, None)
            if h is not None:
                self.digests[k] = h.digest()
            self.cv.notify_all()

    def release(self, k):
        with self.cv:
            self.claimed.discard(k)
            self.cv.notify_all()

    def redo(self, k):
        """A piece the disk did not keep as it arrived: fetched again from its start. Returns how often that has happened to it."""
        with self.cv:
            self.done[k] = 0
            self.got.pop(k, None)
            self.hashers.pop(k, None)
            self.digests.pop(k, None)
            self.redos[k] = self.redos.get(k, 0) + 1
            self.source.pop(k, None)
            self.cv.notify_all()
            return self.redos[k]


def _netloc(url):
    return (urllib.parse.urlsplit(url).netloc or '').lower()


def _untrusted():
    return Failed('network', 'Lastbook could not confirm it is talking to the download server, so it stopped. '
                             'A network that intercepts secure connections (some offices, hotels) can cause this.')


class _Restart(Exception):
    def __init__(self, etag, whole=False):
        super().__init__('restart')
        self.etag, self.whole = etag, whole


class _Busy(Exception):
    """503 or 429: the server has enough connections."""


class _NoRanges(Exception):
    """A 200 to a Range: this server will not send pieces."""


class _Halt(Exception):
    """Another connection of the same download stopped it (a failure, a changed file), or it is complete."""
