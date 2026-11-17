"""Sharing downloads with other people: the person's own choice, off unless they turn it on (Library and local AI → Share).

With sharing on, setup keeps each downloaded file whose torrent is pinned in the manifest (engine/setup/torrent.py) instead of
deleting it once it is unpacked: in <library>.share beside the library, with its .torrent. While Lastbook is open those files
are seeded by rqbit, a BitTorrent program bundled with the app (by Igor Katson, Apache-2.0; the build fetches a pinned
release, packaging/share/). Lastbook itself opens no port and connects to nothing here: it starts rqbit, stops it, and asks it
(engine/setup/download.local_api) how much it has uploaded, which is added up across runs (Tally). rqbit is started
  - with its control API on 127.0.0.1 only, behind a password made for that run, and no UPnP (the router is not changed),
    saving no DHT state,
  - with only the torrents Lastbook hands it, each checked against its pinned pieces root first,
  - checking each file against its torrent before it uploads a byte (its own check, --overwrite),
  - tied to Lastbook: on Windows a job object ends it with the app, on Linux the parent-death signal, and on a Mac it is ended
    when the app exits.
Peers it meets see this computer's address, as with any BitTorrent program; the setting says so.
"""
import atexit
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

SUFFIX = '.share'
TALLY_EVERY = 15                    # seconds between readings of what rqbit has uploaded


def binary():
    """The bundled rqbit, or None (this build has none: sharing is not offered)."""
    name = 'rqbit.exe' if os.name == 'nt' else 'rqbit'
    places = []
    if getattr(sys, 'frozen', False):
        places.append(Path(getattr(sys, '_MEIPASS', Path(sys.executable).parent)) / 'share' / name)
    places.append(Path(__file__).resolve().parents[2] / 'derived' / 'share' / name)
    return next((p for p in places if p.is_file()), None)


def folder_for(target):
    """Where the kept downloads of a library go: <library>.share beside it."""
    return Path(target).with_name(Path(target).name + SUFFIX)


def arguments(folder, torrents, upload_bps=None, port=None):
    """rqbit's arguments to seed `torrents` (paths of .torrent files) whose data is in `folder`, its control API on 127.0.0.1:port."""
    args = ['--disable-dht-persistence', '--disable-upnp-port-forward', '-v', 'warn']
    if upload_bps:
        args += ['--ratelimit-upload', str(int(upload_bps))]
    if port:
        args += ['--http-api-listen-addr', f'127.0.0.1:{int(port)}']
    return args + ['download', '--overwrite'] + ([] if port else ['--disable-http-api']) + ['-o', str(folder)] + [str(t) for t in torrents]


def uploaded(port, secret):
    """What the rqbit at 127.0.0.1:port has uploaded since it started, from its own count, or None."""
    from . import download
    r = download.local_api(port, secret, 'GET', '/stats')
    if not r or r[0] != 200:
        return None
    try:
        n = json.loads(r[1])['counters']['uploaded_bytes']
    except (ValueError, KeyError, TypeError):
        return None
    return n if isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 1 << 62 else None


class Tally:
    """Bytes uploaded to other people, all time, in its own file (not setup.json, which other actions rewrite). rqbit counts
    from 0 each time it starts, so each reading adds what came since that process's last reading, and a smaller one starts
    again from 0."""

    def __init__(self, path):
        self.path, self.lock, self.last = Path(path), threading.Lock(), {}

    def total(self):
        try:
            n = json.loads(self.path.read_text(encoding='utf-8')).get('uploaded_bytes', 0)
            return n if isinstance(n, int) and n >= 0 else 0
        except (OSError, ValueError, AttributeError):
            return 0

    def add(self, readings):
        """readings: {process: bytes it has uploaded so far}. Returns the total."""
        with self.lock:
            total, grew = self.total(), False
            for key, now in readings.items():
                if now is None:
                    continue
                before = self.last.get(key, 0)
                step = now - before if now >= before else now
                self.last[key] = now
                if step:
                    total += step
                    grew = True
            if grew:
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    tmp = self.path.with_suffix('.tmp')
                    tmp.write_text(json.dumps({'uploaded_bytes': total}), encoding='utf-8')
                    os.replace(tmp, self.path)
                except OSError as e:
                    print(f'setup: could not save what was shared: {e}', flush=True)
            return total


class Seeder:
    """The rqbit processes seeding the kept files: one for each folder of data, each with its control API on 127.0.0.1 behind its
    own password, read every TALLY_EVERY seconds for what it has uploaded. command: the program to run instead of the bundled
    rqbit (tests). tally: where the uploaded bytes are added up."""

    def __init__(self, command=None, tally=None):
        self.command, self.tally = command, tally
        self.procs = []
        self.lock = threading.Lock()
        self._job = None
        self._watch = None
        atexit.register(self.stop)

    def available(self):
        return bool(self.command or binary())

    def start(self, groups, upload_bps=None):
        """groups: {data folder: [torrent paths]}. Whatever ran before is stopped first. Returns the number of files seeded."""
        self.stop()
        prog = list(self.command) if self.command else ([str(binary())] if binary() else None)
        if not prog:
            return 0
        n = 0
        with self.lock:
            for folder, torrents in groups.items():
                if not torrents:
                    continue
                from . import download
                port, secret = download.loopback_port(), secrets.token_urlsafe(24)
                kw = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'close_fds': True,
                      'env': {**os.environ, 'RQBIT_HTTP_BASIC_AUTH_USERPASS': f'lastbook:{secret}'}}
                if os.name == 'nt':
                    kw['creationflags'] = 0x08000000          # CREATE_NO_WINDOW
                elif sys.platform.startswith('linux'):
                    kw['preexec_fn'] = _die_with_parent
                try:
                    p = subprocess.Popen(prog + arguments(folder, torrents, upload_bps, port), **kw)
                except OSError as e:
                    print(f'setup: sharing could not start: {e}', flush=True)
                    continue
                if os.name == 'nt':
                    self._tie(p)
                self.procs.append((p, str(folder), [str(t) for t in torrents], port, secret))
                n += len(torrents)
            if n and self.tally is not None and not (self._watch and self._watch.is_alive()):
                self._watch = threading.Thread(target=self._count, daemon=True, name='setup-share-count')
                self._watch.start()
        if n:
            print(f'setup: sharing {n} files with BitTorrent', flush=True)
        return n

    def running(self):
        """[(data folder, [torrent paths])] of the processes still running."""
        with self.lock:
            return [(f, t) for p, f, t, _, _ in self.procs if p.poll() is None]

    def readings(self):
        """{process: bytes uploaded so far} of the processes running."""
        with self.lock:
            procs = list(self.procs)
        return {(p.pid, port): uploaded(port, secret) for p, _, _, port, secret in procs if p.poll() is None}

    def shared(self):
        """All the bytes uploaded to other people so far, with what the running processes say now."""
        if self.tally is None:
            return 0
        return self.tally.add(self.readings())

    def _count(self):
        while True:
            with self.lock:
                if not self.procs:
                    return
            self.shared()
            time.sleep(TALLY_EVERY)

    def stop(self):
        if self.tally is not None:
            self.shared()                  # the last reading, before the count goes with the process
        with self.lock:
            procs, self.procs = self.procs, []
        for p, _, _, _, _ in procs:
            if p.poll() is None:
                p.terminate()
        for p, _, _, _, _ in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()

    def _tie(self, p):
        """Windows: rqbit goes in a job object that ends it when Lastbook ends, however it ends."""
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL('kernel32', use_last_error=True)
            if self._job is None:
                class IO(ctypes.Structure):
                    _fields_ = [(n, ctypes.c_ulonglong) for n in ('r', 'w', 'o', 'rb', 'wb', 'ob')]

                class Basic(ctypes.Structure):
                    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong), ('PerJobUserTimeLimit', ctypes.c_longlong),
                                ('LimitFlags', wintypes.DWORD), ('MinimumWorkingSetSize', ctypes.c_size_t),
                                ('MaximumWorkingSetSize', ctypes.c_size_t), ('ActiveProcessLimit', wintypes.DWORD),
                                ('Affinity', ctypes.c_size_t), ('PriorityClass', wintypes.DWORD), ('SchedulingClass', wintypes.DWORD)]

                class Extended(ctypes.Structure):
                    _fields_ = [('Basic', Basic), ('Io', IO), ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                                ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]
                k32.CreateJobObjectW.restype = wintypes.HANDLE
                job = k32.CreateJobObjectW(None, None)
                info = Extended()
                info.Basic.LimitFlags = 0x2000                    # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                if not job or not k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info)):
                    raise OSError(ctypes.get_last_error(), 'job object')
                self._job = job                                   # held open for the app's life: closing it ends the processes
            if not k32.AssignProcessToJobObject(wintypes.HANDLE(self._job), wintypes.HANDLE(int(p._handle))):
                raise OSError(ctypes.get_last_error(), 'AssignProcessToJobObject')
        except (OSError, AttributeError, ValueError) as e:
            print(f'setup: sharing is not tied to Lastbook ({e}); it stops when Lastbook exits normally', flush=True)


def _die_with_parent():
    """Linux, in the child before rqbit starts: SIGTERM when Lastbook ends."""
    try:
        import ctypes
        import signal
        ctypes.CDLL(None).prctl(1, signal.SIGTERM)                # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass
