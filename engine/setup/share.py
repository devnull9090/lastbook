"""Sharing downloads with other people: the person's own choice, off unless they turn it on (Library and local AI → Share).

With sharing on, setup keeps each downloaded file whose torrent is pinned in the manifest (engine/setup/torrent.py) instead of
deleting it once it is unpacked: in <library>.share beside the library, with its .torrent. While Lastbook is open those files
are seeded by rqbit, a BitTorrent program bundled with the app (by Igor Katson, Apache-2.0; the build fetches a pinned
release, packaging/share/). Lastbook itself still opens no port and makes no connection here: it starts rqbit and
stops it. rqbit is started
  - with no HTTP API (nothing listens for commands) and no UPnP (the router is not changed), saving no DHT state,
  - with only the torrents Lastbook hands it, each checked against its pinned pieces root first,
  - checking each file against its torrent before it uploads a byte (its own check, --overwrite),
  - tied to Lastbook: on Windows a job object ends it with the app, on Linux the parent-death signal, and on a Mac it is ended
    when the app exits.
Peers it meets see this computer's address, as with any BitTorrent program; the setting says so.
"""
import atexit
import os
import subprocess
import sys
import threading
from pathlib import Path

SUFFIX = '.share'


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


def arguments(folder, torrents, upload_bps=None):
    """rqbit's arguments to seed `torrents` (paths of .torrent files) whose data is in `folder`."""
    args = ['--disable-dht-persistence', '--disable-upnp-port-forward', '-v', 'warn']
    if upload_bps:
        args += ['--ratelimit-upload', str(int(upload_bps))]
    return args + ['download', '--overwrite', '--disable-http-api', '-o', str(folder)] + [str(t) for t in torrents]


class Seeder:
    """The rqbit processes seeding the kept files: one for each folder of data. command: the program to run instead of the bundled
    rqbit (tests)."""

    def __init__(self, command=None):
        self.command = command
        self.procs = []
        self.lock = threading.Lock()
        self._job = None
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
                kw = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL, 'close_fds': True}
                if os.name == 'nt':
                    kw['creationflags'] = 0x08000000          # CREATE_NO_WINDOW
                elif sys.platform.startswith('linux'):
                    kw['preexec_fn'] = _die_with_parent
                try:
                    p = subprocess.Popen(prog + arguments(folder, torrents, upload_bps), **kw)
                except OSError as e:
                    print(f'setup: sharing could not start: {e}', flush=True)
                    continue
                if os.name == 'nt':
                    self._tie(p)
                self.procs.append((p, str(folder), [str(t) for t in torrents]))
                n += len(torrents)
        if n:
            print(f'setup: sharing {n} files with BitTorrent', flush=True)
        return n

    def running(self):
        """[(data folder, [torrent paths])] of the processes still running."""
        with self.lock:
            return [(f, t) for p, f, t in self.procs if p.poll() is None]

    def stop(self):
        with self.lock:
            procs, self.procs = self.procs, []
        for p, _, _ in procs:
            if p.poll() is None:
                p.terminate()
        for p, _, _ in procs:
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
