"""Budgets, eindeutige Namen und nicht folgenden Dateizugriff."""
from dataclasses import dataclass, asdict
from contextlib import contextmanager, ExitStack
from pathlib import Path
import os
import stat
import time
import unicodedata

class InputError(ValueError):
    pass

@dataclass(frozen=True)
class Limits:
    compressed_bytes: int = 50 * 1024 * 1024
    entries: int = 10000
    total_bytes: int = 200 * 1024 * 1024
    text_bytes: int = 2_000_000
    member_bytes: int = 25 * 1024 * 1024
    seconds: float = 60
    memory_bytes: int = 512 * 1024 * 1024
    metadata_bytes: int = 4 * 1024 * 1024
    findings: int = 2000

    def __post_init__(self):
        import math
        for key, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("Ungültiges Budget: " + key)
            if key != "seconds" and not isinstance(value, int):
                raise ValueError("Ganzzahliges Budget erforderlich: " + key)

class Budget:
    def __init__(self, limits):
        self.limits = limits
        self.started = time.monotonic()
        self.bytes = 0
        self.entries = 0
        self.metadata = 0

    def check(self):
        if time.monotonic() - self.started > self.limits.seconds:
            raise InputError("Zeitbudget überschritten")

    def consume(self, size):
        self.check()
        self.bytes += size
        if self.bytes > self.limits.total_bytes:
            raise InputError("Gesamtlesebudget überschritten")

    def entry(self, name):
        self.check()
        self.entries += 1
        self.metadata += len(name.encode("utf-8", errors="replace"))
        if self.entries > self.limits.entries:
            raise InputError("Eintragsbudget überschritten")
        if self.metadata > self.limits.metadata_bytes:
            raise InputError("Metadatenbudget überschritten")

def linked(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)

def signature(st):
    # Windows 3.13 kann ctime bei stat/fstat unterschiedlich zuordnen.
    # Zweiter Inhalts-Hash sichert zusätzlich gleiche Größe/mtime ab.
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)

def valid_name(name):
    if not isinstance(name, str) or not name or len(name) > 4096:
        raise InputError("Ungültiger oder zu langer Pfad")
    if name.startswith(("/", "\\")) or "\\" in name or ":" in name:
        raise InputError("Absoluter, Laufwerks-, UNC-, ADS- oder Backslash-Pfad")
    parts = name.rstrip("/").split("/")
    for part in parts:
        base = part.split(".")[0].upper()
        if (part in ("", ".", "..") or part.endswith((" ", "."))
                or any(ord(c) < 32 or ord(c) == 127 for c in part)
                or any(c in '<>"|?*' for c in part)
                or base in {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
                or base in {f"{p}{n}" for p in ("COM", "LPT") for n in "123456789¹²³"}):
            raise InputError("Mehrdeutiger, reservierter oder ausbrechender Pfad")
    return "/".join(parts)

class Names:
    def __init__(self):
        self.explicit = set()
        self.types = {}
        self.paths = {}

    def add(self, name, directory=False):
        name = valid_name(name)
        key = unicodedata.normalize("NFC", name).casefold()
        if key in self.explicit:
            raise InputError("Doppelter oder kollidierender Eintrag")
        parts = key.split("/")
        original_parts = name.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            spelling = "/".join(original_parts[:i])
            if parent in self.paths and self.paths[parent] != spelling:
                raise InputError("Kollidierende Verzeichnisschreibweisen")
            if self.types.get(parent) == "file":
                raise InputError("Datei-/Verzeichniskollision")
            self.types[parent] = "directory"
            self.paths[parent] = spelling
        kind = "directory" if directory else "file"
        if key in self.paths and self.paths[key] != name:
            raise InputError("Kollidierende Verzeichnisschreibweisen")
        if key in self.types and self.types[key] != kind:
            raise InputError("Datei-/Verzeichniskollision")
        self.explicit.add(key)
        self.types[key] = kind
        self.paths[key] = name
        return name

@contextmanager
def _win_handle(path, directory):
    import ctypes
    from ctypes import wintypes as w
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    k.CreateFileW.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    class Info(ctypes.Structure):
        _fields_ = [("attrs", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                    ("written", w.FILETIME), ("volume", w.DWORD), ("size_hi", w.DWORD),
                    ("size_lo", w.DWORD), ("links", w.DWORD), ("index_hi", w.DWORD), ("index_lo", w.DWORD)]
    k.GetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
    # No WRITE/DELETE sharing: path ancestors and data cannot be replaced while held.
    handle = k.CreateFileW(str(path), 0 if directory else 0x80000000, 1, None, 3,
                           0x00200000 | (0x02000000 if directory else 0), None)
    if handle == w.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), "Geschütztes Öffnen fehlgeschlagen")
    try:
        info = Info()
        if not k.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "Handleprüfung fehlgeschlagen")
        if info.attrs & 0x400 or bool(info.attrs & 0x10) != directory:
            raise InputError("Link/Reparse Point oder falscher Dateityp")
        if not directory and info.links > 1:
            raise InputError("Mehrfach verlinkte Datei wird nicht gelesen")
        yield handle
    finally:
        k.CloseHandle(handle)

@contextmanager
def guarded_path(path, directory=False):
    """Hält die gesamte Elternkette; Windows Handles, POSIX dir_fd/O_NOFOLLOW."""
    path = Path(os.path.abspath(path))
    with ExitStack() as stack:
        if os.name == "nt":
            for parent in reversed(path.parents):
                stack.enter_context(_win_handle(parent, True))
            handle = stack.enter_context(_win_handle(path, directory))
            if directory:
                yield path
            else:
                # Duplicate: Python stream owns only the duplicate handle.
                import ctypes, msvcrt
                from ctypes import wintypes as w
                k = ctypes.WinDLL("kernel32", use_last_error=True)
                k.GetCurrentProcess.restype = w.HANDLE
                k.DuplicateHandle.argtypes = [w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD]
                duplicate = w.HANDLE()
                proc = k.GetCurrentProcess()
                if not k.DuplicateHandle(proc, handle, proc, ctypes.byref(duplicate), 0, False, 2):
                    raise OSError(ctypes.get_last_error(), "Handleduplikat fehlgeschlagen")
                fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
                with os.fdopen(fd, "rb") as stream:
                    yield stream
        elif os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
            fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, fd)
            for part in path.parts[1:-1]:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                stack.callback(os.close, fd)
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            if directory:
                flags |= os.O_DIRECTORY
            final = os.open(path.name, flags, dir_fd=fd)
            st = os.fstat(final)
            if (directory and not stat.S_ISDIR(st.st_mode)) or (
                    not directory and (not stat.S_ISREG(st.st_mode) or st.st_nlink > 1)):
                os.close(final)
                raise InputError("Kein regulärer unverlinkter Dateityp")
            if directory:
                stack.callback(os.close, final)
                yield final
            else:
                with os.fdopen(final, "rb") as stream:
                    yield stream
        else:
            raise InputError("Nicht folgender Dateizugriff auf dieser Plattform nicht verfügbar")

def bounded_read(stream, budget, ceiling, keep=True):
    import hashlib
    digest = hashlib.sha256()
    chunks = []
    count = 0
    while True:
        budget.check()
        allowance = min(65536, ceiling - count + 1, budget.limits.total_bytes - budget.bytes + 1)
        chunk = stream.read(max(1, allowance))
        if not chunk:
            break
        budget.consume(len(chunk))
        count += len(chunk)
        if count > ceiling:
            raise InputError("Datei-/Mitgliedsbudget überschritten")
        digest.update(chunk)
        if keep:
            chunks.append(chunk)
    return b"".join(chunks), digest.hexdigest(), count

def write_exclusive(path, text):
    """Neue Ausgabe über gehaltene Elternkette; keine Links oder Überschreibung."""
    path = Path(os.path.abspath(path))
    for part in path.parts[1:]:
        valid_name(part)
    with ExitStack() as stack:
        if os.name == "nt":
            for parent in reversed(path.parents):
                if not parent.exists():
                    parent.mkdir()
                stack.enter_context(_win_handle(parent, True))
            import ctypes, msvcrt
            from ctypes import wintypes as w
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateFileW.argtypes = [w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE]
            k.CreateFileW.restype = w.HANDLE
            handle = k.CreateFileW(str(path), 0x40000000, 1, None, 1, 0x00200000, None)
            if handle == w.HANDLE(-1).value:
                err = ctypes.get_last_error()
                if err in (80, 183):
                    raise FileExistsError("Vorhandene Ausgabe wird nicht ersetzt")
                raise OSError(err, "Geschützte Ausgabe fehlgeschlagen")
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            with os.fdopen(fd, "wb") as stream:
                stream.write(text.encode("utf-8"))
        elif os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
            fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, fd)
            for part in path.parts[1:-1]:
                try:
                    os.mkdir(part, dir_fd=fd)
                except FileExistsError:
                    pass
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                stack.callback(os.close, fd)
            final = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(final, "wb") as stream:
                stream.write(text.encode("utf-8"))
        else:
            raise InputError("Geschützte Ausgabe nicht verfügbar")

