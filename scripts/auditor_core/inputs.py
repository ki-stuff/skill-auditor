"""Begrenzter virtueller Dateibestand. Archive werden nie extrahiert."""
from dataclasses import asdict
from pathlib import Path
import hashlib
import io
import os
import stat
import gzip
import tarfile
import zipfile
from .models import SkillAuditResult, Finding
from .rules import READABLE_EXTENSIONS, READABLE_FILENAMES, RISK_ORDER
from .safeio import Limits, Budget, InputError, Names, guarded_path, linked, signature, bounded_read

ARCHIVE_ENDINGS = (".zip", ".mcpb", ".dxt", ".whl", ".tar", ".tar.gz", ".tgz")

def archive_kind(data):
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if len(data) >= 512 and data[257:262] == b"ustar":
        return "tar"
    return None

def _record(name, size, digest):
    return [name, size, digest]

def _identity(records):
    import json
    raw = json.dumps(sorted(records), ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()

class VirtualInput:
    def __init__(self, path, limits, result, progress):
        self.path = Path(os.path.abspath(path))
        self.budget = Budget(limits)
        self.result = result
        from .privacy import Redactor
        self.result._redactor = Redactor()
        self.progress = progress
        self.names = Names()
        self.records = []
        self.local_records = {}
        self.directories = {}
        self.complete_hash = True
        from .adapters import Adapters
        self.adapters = Adapters(self)
        self.previous_reports = []
        self.previous_report_mentioned = False
        self.scanned_texts = {}

    def gap(self, name, reason, risk=None):
        self.result.skipped_files.append({"file": name, "reason": reason})
        if risk:
            if len(self.result.findings) >= self.budget.limits.findings:
                raise InputError("Befundbudget überschritten")
            self.result.findings.append(Finding("K_COVERAGE", risk, "Eingabeschutz", name, 0, reason, ""))
        self.progress(self.result)

    def consume_file(self, name, stream, declared_size, archive=False):
        limit = self.budget.limits
        ceiling = limit.member_bytes if archive else limit.total_bytes
        if declared_size > ceiling:
            self.complete_hash = False
            self.gap(name, "Mitglieds-/Dateibudget überschritten", "MEDIUM")
            return None
        from .adapters import is_metadata
        textual = (Path(name).suffix.lower() in READABLE_EXTENSIONS or Path(name).name in READABLE_FILENAMES
                   or is_metadata(name) or Path(name).name in {"binding.gyp", "yarn.lock", "uv.lock", "poetry.lock"})
        keep = declared_size <= limit.text_bytes
        data, digest, count = bounded_read(stream, self.budget, ceiling, keep=keep)
        # Known credential containers remain coverage gaps where unsupported,
        # but their already-read bytes may protect other public output fields.
        if Path(name).name.lower().startswith('.env') or Path(name).suffix.lower() in {'.pem', '.key'}:
            self.result._redactor.detected = True
            if keep:
                try:
                    self.result._redactor.observe_file(name, data.decode('utf-8', errors='strict'))
                except UnicodeError:
                    pass
        if count != declared_size:
            raise InputError("Dateigröße während Lesen verändert")
        self.records.append(_record(name, count, digest))
        if name.lower().endswith(ARCHIVE_ENDINGS) or (keep and archive_kind(data)):
            self.gap(name, "Inneres Archiv: keine automatische Öffnung")
        elif not textual:
            self.gap(name, "Dateityp wird nur gehasht, nicht inhaltlich geprüft")
        elif not keep:
            self.gap(name, "Textdateigrenze überschritten; Inhalt nur gehasht", "MEDIUM")
        else:
            try:
                content = data.decode("utf-8", errors="strict")
            except UnicodeError:
                self.gap(name, "Datei konnte nicht als UTF-8 gelesen werden", "MEDIUM")
            else:
                from .scanner import is_previous_auditor_report, PREVIOUS_REPORT_REASON
                self.result._redactor.observe_file(name, content)
                if is_previous_auditor_report(name, content):
                    # Vorläufig als Ausnahme; wird nachgeprüft, falls eine andere
                    # Datei darauf verweist (siehe resolve_previous_reports).
                    self.result.skipped_files.append({"file": name, "reason": PREVIOUS_REPORT_REASON})
                    self.previous_reports.append((name, content, count))
                    self.progress(self.result)
                    return digest
                if "audit-result.json" in content.lower():
                    self.previous_report_mentioned = True
                self._scan_content(name, content, count)
        self.progress(self.result)
        return digest

    def _scan_content(self, name, content, count):
        from .scanner import scan_text
        from .adapters import is_metadata
        limit = self.budget.limits
        self.result.files_scanned.append(name)
        self.scanned_texts[name] = content.lower()
        findings = scan_text(content, name, Path(name).suffix.lower() == ".md")
        self.adapters.capture(name, content, count)
        # Structured configuration may contain credentials. Never emit raw
        # snippets for these files, including early worker progress.
        if ((is_metadata(name) and Path(name).name != "setup.py")
                or Path(name).suffix.lower() in {".json", ".toml", ".yaml", ".yml"}):
            for finding in findings:
                finding.snippet = "[Konfigurationsbeleg nicht als Rohwert ausgegeben]"
        room = limit.findings - len(self.result.findings)
        self.result.findings.extend(findings[:max(0, room)])
        self.progress(self.result)
        if len(findings) > room:
            raise InputError("Befundbudget überschritten; weitere Treffer ungeprüft")

    def resolve_previous_reports(self):
        """Altberichte nur ausnehmen, solange keine andere Datei auf sie verweist.

        Sonst ließe sich eine Anweisung in einer Datei im Altberichtsformat
        verstecken und aus der SKILL.md heraus aufrufen.
        """
        if not self.previous_reports or not self.previous_report_mentioned:
            return
        from .scanner import PREVIOUS_REPORT_REASON
        names = {name for name, _, _ in self.previous_reports}
        self.result.skipped_files = [item for item in self.result.skipped_files
                                     if not (item.get("reason") == PREVIOUS_REPORT_REASON
                                             and item["file"] in names)]
        for name, content, count in self.previous_reports:
            self.result.findings.append(Finding(
                "E_PROMPT_INJECTION", "MEDIUM", "Verweis auf Altberichtsdatei", name, 0,
                "Eine Skill-Datei verweist auf audit-result.json; die Datei wird deshalb "
                "als Skill-Inhalt geprüft", ""))
            self._scan_content(name, content, count)
        self.previous_reports = []

    def resolve_referenced_examples(self):
        """Codebeispiel-Kombinationen hochstufen, wenn eine andere Datei auf die Datei verweist.

        Beispiel: Die SKILL.md sagt "folge dem Setup in README.md", und der
        Codeblock der README liest ~/.ssh und sendet es per curl.
        """
        from .scanner import FENCE_COMBINATION_DESCRIPTION
        for finding in self.result.findings:
            if finding.description != FENCE_COMBINATION_DESCRIPTION or finding.risk != "CONTEXT":
                continue
            target = Path(finding.file).name.lower()
            if any(target in text for other, text in self.scanned_texts.items() if other != finding.file):
                finding.risk = "MEDIUM"
        self.scanned_texts = {}

    def _list(self, directory, count):
        entries = []
        with guarded_path(directory, directory=True) as handle:
            with os.scandir(handle) as listing:
                for entry in listing:
                    self.budget.check()
                    name = str(Path(directory).relative_to(self.path) / entry.name).replace("\\", "/")
                    if count:
                        self.budget.entry(name)
                    elif len(entries) >= self.budget.limits.entries:
                        raise InputError("Verzeichnis während Prüfung gewachsen")
                    # Windows DirEntry.stat liefert für dev/ino teils Nullwerte.
                    st = (os.stat(Path(directory) / entry.name, follow_symlinks=False)
                          if os.name == "nt" else entry.stat(follow_symlinks=False))
                    entries.append((entry.name, st))
        return sorted(entries, key=lambda item: item[0])

    def directory(self):
        pending = [self.path]
        while pending:
            directory = pending.pop()
            entries = self._list(directory, True)
            self.directories[str(directory)] = [(n, signature(s)) for n, s in entries]
            for basename, st in entries:
                path = directory / basename
                rel = path.relative_to(self.path).as_posix()
                if basename == ".git" and stat.S_ISDIR(st.st_mode) and not linked(st):
                    self.result.skipped_files.append({"file": rel + "/", "reason": "Git-Metadaten ausgeschlossen"})
                    continue
                if linked(st) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)) or (
                        stat.S_ISREG(st.st_mode) and st.st_nlink > 1):
                    self.complete_hash = False
                    self.gap(rel, "Link/Reparse Point, Hardlink oder Spezialdatei nicht verfolgt", "HIGH")
                    continue
                try:
                    name = self.names.add(rel, stat.S_ISDIR(st.st_mode))
                except InputError as exc:
                    self.complete_hash = False
                    self.gap(rel, str(exc), "HIGH")
                    continue
                if stat.S_ISDIR(st.st_mode):
                    pending.append(path)
                    continue
                try:
                    with guarded_path(path) as stream:
                        opened = os.fstat(stream.fileno())
                        if signature(opened) != signature(st):
                            raise InputError("Datei zwischen Auflistung und Öffnen verändert")
                        digest = self.consume_file(name, stream, st.st_size)
                        if signature(os.fstat(stream.fileno())) != signature(opened):
                            raise InputError("Datei während Prüfung verändert")
                    if digest:
                        self.local_records[str(path)] = (signature(opened), digest)
                except OSError as exc:
                    self.complete_hash = False
                    self.gap(name, "Datei nicht lesbar: " + type(exc).__name__, "MEDIUM")
        self.verify_directory()

    def verify_directory(self):
        # Erneut genau die geprüften Bytes lesen, innerhalb desselben Gesamtbudgets.
        for path, (before, expected_digest) in self.local_records.items():
            with guarded_path(path) as stream:
                if signature(os.fstat(stream.fileno())) != before:
                    raise InputError("Prüfobjekt nach Textscan verändert")
                _, digest, _ = bounded_read(stream, self.budget, self.budget.limits.total_bytes, keep=False)
                if digest != expected_digest or signature(os.fstat(stream.fileno())) != before:
                    raise InputError("Inhalt während Prüfung verändert")
        for path, expected in self.directories.items():
            actual = [(n, signature(st)) for n, st in self._list(Path(path), False)]
            if actual != expected:
                raise InputError("Verzeichnisbestand während Prüfung verändert")

    def standalone(self, supervised):
        with guarded_path(self.path) as stream:
            before = signature(os.fstat(stream.fileno()))
            size = before[2]
            header = stream.read(512)
            self.budget.consume(len(header))
            stream.seek(0)
            kind = archive_kind(header)
            declared_archive = self.path.name.lower().endswith(ARCHIVE_ENDINGS)
            if kind or declared_archive:
                if not supervised:
                    raise InputError("Archivprüfung benötigt harten Prozesswächter")
                if size > self.budget.limits.compressed_bytes:
                    raise InputError("Komprimierte Eingabe überschreitet Budget")
                raw, raw_hash, _ = bounded_read(stream, self.budget, self.budget.limits.compressed_bytes)
                self.result.input_details["container_sha256"] = "sha256:" + raw_hash
                self.result.artifact.type = "archive"
                self.result.input_details["container_format"] = kind or "unknown"
                expected = ("zip" if self.path.name.lower().endswith((".zip", ".mcpb", ".dxt", ".whl"))
                            else "gzip" if self.path.name.lower().endswith((".tgz", ".tar.gz"))
                            else "tar" if self.path.name.lower().endswith(".tar") else None)
                if expected and expected != kind:
                    self.gap(self.path.name, "Dateiendung und Signatur widersprechen sich", "MEDIUM")
                if kind == "zip":
                    self.zip(raw)
                elif kind in ("tar", "gzip"):
                    self.tar(raw, kind)
                else:
                    raise InputError("Keine unterstützte Archivsignatur")
            else:
                self.result.artifact.type = "file"
                self.result.input_details["container_format"] = "file"
                self.budget.entry(self.path.name)
                self.consume_file(self.names.add(self.path.name), stream, size)
            if signature(os.fstat(stream.fileno())) != before:
                raise InputError("Eingabedatei während Prüfung verändert")
            stream.seek(0)
            _, after_hash, _ = bounded_read(stream, self.budget, self.budget.limits.total_bytes, keep=False)
            expected_hash = raw_hash if kind or declared_archive else self.records[0][2] if self.records else None
            if expected_hash != after_hash:
                raise InputError("Eingabedatei nach Prüfung verändert")

    def zip(self, raw):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            for entry in entries:
                self.budget.entry(entry.orig_filename)
                self.budget.metadata += len(entry.extra) + len(entry.comment)
                if self.budget.metadata > self.budget.limits.metadata_bytes:
                    raise InputError("ZIP-Metadatenbudget überschritten")
                try:
                    name = self.names.add(entry.orig_filename, entry.is_dir())
                except InputError as exc:
                    self.complete_hash = False
                    self.gap(entry.orig_filename[:4096], str(exc), "HIGH")
                    continue
                mode = entry.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    self.complete_hash = False
                    self.gap(name, "Link oder Spezialdatei im ZIP nicht gelesen", "HIGH")
                    continue
                if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    self.complete_hash = False
                    self.gap(name, "Verschlüsseltes oder nicht unterstütztes ZIP-Verfahren", "MEDIUM")
                    continue
                if entry.is_dir():
                    continue
                if entry.file_size > self.budget.limits.member_bytes:
                    self.complete_hash = False
                    self.gap(name, "Archivmitglied überschreitet Budget", "MEDIUM")
                    continue
                with archive.open(entry) as stream:
                    self.consume_file(name, stream, entry.file_size, archive=True)

    def tar(self, raw, kind):
        source = gzip.GzipFile(fileobj=io.BytesIO(raw)) if kind == "gzip" else io.BytesIO(raw)
        budget = self.budget
        class Counting:
            def read(self, size=-1):
                budget.check()
                amount = min(65536 if size < 0 else size, budget.limits.total_bytes-budget.bytes+1)
                data = source.read(max(1, amount))
                budget.consume(len(data))
                return data
        # All decompressed bytes including headers/PAX/padding count before tar parsing.
        try:
            with tarfile.open(fileobj=Counting(), mode="r|") as archive:
                for entry in archive:
                    self.budget.entry(entry.name)
                    self.budget.metadata += sum(len(str(k))+len(str(v)) for k,v in entry.pax_headers.items())
                    if self.budget.metadata > self.budget.limits.metadata_bytes:
                        raise InputError("TAR-Metadatenbudget überschritten")
                    try:
                        name = self.names.add(entry.name, entry.isdir())
                    except InputError as exc:
                        self.complete_hash = False
                        self.gap(entry.name[:4096], str(exc), "HIGH")
                        continue
                    if entry.isdir():
                        continue
                    if not entry.isfile() or entry.sparse is not None:
                        self.complete_hash = False
                        self.gap(name, "TAR-Link, Sparse- oder Spezialdatei nicht gelesen", "HIGH")
                        continue
                    if entry.size > self.budget.limits.member_bytes:
                        self.complete_hash = False
                        self.gap(name, "Archivmitglied überschreitet Budget", "MEDIUM")
                        continue
                    with archive.extractfile(entry) as stream:
                        # Counting counts the raw decoded stream; this second charge is conservative.
                        self.consume_file(name, stream, entry.size, archive=True)
                # Force decompressor trailer/CRC validation, including trailing stream bytes.
                while Counting().read(65536):
                    pass
        finally:
            source.close()

def audit_local(path, limits=None, progress=None, supervised=False):
    """Interner Worker; ungeschützte Archivaufrufe werden abgewiesen."""
    limits = limits or Limits()
    result = SkillAuditResult(str(Path(os.path.abspath(path))), Path(path).name)
    result.input_details = {"limits": asdict(limits), "identity": "incomplete",
                            "hash_algorithm": "sha256-canonical-file-records-v2",
                            "hard_guard": supervised, "container_format": "unknown"}
    reader = VirtualInput(path, limits, result, progress or (lambda r: None))
    try:
        if sys_version_too_old():
            raise InputError("Python ab 3.11 erforderlich")
        if os.name == "nt" and str(reader.path).startswith("\\\\"):
            raise InputError("UNC-/Gerätepfade sind keine unterstützte lokale Eingabe")
        st = reader.path.lstat()
        if linked(st):
            raise InputError("Eingabewurzel ist ein Link/Reparse Point")
        result.execution.scanner_executed = True
        if stat.S_ISDIR(st.st_mode):
            result.input_details["container_format"] = "directory"
            reader.directory()
        elif stat.S_ISREG(st.st_mode):
            reader.standalone(supervised)
        else:
            raise InputError("Eingabe ist kein regulärer Dateityp")
        reader.resolve_previous_reports()
        reader.resolve_referenced_examples()
        reader.adapters.run()
        result.input_details["identity"] = "stable_observed" if reader.complete_hash else "incomplete"
        if reader.complete_hash:
            directories = [[reader.names.paths[key] + "/", 0, "directory"]
                           for key, kind in reader.names.types.items() if kind == "directory"]
            result.content_hash = _identity(reader.records + directories)
        result.source_commit_note = "Keine Suche nach Git-Metadaten außerhalb des Prüfobjekts"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, RuntimeError,
            MemoryError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        result.error = str(exc) if isinstance(exc, InputError) else "Eingabeprüfung abgebrochen: " + type(exc).__name__
        if isinstance(exc, FileNotFoundError):
            result.error_code = 'input_not_found'
        elif isinstance(exc, PermissionError):
            result.error_code = 'input_access_denied'
        result.content_hash = None
        result.input_details["identity"] = "incomplete"
    result.input_details.update(bytes_read=reader.budget.bytes, entries=reader.budget.entries)
    result.findings.sort(key=lambda f: (RISK_ORDER.get(f.risk, 99), f.file, f.line))
    return result

def sys_version_too_old():
    import sys
    return sys.version_info < (3, 11)
