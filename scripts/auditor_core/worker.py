"""Nur intern vom eigenen Supervisor gestartet; keinerlei Prüfobjektcode ausführen."""
import json
import sys
from pathlib import Path
from dataclasses import asdict
# Ausschließlich der vertrauenswürdige Paketpfad, niemals Eingabe/CWD/PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor_core.safeio import Limits
from auditor_core.inputs import audit_local

def emit(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=True) + "\n")
    sys.stdout.flush()

def main():
    request = json.loads(sys.stdin.buffer.readline(65536))
    limits = Limits(**request["limits"])
    if sys.platform.startswith("linux"):
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        metric = "virtual_address_space"
    elif sys.platform == "win32":
        # Parent attaches the Job Object before delivering the request.
        metric = "process_committed_memory"
    else:
        raise RuntimeError("Kein Speicherwächter")
    emit({"ready": True, "memory_metric": metric})
    # Ausschließlich eigene kleine Wächtertests; kein frei wählbarer Code oder Befehl.
    if request.get("probe") == "time":
        import time
        time.sleep(5)
    if request.get("probe") == "memory":
        blocks = []
        try:
            while True:
                blocks.append(bytearray(8 * 1024 * 1024))
        except MemoryError:
            emit({"error": "Speichergrenze ausgelöst: MemoryError"})
            return
    previous = [0, 0, 0]
    def progress(result):
        counts = [len(result.findings), len(result.files_scanned), len(result.skipped_files)]
        if counts != previous:
            # A killed worker may not yet have seen the file declaring a secret.
            # Interim messages retain severity but no source-controlled prose.
            findings = []
            for f in result.findings[previous[0]:]:
                item = asdict(f)
                item.update(file='[Fundstelle bei Abbruch zurückgehalten]', snippet='',
                            description='Befund vor Abbruch erkannt', context_reason=None)
                findings.append(item)
            emit({"progress": {"findings": findings,
                               "files": ['[Datei vor Abbruch gelesen]' for _ in result.files_scanned[previous[1]:]],
                               "gaps": [{'file': '[Datei zurückgehalten]', 'reason': 'Prüflücke vor Abbruch'} for _ in result.skipped_files[previous[2]:]]}})
            previous[:] = counts
            if request.get("probe") == "time_after_progress" and result.findings:
                import time
                time.sleep(5)
    result = audit_local(request["path"], limits, progress, supervised=True)
    redactor = result._redactor
    # Private pipe only: context is never a report field or written to disk.
    emit({"result": asdict(result), "redaction_context": {
        "values": sorted(redactor.secrets), "detected": redactor.detected,
        "exhausted": redactor.exhausted}})

if __name__ == "__main__":
    main()
