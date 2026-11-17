"""Eigener Worker mit hartem Speicherlimit und überwachter verstrichener Zeit."""
from dataclasses import asdict
from pathlib import Path
import json
import os
import queue
import subprocess
import sys
import threading
import time
from .models import SkillAuditResult, Finding, Artifact, Execution
from .safeio import Limits

def windows_job(process, limit):
    import ctypes
    from ctypes import wintypes as w
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", w.DWORD), ("min_working_set", ctypes.c_size_t),
                    ("max_working_set", ctypes.c_size_t), ("active", w.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops","write_ops","other_ops","read_bytes","write_bytes","other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                    ("peak_job", ctypes.c_size_t)]
    k.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
    k.CreateJobObjectW.restype = w.HANDLE
    k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
    k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    k.CloseHandle.argtypes = [w.HANDLE]
    handle = k.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "Job Object nicht verfügbar")
    try:
        info = Extended()
        info.basic.flags = 0x100 | 0x2000  # process committed memory + kill on close
        info.process_memory = limit
        if not k.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "Speicherlimit nicht aktivierbar")
        if not k.AssignProcessToJobObject(handle, w.HANDLE(int(process._handle))):
            raise OSError(ctypes.get_last_error(), "Worker nicht in Job aufnehmbar")
    except BaseException:
        k.CloseHandle(handle)
        raise
    return lambda: k.CloseHandle(handle)

def result_from_wire(data):
    data = dict(data)
    data["findings"] = [Finding(**item) for item in data["findings"]]
    data["artifact"] = Artifact(**data["artifact"])
    data["execution"] = Execution(**data["execution"])
    return SkillAuditResult(**data)

def run_worker(request, limits):
    result = SkillAuditResult(str(Path(os.path.abspath(request.get("path", ".")))),
                              Path(request.get("path", ".")).name)
    result.input_details = {"limits": asdict(limits), "identity": "incomplete", "hard_guard": False}
    process = None
    close_job = None
    started = time.monotonic()
    events = queue.Queue(maxsize=32)
    stopped = threading.Event()
    reader = None

    def receive():
        total = 0
        try:
            while not stopped.is_set():
                line = process.stdout.readline(8 * 1024 * 1024 + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > 8 * 1024 * 1024 or total > 32 * 1024 * 1024:
                    item = {"error": "Worker-Ausgabebudget überschritten"}
                else:
                    item = json.loads(line)
                while not stopped.is_set():
                    try:
                        events.put(item, timeout=0.05)
                        break
                    except queue.Full:
                        pass
                if "error" in item:
                    break
        except (ValueError, OSError):
            try:
                events.put({"error": "Ungültige Worker-Ausgabe"}, timeout=0.1)
            except queue.Full:
                pass
        finally:
            while not stopped.is_set():
                try:
                    events.put({"eof": True}, timeout=0.05)
                    break
                except queue.Full:
                    pass

    try:
        if os.name != "nt" and not sys.platform.startswith("linux"):
            raise OSError("Kein geprüfter Prozesswächter für diese Plattform")
        worker = Path(__file__).with_name("worker.py")
        process = subprocess.Popen([sys.executable, "-I", "-B", str(worker)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   creationflags=0x08000000 if os.name == "nt" else 0)
        if os.name == "nt":
            close_job = windows_job(process, limits.memory_bytes)
        request = {**request, "limits": asdict(limits)}
        process.stdin.write((json.dumps(request, ensure_ascii=True) + "\n").encode("ascii"))
        process.stdin.close()
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        final = None
        while True:
            remaining = limits.seconds - (time.monotonic() - started)
            if remaining <= 0:
                result.error = "Hartes Zeitbudget überschritten; Worker beendet"
                result.error_code = 'worker_timeout'
                break
            try:
                event = events.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if "error" in event:
                result.error = event["error"]
                result.error_code = 'worker_output_error'
                break
            if event.get("eof"):
                if final is None:
                    result.error = "Worker abgebrochen; Speicherlimit oder Laufzeitfehler"
                    result.error_code = 'worker_failed'
                else:
                    result = final
                break
            if event.get("ready"):
                result.input_details.update(hard_guard=True, memory_metric=event["memory_metric"],
                                            wall_clock_guard=True)
            if "progress" in event:
                delta = event["progress"]
                result.execution.scanner_executed = True
                result.findings.extend(Finding(**item) for item in delta["findings"])
                result.files_scanned.extend(delta["files"])
                result.skipped_files.extend(delta["gaps"])
            if "result" in event:
                final = result_from_wire(event["result"])
                from .privacy import Redactor
                context = event.get('redaction_context', {})
                final._redactor = Redactor(context.get('values', []))
                final._redactor.detected = context.get('detected', False)
                final._redactor.exhausted = context.get('exhausted', False)
                final.input_details.update(hard_guard=True, wall_clock_guard=True,
                                           memory_metric=result.input_details.get("memory_metric", "unknown"))
        if result.error:
            from .privacy import Redactor
            if not hasattr(result, '_redactor'):
                result._redactor = Redactor()
                result._redactor.context_incomplete = True
            result.content_hash = None
            result.input_details["identity"] = "incomplete"
    except (OSError, ValueError, TypeError) as exc:
        result.error = "Prozesswächter nicht verfügbar: " + type(exc).__name__
        result.error_code = 'guard_unavailable'
        from .privacy import Redactor
        result._redactor = Redactor()
        result._redactor.context_incomplete = True
        result.content_hash = None
    finally:
        stopped.set()
        if process:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if reader:
                reader.join(timeout=2)
            if process.stdout:
                process.stdout.close()
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        if close_job:
            close_job()
    return result

def audit_input(path, limits=None):
    return run_worker({"path": str(path)}, limits or Limits())
