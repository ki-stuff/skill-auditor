"""Plattformneutrale Ergebnisobjekte; keine Suche nach installierten Skills."""
from dataclasses import dataclass, field
from typing import Optional
import datetime
import platform
import sys
from .rules import RISK_ORDER

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

@dataclass
class Artifact:
    path: str
    name: str
    type: str = "skill"
    source: Optional[str] = None
    version: Optional[str] = None
    target_platform: str = "unspecified"
    components: list[dict] = field(default_factory=list)

@dataclass
class Execution:
    profile: str = "core-local"
    surface: str = "python-api"
    os: str = field(default_factory=platform.system)
    runtime: str = field(default_factory=lambda: platform.python_version())
    interpreter: str = field(default_factory=lambda: sys.executable)
    scan_mode: str = "static-text"
    scanner_executed: bool = False

@dataclass
class Finding:
    category: str
    risk: str
    label: str
    file: str
    line: int
    description: str
    snippet: str
    is_reject: bool = False
    in_code_fence: bool = False
    original_risk: Optional[str] = None
    context_reason: Optional[str] = None

@dataclass
class AuditResult:
    skill_path: str
    skill_name: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    skipped_files: list[dict] = field(default_factory=list)
    content_hash: Optional[str] = None
    source_commit: Optional[str] = None
    source_commit_note: Optional[str] = None
    error: Optional[str] = None

    artifact: Optional[Artifact] = None
    execution: Execution = field(default_factory=Execution)
    audited_at: str = field(default_factory=utc_now)
    input_details: dict = field(default_factory=dict)
    error_code: Optional[str] = None

    def __post_init__(self):
        if self.artifact is None:
            self.artifact = Artifact(path=self.skill_path, name=self.skill_name)

    @property
    def coverage(self) -> dict:
        # Beschreibt den vorhandenen Textscanner, keine vollständige Codeprüfung.
        from .scanner import PREVIOUS_REPORT_REASON

        def excluded(item):
            return item["file"].endswith(".git/") or item.get("reason") == PREVIOUS_REPORT_REASON

        gaps = [dict(item) for item in self.skipped_files if not excluded(item)]
        for finding in self.findings:
            if finding.category in {"K_COVERAGE", "J_SYMLINK"}:
                gaps.append({"file": finding.file, "reason": finding.description})
        if self.error:
            gaps.append({"file": self.skill_path, "reason": self.error})
        if not self.execution.scanner_executed:
            gaps.append({"file": self.skill_path, "reason": "Scanner nicht ausgeführt"})
        limited = {item["file"] for item in gaps}
        return {
            "status": "insufficient" if self.error or not self.execution.scanner_executed
                      else ("partial" if gaps else "complete_for_text_scope"),
            "scope": "Statische Musterprüfung lesbarer Dateien; keine Ausführung oder Sicherheitsgarantie",
            "checked": [p for p in self.files_scanned if p not in limited],
            "partial_or_unexamined": gaps,
            "exclusions": [dict(item) for item in self.skipped_files if excluded(item)],
            "limits": self.input_details.get("limits") or {
                "global_resource_limits": "not_reported" if self.execution.scanner_executed
                                          else "not_applied_this_run"},
            "hash_scope": "bounded_regular_file_records" if self.input_details else "regular_files_except_git_plus_link_targets",
            "hash_limitations": ("Zweifach beobachteter Stand, kein atomarer Dateisystem-Snapshot; Links ungeprüft."
                                 if self.input_details else "Kein atomarer Snapshot; Lesefehler können Platzhalter ergeben."),
        }

    @property
    def execution_status(self) -> str:
        if self.error:
            return "aborted"
        if not self.execution.scanner_executed:
            return "not_executed"
        return "completed" if self.coverage["status"] == "complete_for_text_scope" else "limited"

    @property
    def assessment(self) -> dict:
        if not self.execution.scanner_executed and not self.findings:
            return {"risk": None, "verdict": None, "status": "unavailable"}
        return {"risk": self.max_risk, "verdict": self.verdict,
                "status": "reject" if any(f.is_reject or f.risk == "CRITICAL" for f in self.verdict_findings)
                else "caution" if self.max_risk in {"HIGH", "MEDIUM"}
                else "insufficient" if self.coverage["status"] != "complete_for_text_scope"
                else "clear"}

    @property
    def verdict_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.risk != "CONTEXT"]

    @property
    def verdict(self) -> str:
        if any(f.is_reject or f.risk == "CRITICAL" for f in self.verdict_findings):
            return "🔴 NICHT VERWENDEN"
        if any(f.risk in ("HIGH", "MEDIUM") for f in self.verdict_findings):
            return "🟡 MANUELL PRÜFEN"
        if self.coverage["status"] != "complete_for_text_scope":
            return "⚪ NICHT AUSREICHEND GEPRÜFT"
        return "🟢 KEINE OFFENSICHTLICHEN BEFUNDE"

    @property
    def scanner_verdict(self) -> str:
        return self.verdict

    @property
    def short_verdict(self) -> str:
        if any(f.is_reject or f.risk == "CRITICAL" for f in self.verdict_findings):
            return "🔴 REJECT"
        if any(f.risk in ("HIGH", "MEDIUM") for f in self.verdict_findings):
            return "🟡 PRÜFEN"
        if self.coverage["status"] != "complete_for_text_scope":
            return "⚪ NICHT AUSREICHEND GEPRÜFT"
        return "🟢 KEINE OFFENSICHTLICHEN BEFUNDE"

    @property
    def max_risk(self) -> str:
        # Kompatible Befundstufe: NONE ist keine Aussage über ungeprüfte Inhalte.
        # Ausführung und Abdeckung bestimmen die verständliche Risikoanzeige.
        if not self.verdict_findings:
            return "NONE"
        # RISK_ORDER: lower number = more severe (CRITICAL=0). min() surfaces the worst one.
        return min(self.verdict_findings, key=lambda f: RISK_ORDER.get(f.risk, 99)).risk


# Kompatibilitätsname für Aufrufer von 1.0.x.
SkillAuditResult = AuditResult
