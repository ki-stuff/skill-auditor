#!/usr/bin/env python3
"""
Skill Auditor - Automatischer Sicherheits-Scan fuer Claude Code Skills
Verwendung: python audit.py <skill-verzeichnis> [skill-verzeichnis2 ...]
"""

import sys
import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# Windows: UTF-8 Output erzwingen
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─── Pattern-Definitionen ────────────────────────────────────────────────────

PATTERNS = {
    "A_NETWORK": {
        "risk": "HIGH",
        "label": "Netzwerk / Datenexfiltration",
        "patterns": [
            (r"\bcurl\b",                         "curl-Aufruf"),
            (r"\bwget\b",                         "wget-Aufruf"),
            (r"requests\.(get|post|put|delete)",  "Python requests"),
            (r"\burllib\b",                       "urllib"),
            (r"fetch\(",                          "JS fetch()"),
            (r"\baxios\b",                        "axios"),
            (r"XMLHttpRequest",                   "XHR"),
        ],
        "reject_if": [
            r"(~/.ssh|~/.aws|\.env|api_key|password|token|secret).*?(curl|fetch|requests|urllib|wget)",
            r"(curl|fetch|requests|urllib|wget).*(~/.ssh|~/.aws|\.env|api_key|password|token|secret)",
            r"base64\.(encode|b64encode).*?(send|post|upload|curl|fetch)",
            r"whoami|hostname.*?(curl|fetch|post|send)",
        ],
    },
    "B_ENCODING": {
        "risk": "HIGH",
        "label": "Obfuskierung / Encoding",
        "patterns": [
            (r"\bbase64\b",                       "base64"),
            (r"\batob\(",                         "atob()"),
            (r"String\.fromCharCode",             "fromCharCode"),
            (r"\\x[0-9a-fA-F]{2}",               "Hex-Escape"),
            (r"\\u[0-9a-fA-F]{4}",               "Unicode-Escape"),
            (r"eval\s*\(",                        "eval()"),
        ],
        "reject_if": [],
    },
    "C_EXEC": {
        "risk": "CRITICAL",
        "label": "Code-Ausfuehrung",
        "patterns": [
            (r"\bexec\s*\(",                      "exec()"),
            (r"os\.system\s*\(",                  "os.system()"),
            (r"subprocess\.",                     "subprocess"),
            (r"child_process",                    "child_process (Node)"),
            (r"__import__\s*\(",                  "__import__()"),
            (r"compile\s*\(.*eval",               "compile+eval"),
        ],
        "reject_if": [
            r"curl\s*\|+\s*bash",
            r"wget\s*\|+\s*sh",
        ],
    },
    "D_PACKAGES": {
        "risk": "HIGH",
        "label": "Package-Installation / Privilege Escalation",
        "patterns": [
            (r"\bpip\s+install\b",                "pip install"),
            (r"\bnpm\s+install\b",                "npm install"),
            (r"\bapt(-get)?\s+install\b",         "apt install"),
            (r"\bsudo\b",                         "sudo"),
            (r"\bchmod\s+777\b",                  "chmod 777"),
            (r"\bchown\b",                        "chown"),
        ],
        "reject_if": [
            r"PATH\s*=.*\$PATH",
            r"(crontab|cron\.d|LaunchAgents|launchctl)",
            r"\.(bashrc|zshrc|profile|bash_profile)\s*>>",
        ],
    },
    "E_PROMPT_INJECTION": {
        "risk": "CRITICAL",
        "label": "Prompt Injection & Social Engineering",
        "patterns": [
            (r"ignore.{0,30}previous",            "ignore previous instructions"),
            (r"you are now",                      "Rollenneuzuweisung EN"),
            (r"du bist jetzt",                    "Rollenneuzuweisung DE"),
            (r"forget all",                       "forget all instructions"),
            (r"vergiss alles",                    "Vergiss-Anweisung"),
            (r"<system-reminder>",                "Fake <system-reminder>"),
            (r"<system>",                         "Fake <system>-Tag"),
            (r"<tool_result>",                    "Fake <tool_result>-Tag"),
            (r"override.{0,30}instructions",      "override instructions"),
            (r"trust this skill",                 "trust-forcing"),
            (r"skip.{0,20}vetting",               "vetting bypass"),
            (r"disable.{0,20}safety",             "safety disable"),
            (r"your new purpose",                 "purpose reassignment"),
        ],
        "reject_if": [],
    },
    "F_PERSISTENCE": {
        "risk": "CRITICAL",
        "label": "Persistence & Stealth",
        "patterns": [
            (r"\bcrontab\b",                      "crontab"),
            (r"LaunchAgents",                     "macOS LaunchAgents"),
            (r"\.(bashrc|zshrc)",                 ".bashrc/.zshrc Modifikation"),
            (r"settings\.json",                   "settings.json Zugriff"),
            (r"CLAUDE\.md",                       "CLAUDE.md Zugriff"),
            (r"MEMORY\.md",                       "MEMORY.md Zugriff"),
            (r"SOUL\.md|IDENTITY\.md",            "Identity-Dateien"),
            (r"self.*update|update.*self",        "Self-Update Mechanismus"),
        ],
        "reject_if": [],
    },
    "G_SECRETS": {
        "risk": "HIGH",
        "label": "Secrets & Credential-Zugriff",
        "patterns": [
            (r"~/.ssh",                           "SSH-Verzeichnis"),
            (r"~/.aws",                           "AWS Credentials"),
            (r"\.env\b",                          ".env Datei"),
            (r"api_key|apikey|api-key",           "API Key Zugriff"),
            (r"password|passwd|passwort",         "Passwort-Zugriff"),
            (r"secret[_\s]key|secret_token",     "Secret Token"),
            (r"private_key|privatekey",           "Private Key"),
        ],
        "reject_if": [],
    },
    "H_TIMEBOMB": {
        "risk": "MEDIUM",
        "label": "Time Bombs / Bedingte Logik",
        "patterns": [
            (r"datetime\.now\(\)|Date\.now\(\)|time\.time\(\)", "Zeitabfrage"),
            (r"if.{0,50}date.{0,30}>",           "Datums-Bedingung"),
            (r"if.{0,50}version.{0,30}[><=]",   "Versions-Bedingung"),
        ],
        "reject_if": [],
    },
}

READABLE_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".ts", ".sh", ".bash",
    ".json", ".yaml", ".yml", ".toml", ".html", ".css",
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

# ─── Datenstrukturen ──────────────────────────────────────────────────────────

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

@dataclass
class SkillAuditResult:
    skill_path: str
    skill_name: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def verdict(self) -> str:
        if any(f.is_reject or f.risk == "CRITICAL" for f in self.findings):
            return "🔴 NICHT VERWENDEN"
        if any(f.risk == "HIGH" for f in self.findings):
            return "🟡 HINWEISE BEACHTEN"
        if self.findings:
            return "🟡 HINWEISE BEACHTEN"
        return "🟢 UNBEDENKLICH"

    @property
    def short_verdict(self) -> str:
        if any(f.is_reject or f.risk == "CRITICAL" for f in self.findings):
            return "🔴 REJECT"
        if any(f.risk == "HIGH" for f in self.findings):
            return "🟡 CAUTION"
        if self.findings:
            return "🟡 CAUTION"
        return "🟢 SAFE"

    @property
    def max_risk(self) -> str:
        if not self.findings:
            return "NONE"
        # RISK_ORDER: lower number = more severe (CRITICAL=0). min() surfaces the worst one.
        return min(self.findings, key=lambda f: RISK_ORDER.get(f.risk, 99)).risk

# ─── Scanner ─────────────────────────────────────────────────────────────────

def collect_files(skill_dir: Path) -> list[Path]:
    files = []
    for f in skill_dir.rglob("*"):
        if f.is_file() and f.suffix.lower() in READABLE_EXTENSIONS:
            files.append(f)
    return sorted(files)


def _code_fence_mask(lines: list[str]) -> list[bool]:
    """Returns a bool list: True = line is inside a fenced code block."""
    inside = False
    mask = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            inside = not inside
        mask.append(inside)
    return mask


# Categories skipped when inside markdown code fences.
# E_PROMPT_INJECTION is included: regex patterns in fenced blocks are
# documentation examples, not live injections. A real injector would use prose.
SKIP_IN_FENCES = {"A_NETWORK", "B_ENCODING", "C_EXEC", "D_PACKAGES",
                  "E_PROMPT_INJECTION", "F_PERSISTENCE", "G_SECRETS", "H_TIMEBOMB"}


def _strip_code_blocks(content: str) -> str:
    """Remove fenced code blocks (``` or ~~~) from markdown content."""
    result = []
    inside = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            inside = not inside
            result.append("")
        elif not inside:
            result.append(line)
        else:
            result.append("")
    return "\n".join(result)


def scan_file(filepath: Path, skill_dir: Path) -> list[Finding]:
    findings = []
    rel_path = str(filepath.relative_to(skill_dir))

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings, urls

    lines = content.splitlines()
    is_md = filepath.suffix.lower() == ".md"
    fence_mask = _code_fence_mask(lines) if is_md else [False] * len(lines)
    # For reject_if full-content scans: strip code blocks in .md files first
    scan_content = _strip_code_blocks(content) if is_md else content

    for cat_key, cat in PATTERNS.items():
        risk = cat["risk"]
        label = cat["label"]

        for pat_str, description in cat["patterns"]:
            try:
                pat = re.compile(pat_str, re.IGNORECASE)
            except re.error:
                continue
            for lineno, line in enumerate(lines, start=1):
                if is_md and fence_mask[lineno - 1] and cat_key in SKIP_IN_FENCES:
                    continue
                if pat.search(line):
                    snippet = line.strip()[:120]
                    findings.append(Finding(
                        category=cat_key,
                        risk=risk,
                        label=label,
                        file=rel_path,
                        line=lineno,
                        description=description,
                        snippet=snippet,
                        is_reject=False,
                    ))

        for reject_str in cat.get("reject_if", []):
            try:
                reject_pat = re.compile(reject_str, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue
            if reject_pat.search(scan_content):
                findings.append(Finding(
                    category=cat_key,
                    risk="CRITICAL",
                    label=label,
                    file=rel_path,
                    line=0,
                    description=f"REJECT-Pattern: {reject_str[:60]}",
                    snippet="(ganzer Dateiinhalt)",
                    is_reject=True,
                ))

    return findings


def audit_skill(skill_path: str) -> SkillAuditResult:
    skill_dir = Path(skill_path).resolve()
    skill_name = skill_dir.name
    result = SkillAuditResult(skill_path=str(skill_dir), skill_name=skill_name)

    if not skill_dir.exists():
        result.error = f"Verzeichnis nicht gefunden: {skill_dir}"
        return result

    files = collect_files(skill_dir)
    if not files:
        result.error = "Keine lesbaren Dateien gefunden"
        return result

    for f in files:
        rel = str(f.relative_to(skill_dir))
        result.files_scanned.append(rel)
        result.findings.extend(scan_file(f, skill_dir))

    result.findings.sort(key=lambda f: (RISK_ORDER.get(f.risk, 99), f.file, f.line))
    return result

# ─── Report-Ausgabe ──────────────────────────────────────────────────────────

def print_report(result: SkillAuditResult) -> None:
    sep = "═" * 60

    if result.error:
        print(f"\n{sep}")
        print(f"Skill-Audit: {result.skill_name}")
        print(f"FEHLER: {result.error}")
        print(sep)
        return

    print(f"\n{sep}")
    print(f"Skill-Audit: {result.skill_name}")
    print(sep)
    print(f"Pfad:             {result.skill_path}")
    print(f"Geprüfte Dateien: {len(result.files_scanned)}")
    for f in result.files_scanned:
        print(f"  · {f}")
    print(f"Gesamtbewertung:  {result.verdict}")
    print()

    if not result.findings:
        print("Keine Auffälligkeiten gefunden.")
    else:
        print(f"{'#':<4} {'Risiko':<10} {'Kategorie':<35} {'Datei:Zeile':<30} {'Beschreibung'}")
        print("─" * 120)
        for i, f in enumerate(result.findings, 1):
            emoji = RISK_EMOJI.get(f.risk, "")
            loc = f"{f.file}:{f.line}" if f.line else f.file
            reject_marker = " [REJECT]" if f.is_reject else ""
            print(f"{i:<4} {emoji}{f.risk:<9} {f.label:<35} {loc:<30} {f.description}{reject_marker}")
            if f.snippet and f.snippet != "(ganzer Dateiinhalt)":
                print(f"     └─ {f.snippet}")

    print()
    print("Empfehlung:", result.verdict)
    print(sep)


def write_json_report(result: SkillAuditResult) -> Optional[Path]:
    """Schreibt audit-result.json neben dem geprueften Skill-Verzeichnis."""
    if result.error:
        return None
    out_path = Path(result.skill_path) / "audit-result.json"
    data = {
        "skill": result.skill_name,
        "path": result.skill_path,
        "overall_risk": result.verdict,
        "max_risk": result.max_risk,
        "files_scanned": result.files_scanned,
        "total_findings": len(result.findings),
        "findings": [
            {
                "category": f.category,
                "label": f.label,
                "risk": f.risk,
                "file": f.file,
                "line": f.line,
                "description": f.description,
                "snippet": f.snippet,
                "is_reject": f.is_reject,
            }
            for f in result.findings
        ],
    }
    try:
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path
    except OSError:
        return None


def print_batch_summary(results: list[SkillAuditResult]) -> None:
    print("\n")
    print("BATCH-AUDIT")
    print("═" * 55)
    print(f"{'Skill':<30} {'Risiko':<10} {'Verdict'}")
    print("─" * 55)
    for r in results:
        risk = r.max_risk if not r.error else "ERROR"
        print(f"{r.skill_name:<30} {risk:<10} {r.short_verdict}")
    print("─" * 55)
    total = len(results)
    flags = sum(1 for r in results if r.findings)
    rejects = sum(1 for r in results if "REJECT" in r.short_verdict)
    print(f"Gesamt: {total} Skills | {flags} mit Flags | {rejects} Rejections")
    print("═" * 55)

# ─── Einstiegspunkt ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Verwendung: python audit.py <skill-verzeichnis> [skill-verzeichnis2 ...]")
        print("Beispiel:   python audit.py C:/Users/ss/.claude/skills/some-skill")
        sys.exit(1)

    skill_paths = sys.argv[1:]
    results = []

    for path in skill_paths:
        result = audit_skill(path)
        print_report(result)
        json_path = write_json_report(result)
        if json_path:
            print(f"  JSON-Report: {json_path}")
        results.append(result)

    if len(results) > 1:
        print_batch_summary(results)

    has_reject = any("REJECT" in r.short_verdict for r in results)
    sys.exit(1 if has_reject else 0)


if __name__ == "__main__":
    main()
