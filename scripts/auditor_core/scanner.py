"""Lesender statischer Textscanner für Skill-Dateien."""
import os
import re
import hashlib
from pathlib import Path
from typing import Optional
from .rules import *
from .models import Finding, SkillAuditResult
# ─── Scanner ─────────────────────────────────────────────────────────────────

# Kompatibilitätskonstante; Dateinamen allein begründen keine Ausnahme mehr.
OWN_ARTIFACT_FILES = {"audit-result.json", "skill-inventory-cache.json", "skill-inventory-raw.json"}

# Frühere Auditor-Fassungen (bis 2.5) legten audit-result.json im geprüften
# Skill ab. Der Inhalt besteht aus Fundstellen-Auszügen früherer Scans; ein
# erneuter Textscan würde diese Auszüge als neue Treffer werten.
PREVIOUS_REPORT_REASON = (
    "Frühere Auditor-Berichtsdatei (Format bis 2.5); als Altbericht gelesen, "
    "nicht als Skill-Inhalt gewertet"
)
_PREVIOUS_REPORT_KEYS = {"skill", "path", "overall_risk", "max_risk", "audited_at",
                         "files_scanned", "total_findings", "findings"}
_PREVIOUS_FINDING_KEYS = {"category", "description", "file", "is_reject", "label",
                          "line", "risk", "snippet"}


def is_previous_auditor_report(name: str, content: str) -> bool:
    """Erkennt nur exakt das alte Berichtsformat; Name allein genügt nicht."""
    import json
    if Path(name).name != "audit-result.json" or len(content) > 2_000_000:
        return False
    try:
        data = json.loads(content)
    except ValueError:
        return False
    if not isinstance(data, dict) or set(data) != _PREVIOUS_REPORT_KEYS:
        return False
    if not isinstance(data["findings"], list) or not isinstance(data["files_scanned"], list):
        return False
    if not all(isinstance(v, str) for v in data["files_scanned"]):
        return False
    for key in ("skill", "path", "overall_risk", "max_risk", "audited_at"):
        if not isinstance(data[key], str):
            return False
    if type(data["total_findings"]) is not int:
        return False
    for finding in data["findings"]:
        if not isinstance(finding, dict) or not set(finding) <= _PREVIOUS_FINDING_KEYS:
            return False
        if not all(isinstance(v, (str, int, bool)) or v is None for v in finding.values()):
            return False
    return True


def collect_files_and_skipped(skill_dir: Path) -> tuple[list[Path], list[Path], list[dict]]:
    """Liefert Scan-Dateien, Hash-Dateien und transparent ausgelassene Inhalte."""
    scan_files = []
    hash_files = []
    skipped = []
    def walk_error(exc):
        skipped.append({"file": str(exc.filename or skill_dir),
                        "reason": "Verzeichnis nicht lesbar: " + type(exc).__name__})
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False, onerror=walk_error):
        kept_dirs = []
        for dirname in dirnames:
            directory = Path(dirpath) / dirname
            rel = directory.relative_to(skill_dir).as_posix()
            if dirname == ".git":
                skipped.append({
                    "file": f"{rel}/",
                    "reason": "Git-Metadaten werden nicht als Skill-Inhalt gescannt",
                })
            elif directory.is_symlink():
                # Symlinks werden separat bewertet und in den Inhalts-Hash aufgenommen.
                continue
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            f = Path(dirpath) / filename
            rel = f.relative_to(skill_dir).as_posix()
            if f.is_symlink():
                # Symlinks werden separat bewertet und in den Inhalts-Hash aufgenommen.
                continue
            if not f.is_file():
                skipped.append({"file": rel, "reason": "Kein regulärer Dateityp"})
                continue

            hash_files.append(f)
            if f.suffix.lower() in READABLE_EXTENSIONS or f.name in READABLE_FILENAMES:
                scan_files.append(f)
                try:
                    oversized = f.stat().st_size > MAX_SCAN_FILE_BYTES
                except OSError:
                    oversized = False
                if oversized:
                    skipped.append({
                        "file": rel,
                        "reason": (
                            f"Größer als {MAX_SCAN_FILE_BYTES} Bytes; Inhalt wird gehasht, "
                            "aber nicht vollständig automatisch geprüft"
                        ),
                    })
            else:
                skipped.append({
                    "file": rel,
                    "reason": "Dateityp wird nicht automatisch inhaltlich geprüft; Inhalt wird nur gehasht",
                })

    return sorted(scan_files), sorted(hash_files), sorted(skipped, key=lambda item: item["file"])


def collect_files(skill_dir: Path) -> list[Path]:
    """Kompatibilitätshelfer für Inventar und bestehende Aufrufer."""
    scan_files, _, _ = collect_files_and_skipped(skill_dir)
    return scan_files


def content_hash(files: list[Path], skill_dir: Path) -> str:
    digest = hashlib.sha256()
    for filepath in files:
        rel = filepath.relative_to(skill_dir).as_posix().encode("utf-8")
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        try:
            size = filepath.stat().st_size
            digest.update(size.to_bytes(8, "big"))
            with filepath.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        except OSError:
            digest.update((12).to_bytes(8, "big"))
            digest.update(b"<UNREADABLE>")

    symlinks = []
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(dirpath) / name
            if path.is_symlink():
                try:
                    target = os.readlink(path)
                except OSError:
                    target = "<UNREADABLE>"
                symlinks.append((path.relative_to(skill_dir).as_posix(), target))
    for rel_path, target in sorted(symlinks):
        digest.update(f"SYMLINK:{rel_path}->{target}".encode("utf-8", errors="replace"))
    return f"sha256:{digest.hexdigest()}"


def detect_git_commit(skill_dir: Path) -> tuple[Optional[str], str]:
    """Liest HEAD direkt und führt dabei weder Git noch Code des Prüfobjekts aus."""
    for repository_root in (skill_dir, *skill_dir.parents):
        marker = repository_root / ".git"
        if not marker.exists():
            continue
        if marker.is_file():
            return None, (
                "Ausgelagerte Git-Metadaten erkannt; der externe gitdir-Verweis wird "
                "aus Sicherheitsgründen nicht verfolgt"
            )
        if not marker.is_dir():
            return None, "Git-Metadaten haben einen unerwarteten Dateityp"

        try:
            head = (marker / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            return None, f"Git-HEAD konnte nicht gelesen werden: {exc}"

        if re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
            return head.lower(), "Direkt aus .git/HEAD gelesen (detached HEAD)"

        if not head.startswith("ref: "):
            return None, "Git-HEAD enthält weder eine Commit-SHA noch eine gültige Referenz"
        ref_name = head[5:].strip()
        if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref_name) or ".." in ref_name:
            return None, "Git-HEAD enthält eine nicht unterstützte Referenz"

        ref_path = marker.joinpath(*ref_name.split("/"))
        try:
            commit = ref_path.read_text(encoding="ascii", errors="replace").strip()
        except OSError:
            commit = ""
        if re.fullmatch(r"[0-9a-fA-F]{40,64}", commit):
            return commit.lower(), f"Direkt aus .git/{ref_name} gelesen"

        try:
            packed_refs = (marker / "packed-refs").read_text(
                encoding="ascii", errors="replace"
            ).splitlines()
        except OSError:
            packed_refs = []
        for line in packed_refs:
            if not line or line.startswith(("#", "^")):
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1] == ref_name and re.fullmatch(
                r"[0-9a-fA-F]{40,64}", parts[0]
            ):
                return parts[0].lower(), f"Direkt aus .git/packed-refs gelesen ({ref_name})"
        return None, f"Git-Referenz {ref_name} konnte nicht aufgelöst werden"

    return None, "Kein umgebendes Git-Repository gefunden"


def inspect_symlinks(skill_dir: Path) -> list[Finding]:
    findings = []
    root = skill_dir.resolve()
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(dirpath) / name
            if not path.is_symlink():
                continue
            target = path.resolve(strict=False)
            try:
                target.relative_to(root)
                outside = False
            except ValueError:
                outside = True
            findings.append(Finding(
                category="J_SYMLINK",
                risk="CRITICAL" if outside else "MEDIUM",
                label="Symbolischer Link",
                file=str(path.relative_to(skill_dir)),
                line=0,
                description=("Link verweist außerhalb des Skill-Ordners" if outside
                             else "Link verweist innerhalb des Skill-Ordners"),
                snippet=f"{path.name} -> {target}",
            ))
    return findings


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


DOCUMENTATION_CONTEXT_CUES = re.compile(
    r"\b(must\s+not|do\s+not|don't|never|avoid|prevent|unsafe|dangerous|"
    r"vulnerab\w*|bad\s+patterns?|red\s+flags?|search\s+for|look\s+for|"
    r"instead\s+of|rather\s+than|no\s+shell\s+by\s+default|guidance|"
    r"nicht\s+verwenden|niemals|vermeid\w*|verhinder\w*|unsicher\w*|"
    r"gefährlich\w*|verboten\w*|suche\s+nach|prüfe\s+auf)\b",
    re.IGNORECASE,
)


def _documentation_context_mask(lines: list[str]) -> list[Optional[str]]:
    """Markiert mögliche Warnungen und Negativbeispiele in Markdown.

    Rückgabe je Zeile: ``"section"`` (ausdrücklicher Doku-Abschnitt),
    ``"line"`` (Warnwort in derselben Zeile), ``"window"`` (Warnwort nur in
    den drei Zeilen davor) oder ``None``. Warnwörter sind leicht von
    Angreifern einzufügen; sie senken deshalb höchstens auf Gelb und nur
    ``section``/``line`` unterdrücken die automatische Ablehnung.
    """
    mask: list[Optional[str]] = []
    example_section = False
    contextual_heading = False
    for index in range(len(lines)):
        stripped = lines[index].strip()
        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            heading_text = heading.group(2)
            contextual_heading = bool(re.search(
                r"\b(practical\s+scanning|scanning\s+heuristics|sources|"
                r"audit\s+checklist|detection\s+checklist)\b",
                heading_text,
                re.IGNORECASE,
            ))
            example_section = False

        if re.match(
            r"^(insecure|unsafe|bad|dangerous|vulnerable)\s+"
            r"(patterns?|examples?|code)\s*:?$|^detection\s+hints?\s*:?$",
            stripped,
            re.IGNORECASE,
        ):
            example_section = True
        elif re.match(
            r"^(required|fix|mitigation|safe\s+patterns?|notes?|references?)\s*:?$",
            stripped,
            re.IGNORECASE,
        ):
            example_section = False

        window = " ".join(lines[max(0, index - 3):index + 1])
        if contextual_heading or example_section:
            mask.append("section")
        elif DOCUMENTATION_CONTEXT_CUES.search(lines[index]):
            mask.append("line")
        elif DOCUMENTATION_CONTEXT_CUES.search(window):
            mask.append("window")
        else:
            mask.append(None)
    return mask


FENCE_COMBINATION_DESCRIPTION = (
    "Gefährliche Musterkombination in einem Codebeispiel; prüfen, ob eine Anweisung "
    "auf dieses Beispiel verweist"
)


# Mindeststufe für Treffer im möglichen Dokumentationskontext: sichtbar als
# Gelb ("manuell prüfen"), nie stillschweigend Grün.
CONTEXT_FLOOR = "MEDIUM"


def _context_risk(risk: str) -> str:
    """Senkt einen Kontexttreffer höchstens bis zur Mindeststufe."""
    if RISK_ORDER.get(risk, 99) < RISK_ORDER[CONTEXT_FLOOR]:
        return CONTEXT_FLOOR
    return risk


def _markdown_section_ranges(lines: list[str]) -> list[tuple[int, int, str]]:
    """Liefert Überschriftenabschnitte inklusive ihrer Unterabschnitte.

    Ein Abschnitt endet an der nächsten Überschrift gleicher oder höherer
    Ebene. Dadurch kann eine Kombination auch über Leerzeilen und untergeordnete
    Überschriften hinweg erkannt werden, ohne benachbarte Hauptabschnitte
    miteinander zu vermischen.
    """
    if not lines:
        return []

    headings = []
    for index, line in enumerate(lines):
        match = re.match(r"^(#{1,6})\s+(.+)$", line.strip())
        if match:
            headings.append((index, len(match.group(1)), match.group(2).strip()))

    if not headings:
        return [(0, len(lines), "Dokument ohne Überschriften")]

    ranges = []
    if headings[0][0] > 0:
        ranges.append((0, headings[0][0], "Vorspann"))

    stack = []
    for index, level, title in headings:
        while stack and stack[-1][1] >= level:
            start, _, previous_title = stack.pop()
            ranges.append((start, index, previous_title))
        stack.append((index, level, title))

    while stack:
        start, _, title = stack.pop()
        ranges.append((start, len(lines), title))

    return sorted(ranges, key=lambda item: (item[1] - item[0], item[0]))


def scan_file(filepath: Path, skill_dir: Path) -> list[Finding]:
    findings = []
    rel_path = str(filepath.relative_to(skill_dir))

    try:
        if filepath.stat().st_size > MAX_SCAN_FILE_BYTES:
            return [Finding(
                category="K_COVERAGE",
                risk="MEDIUM",
                label="Prüfabdeckung",
                file=rel_path,
                line=0,
                description=f"Datei größer als {MAX_SCAN_FILE_BYTES} Bytes; Inhalt nicht automatisch geprüft",
                snippet="Manuelle Prüfung erforderlich",
            )]
        content = filepath.read_text(encoding="utf-8", errors="strict")
    except Exception as exc:
        return [Finding(
            category="K_COVERAGE",
            risk="MEDIUM",
            label="Prüfabdeckung",
            file=rel_path,
            line=0,
            description="Datei konnte nicht automatisch gelesen werden",
            snippet=type(exc).__name__,
        )]

    return scan_text(content, rel_path, filepath.suffix.lower() == ".md")


def scan_text(content: str, rel_path: str, is_md: bool) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    fence_mask = _code_fence_mask(lines) if is_md else [False] * len(lines)
    documentation_kind = _documentation_context_mask(lines) if is_md else [None] * len(lines)
    # Abschnittskombinationen (Stufe 2) ignorieren weiterhin jeden Doku-Kontext.
    documentation_mask = [kind is not None for kind in documentation_kind]
    # Die automatische Ablehnung (Stufe 1) ignoriert nur eindeutige Doku-Stellen;
    # ein Warnwort in den Zeilen davor reicht dafür nicht.
    reject_doc_mask = [kind in {"section", "line"} for kind in documentation_kind]
    # Codeblöcke in der SKILL.md sind Anweisungen an den Agenten, keine Beispiele.
    instruction_file = Path(rel_path).name.lower() == "skill.md"
    markdown_sections = _markdown_section_ranges(lines) if is_md else []
    if is_md and fence_mask and fence_mask[-1]:
        findings.append(Finding(
            category="K_COVERAGE",
            risk="HIGH",
            label="Prüfabdeckung",
            file=rel_path,
            line=len(lines),
            description="Nicht geschlossener Markdown-Codeblock kann nachfolgenden Inhalt verdecken",
            snippet="Codeblock endet nicht mit ``` oder ~~~",
        ))
    for cat_key, cat in PATTERNS.items():
        risk = cat["risk"]
        label = cat["label"]

        for pat_str, description in cat["patterns"]:
            try:
                pat = re.compile(pat_str, re.IGNORECASE)
            except re.error:
                continue
            for lineno, line in enumerate(lines, start=1):
                if pat.search(line):
                    in_fence = is_md and fence_mask[lineno - 1]
                    in_documentation = is_md and documentation_mask[lineno - 1]
                    is_context = in_fence or in_documentation
                    if not is_context:
                        effective_risk = risk
                    elif in_fence and not instruction_file:
                        # Beispielcode in README/Referenzen bleibt reiner Kontext.
                        effective_risk = "CONTEXT"
                    else:
                        effective_risk = _context_risk(risk)
                    snippet = line.strip()[:120]
                    findings.append(Finding(
                        category=cat_key,
                        risk=effective_risk,
                        label=label,
                        file=rel_path,
                        line=lineno,
                        description=description,
                        snippet=snippet,
                        is_reject=False,
                        in_code_fence=in_fence,
                        original_risk=risk if is_context else None,
                        context_reason=(
                            "markdown_code_fence" if in_fence else
                            "sicherheitswarnung_oder_negativbeispiel" if in_documentation else None
                        ),
                    ))

        for reject_str in cat.get("reject_if", []):
            try:
                reject_pat = re.compile(reject_str, re.IGNORECASE)
            except re.error:
                continue
            # Stufe 1: Ein enger lokaler Block bleibt ein hochpräziser
            # automatischer Ablehnungsbefund.
            local_reject_lines = []
            for start in range(len(lines)):
                end = min(len(lines), start + 3)
                window_parts = []
                for index in range(start, end):
                    if (is_md and fence_mask[index]) or (is_md and reject_doc_mask[index]):
                        window_parts.append("")
                    else:
                        window_parts.append(lines[index])
                window = " ".join(window_parts)
                if reject_pat.search(window):
                    findings.append(Finding(
                        category=cat_key,
                        risk="CRITICAL",
                        label=label,
                        file=rel_path,
                        line=start + 1,
                        description="Gefährliche Musterkombination im lokalen Kontext",
                        snippet=window.strip()[:120],
                        is_reject=True,
                    ))
                    local_reject_lines.append(start)
                    break

            if not is_md:
                continue

            # Stufe 1b: Gefährliche Kombinationen innerhalb von Codeblöcken.
            # In der SKILL.md sind Codeblöcke Anweisungen (HIGH). In anderen
            # Markdown-Dateien bleibt der Treffer Kontext, bis eine andere
            # Datei auf diese Datei verweist (Hochstufung in inputs.py).
            for start in range(len(lines)):
                end = min(len(lines), start + 3)
                window = " ".join(lines[index] if fence_mask[index] else ""
                                  for index in range(start, end))
                if window.strip() and reject_pat.search(window):
                    findings.append(Finding(
                        category=cat_key,
                        risk="HIGH" if instruction_file else "CONTEXT",
                        label=label,
                        file=rel_path,
                        line=start + 1,
                        description=FENCE_COMBINATION_DESCRIPTION,
                        snippet=window.strip()[:120],
                        is_reject=False,
                        in_code_fence=True,
                        original_risk="HIGH",
                        context_reason="markdown_code_fence",
                    ))
                    break

            # Stufe 2: In Markdown können zusammengehörige Anweisungen über
            # Leerzeilen, Absätze und Unterüberschriften verteilt sein. Solche
            # Abschnittstreffer werden sichtbar, aber wegen des größeren
            # Kontexts nicht automatisch als REJECT gewertet.
            section_matches = []
            for section_start, section_end, section_title in markdown_sections:
                section_parts = []
                for index in range(section_start, section_end):
                    if fence_mask[index] or documentation_mask[index]:
                        section_parts.append("")
                    else:
                        section_parts.append(lines[index])
                section_text = " ".join(section_parts)
                match = reject_pat.search(section_text)
                if match:
                    section_matches.append((
                        section_start,
                        section_end,
                        section_title,
                        match.group(0).strip(),
                    ))

            # Unterabschnitte zuerst behalten. Ein übergeordneter Abschnitt
            # wird nur zusätzlich gemeldet, wenn die Kombination erst über
            # mehrere Unterabschnitte hinweg entsteht.
            minimal_matches = []
            for candidate in section_matches:
                start, end, _, _ = candidate
                if any(
                    start <= kept_start and end >= kept_end
                    for kept_start, kept_end, _, _ in minimal_matches
                ):
                    continue
                minimal_matches.append(candidate)

            for section_start, section_end, section_title, matched_text in minimal_matches:
                if any(
                    section_start <= local_line < section_end
                    for local_line in local_reject_lines
                ):
                    continue
                findings.append(Finding(
                    category=cat_key,
                    risk="HIGH",
                    label=label,
                    file=rel_path,
                    line=section_start + 1,
                    description=(
                        "Gefährliche Musterkombination im selben Markdown-Abschnitt; "
                        "manuelle Prüfung erforderlich"
                    ),
                    snippet=f"Abschnitt „{section_title}“: {matched_text}"[:120],
                    is_reject=False,
                ))

    return findings


def audit_skill(skill_path: str) -> SkillAuditResult:
    """Kompatibler öffentlicher Einstieg; alle Eingaben laufen beaufsichtigt."""
    from .supervisor import audit_input
    return audit_input(skill_path)

