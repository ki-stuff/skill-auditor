"""Codex-Adapter: Erkennung installierter Skills und gemeinsame Berichtsdarstellung."""
import os
import re
import json
import html
import datetime
from pathlib import Path
from typing import Optional
from .scanner import collect_files_and_skipped, content_hash
from .reports import report_status, write_new_output, coverage_label, freshness_label
from .safeio import guarded_path, Budget, Limits, linked, InputError
from .privacy import safe_tree, Redactor
from .reports import result_to_dict
from .presentation import (report_sections_html, document, guidance_html, dashboard_sections,
                           brief_reason)


class InventoryEntries(list):
    """Public masked entries with private, original roots for output boundaries."""
    def __init__(self, entries, input_roots):
        super().__init__(entries)
        self.input_roots = input_roots
# ─── Inventar-Modus ──────────────────────────────────────────────────────────
# Sammelt Codex-Skills aus Benutzer-, Repository- und Plugin-Verzeichnissen.
# Plugin-Herkunft ist nur Provenienz und niemals ein Sicherheitsurteil.

DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))


def find_skill_md(skill_dir: Path) -> Optional[Path]:
    for candidate in ("SKILL.md", "skill.md"):
        p = skill_dir / candidate
        if p.is_file() and not linked(p.lstat()):
            return p
    return None


def parse_frontmatter(md_path: Path) -> dict:
    """Liest 'name:' und 'description:' aus dem YAML-Frontmatter einer SKILL.md."""
    meta = {"name": md_path.parent.name, "description": ""}
    try:
        with guarded_path(md_path) as stream:
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            return meta
        text = raw.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return meta
    if not text.lstrip().startswith("---"):
        return meta
    parts = text.split("---", 2)
    if len(parts) < 3:
        return meta

    lines = parts[1].splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if ":" not in line:
            i += 1
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key in ("name", "description") and value in ("|", ">"):
            # YAML block scalar: following indented lines are the value.
            block = []
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                block.append(lines[i].strip())
                i += 1
            value = " ".join(l for l in block if l)
            if key == "name":
                meta["name"] = value
            else:
                meta["description"] = value
            continue
        value = value.strip('"').strip("'")
        if key == "name" and value:
            meta["name"] = value
        elif key == "description" and value:
            meta["description"] = value
        i += 1
    return meta


def _deduplicate_paths(paths: list[Path]) -> list[Path]:
    result = []
    seen = set()
    for path in paths:
        resolved = Path(os.path.abspath(path.expanduser()))
        key = os.path.normcase(str(resolved))
        if key not in seen:
            seen.add(key)
            result.append(resolved)
    return result


def default_skill_roots(cwd: Optional[Path] = None) -> list[Path]:
    start = (cwd or Path.cwd()).resolve(strict=False)
    roots = [Path.home() / ".agents" / "skills", DEFAULT_CODEX_HOME / "skills"]
    roots.extend(parent / ".agents" / "skills" for parent in (start, *start.parents))
    if os.name != "nt":
        roots.append(Path("/etc/codex/skills"))
    return _deduplicate_paths(roots)


def default_plugin_roots() -> list[Path]:
    return _deduplicate_paths([DEFAULT_CODEX_HOME / "plugins"])


def _direct_skill_dirs(root: Path) -> list[Path]:
    return _discover(root, recursive=False)


def _plugin_skill_dirs(root: Path) -> list[Path]:
    return _discover(root, recursive=True)


def _discover(root: Path, recursive: bool) -> list[Path]:
    """Inventarsuche begrenzen; keine Verzeichnislinks verfolgen."""
    import stat
    if not root.exists() or linked(root.lstat()) or not root.is_dir():
        return []
    budget = Budget(Limits())
    pending = [(root, 0)]
    found = []
    while pending:
        directory, depth = pending.pop()
        if find_skill_md(directory):
            found.append(directory)
        if not recursive and depth >= 1:
            continue
        with guarded_path(directory, directory=True) as handle:
            with os.scandir(handle) as entries:
                for entry in entries:
                    budget.entry(entry.name)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode) and not linked(info) and entry.name != ".git":
                        pending.append((directory / entry.name, depth + 1))
    return _deduplicate_paths(found)


def load_audit_status(skill_dir: Path, reports_dir: Optional[Path] = None, metadata=None,
                      profile='core-local', surface='python-api') -> dict:
    """Altberichte unverändert lesen; Inhaltsumfang entspricht dem Scanner."""
    from .supervisor import audit_input
    current = audit_input(skill_dir)
    current.execution.profile = profile
    current.execution.surface = surface
    current_data = result_to_dict(current)
    current_hash = current_data['content_hash']
    history_gap = None
    # Externe, explizit gewählte Berichte zuerst; mitgelieferte niemals als Freigabe.
    candidates = []
    if reports_dir and reports_dir.is_dir():
        try:
            with guarded_path(reports_dir, directory=True) as handle:
                with os.scandir(handle) as listing:
                    for index, entry in enumerate(listing):
                        if index >= 1000:
                            raise InputError('Mehr als 1000 Einträge im Berichtsordner; Historie unvollständig')
                        if entry.name.endswith('-audit.json') and entry.is_file(follow_symlinks=False) and not linked(entry.stat(follow_symlinks=False)):
                            candidates.append(reports_dir / entry.name)
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            history_gap = 'Berichtsordner nicht vollständig lesbar'
        except InputError:
            history_gap = 'Berichtsgrenze erreicht; Historie unvollständig'
    embedded = skill_dir / "audit-result.json"
    candidates.append(embedded)
    history = []
    for report in candidates:
        if report.is_file():
            status = report_status(report, skill_dir, current_hash, embedded=report == embedded, profile=profile)
            if status is not None:
                history.append(status)
    result = {"status": "unaudited", "verdict": None, "audited_at": None,
            "content_hash": current_hash, "report": None, "risk": None,
            "coverage": {"status": "unknown"},
            "freshness": {"content": "unknown", "engine": "unknown", "rules": "unknown",
                          "configuration": "unknown"},
            "manual_assessment": {"status": "pending"}, "report_trust": "unverified"}
    if history:
        result = dict(next((h for h in history if h['status'] == 'reject'), history[0]))
    result['history'] = history
    result['history_limitations'] = history_gap or 'Nur zuordenbare Berichte; Herkunft unbestätigt'
    if history_gap and result['status'] not in {'reject', 'caution'}:
        result.update(status='unaudited', verdict='⚪ Berichtshistorie unvollständig')
    result['current_scan'] = current_data
    assessment = current_data['scanner_assessment']
    historical_warning = next((h for h in history if h['status'] == 'reject'),
                              next((h for h in history if h['status'] == 'caution'), None))
    result.update(status=assessment['status'], risk=assessment['risk'],
                  verdict=current_data['scanner_verdict'], coverage=current_data['coverage'],
                  status_basis='current_scan', current_audited_at=current_data['audited_at'],
                  history_status='incomplete' if history_gap else 'available' if history else 'none',
                  manual_assessment={'status': 'pending'})
    if historical_warning and assessment['status'] != 'reject' and (historical_warning['status'] == 'reject' or assessment['status'] not in {'reject', 'caution'}):
        result.update(status=historical_warning['status'], risk=historical_warning['risk'],
                      verdict=historical_warning['verdict'], status_basis='historical_warning')
    if history_gap and result['status'] not in {'reject', 'caution'}:
        result.update(status='insufficient', verdict='⚪ Berichtshistorie unvollständig', status_basis='history_gap')
    if metadata:
        result.update(metadata)
    redactor = getattr(current, '_redactor', Redactor())
    if redactor.exhausted or redactor.context_incomplete:
        # Retain typed red conclusions even when the private context is incomplete.
        result = {k: result[k] for k in ('status', 'risk', 'verdict', 'freshness', 'manual_assessment')}
        result.update(name='[Name zurückgehalten]', description='Maskierungsgrenze erreicht',
                      path='[Pfad zurückgehalten]', sources=['[Herkunft zurückgehalten]'],
                      content_hash=None, report=None, report_trust='unverified',
                      coverage=current_data['coverage'], current_scan=current_data,
                      history=[{'status': h['status'], 'risk': h.get('risk'), 'report_trust': 'unverified'} for h in history],
                      history_limitations='Details wegen Maskierungsgrenze zurückgehalten')
        return result
    public = safe_tree(result, redactor)
    # This typed conclusion is not prose from the inspected skill.
    for key in ('status', 'risk', 'verdict'):
        public[key] = result.get(key)
    public['current_scan'] = current_data
    return public

def scan_installed_skills(
    skill_roots: Optional[list[Path]] = None,
    plugin_roots: Optional[list[Path]] = None,
    reports_dir: Optional[Path] = None,
    profile='core-local', surface='python-api',
) -> list[dict]:
    """Sammelt Codex-Skills; Herkunft und Auditstatus bleiben getrennte Felder."""
    entries_by_path = {}

    def add_skill(skill_dir: Path, source: str) -> None:
        resolved = Path(os.path.abspath(skill_dir))
        key = os.path.normcase(str(resolved))
        if key in entries_by_path:
            if source not in entries_by_path[key]["sources"]:
                entries_by_path[key]["sources"].append(source)
            return
        md = find_skill_md(resolved)
        if not md:
            return
        meta = parse_frontmatter(md)
        metadata = {
            "name": meta["name"],
            "description": meta["description"],
            "path": str(resolved),
            "sources": [source],
        }
        entries_by_path[key] = metadata

    selected_skill_roots = default_skill_roots() if skill_roots is None else skill_roots
    selected_plugin_roots = default_plugin_roots() if plugin_roots is None else plugin_roots

    for root in _deduplicate_paths(selected_skill_roots):
        for skill_dir in _direct_skill_dirs(root):
            add_skill(skill_dir, f"skill-root:{root}")

    for root in _deduplicate_paths(selected_plugin_roots):
        for skill_dir in _plugin_skill_dirs(root):
            add_skill(skill_dir, f"plugin:{root}")

    entries = [load_audit_status(Path(meta['path']), reports_dir, meta, profile, surface) for meta in entries_by_path.values()]
    return InventoryEntries(sorted(entries, key=lambda entry: entry["name"].lower()),
                            [*selected_skill_roots, *selected_plugin_roots])


def safe_entries(entries: list[dict]) -> list[dict]:
    """Maskiert jeden Eintrag einzeln.

    Ein gemeinsamer Durchlauf über den ganzen Bestand erreichte bei realen
    Sammlungen (viele Skills mit API-Beispielen) die Maskierungsgrenze und
    verwarf das komplette Inventar. Jetzt wird nur der betroffene Eintrag
    zurückgehalten; sein typisiertes Ergebnis bleibt sichtbar.
    """
    result = []
    for entry in entries:
        try:
            result.append(safe_tree(entry))
        except ValueError:
            status = entry.get('status') if entry.get('status') in INVENTORY_STATUS_META else 'insufficient'
            result.append({
                'name': '[Name zurückgehalten]', 'description': 'Details wegen Maskierungsgrenze zurückgehalten',
                'path': '[Pfad zurückgehalten]', 'sources': ['[Herkunft zurückgehalten]'],
                'status': status, 'risk': entry.get('risk') if entry.get('risk') in {
                    'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', None} else None,
                'verdict': None, 'coverage': {'status': 'insufficient'}, 'history': [],
                'history_limitations': 'Details wegen Maskierungsgrenze zurückgehalten',
                'manual_assessment': {'status': 'pending'}, 'report_trust': 'unverified',
            })
    return InventoryEntries(result, getattr(entries, 'input_roots', []))


def write_inventory_json(entries: list[dict], output_path: Path) -> None:
    write_new_output(output_path, json.dumps(safe_entries(entries), indent=2, ensure_ascii=False),
                     getattr(entries, 'input_roots', [e['path'] for e in entries if e.get('path')]))


INVENTORY_STATUS_META = {
    "reject": ("🔴", "Nicht verwenden", "status-reject"),
    "caution": ("🟡", "Manuell prüfen", "status-caution"),
    "stale": ("🟠", "Veraltet – erneut prüfen", "status-stale"),
    "unaudited": ("⚪", "Nicht geprüft", "status-unaudited"),
    "insufficient": ("⚪", "Nicht ausreichend geprüft", "status-unaudited"),
    "unavailable": ("⚪", "Prüfung nicht ausgeführt", "status-unaudited"),
    "clear": ("🟢", "Keine offensichtlichen Befunde", "status-clear"),
}


CATEGORY_FILE_LIMIT = 1_000_000
CATEGORY_LIMITS = {'entries': 5000, 'category': 60, 'summary': 240}


def _read_limited(path: Path, limit: int, label: str) -> str:
    with guarded_path(Path(path)) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(label + ' ist zu groß')
    try:
        return raw.decode('utf-8-sig')
    except UnicodeError:
        raise ValueError(label + ' ist keine UTF-8-Textdatei') from None


def load_categories(path: Path) -> dict:
    """Liest die von der KI vergebenen Themen: {"skill": {"category": "...", "summary": "..."}}.

    Die Werte sind reine Anzeige-Texte. Sie werden maskiert, gekürzt und ändern
    nie Status, Risiko oder Abdeckung eines Eintrags.
    """
    from .formats import strict_json
    from .privacy import safe_text
    data = strict_json(_read_limited(path, CATEGORY_FILE_LIMIT, 'Kategorien-Datei'))
    if not isinstance(data, dict):
        raise ValueError('Kategorien-Datei muss ein JSON-Objekt {"skill-name": {...}} sein')
    if len(data) > CATEGORY_LIMITS['entries']:
        raise ValueError('Kategorien-Datei enthält zu viele Einträge')
    result = {}
    for name, value in data.items():
        if not isinstance(value, dict) or not isinstance(value.get('category', ''), str) \
                or not isinstance(value.get('summary', ''), str):
            raise ValueError('Kategorien-Eintrag muss "category" und optional "summary" als Text enthalten')
        category = ' '.join(safe_text(value.get('category', '')).split())[:CATEGORY_LIMITS['category']]
        summary = ' '.join(safe_text(value.get('summary', '')).split())[:CATEGORY_LIMITS['summary']]
        result[str(name)] = {'category': category or 'Ohne Kategorie', 'summary': summary}
    return result


def load_saved_inventory(path: Path) -> 'InventoryEntries':
    """Liest eine zuvor mit --output gespeicherte Bestandsdatei für eine neue Darstellung.

    Kein erneuter Scan. Die Datei wird wie fremde Eingabe behandelt: strikt
    geparst, Struktur geprüft und beim Darstellen erneut maskiert.
    """
    from .formats import strict_json
    # Eigene Ausgabedatei: deutlich mehr Knoten als ein Manifest, aber weiterhin begrenzt.
    data = strict_json(_read_limited(path, 64 * 1024 * 1024, 'Bestandsdatei'), max_nodes=5_000_000)
    if not isinstance(data, list) or not all(isinstance(e, dict) and isinstance(e.get('name'), str)
                                             and isinstance(e.get('status'), str) for e in data):
        raise ValueError('Bestandsdatei hat nicht das erwartete Format (Ausgabe von --inventory --output)')
    return InventoryEntries(data, [])


def _short(text: str, limit: int = 170) -> str:
    text = ' '.join(str(text).split())
    return text if len(text) <= limit else text[:limit].rsplit(' ', 1)[0] + ' …'


def render_inventory_html(entries: list[dict], template_path: Optional[Path] = None,
                          categories: Optional[dict] = None, notice: str = '') -> str:
    """Erzeugt das gemeinsame Layout; vorhandene Urteile bleiben unverändert."""
    from .guidance import next_steps
    categories = categories or {}
    entries = safe_entries(entries)
    items, notes = [], []
    for entry in entries:
        if entry.get('status') not in INVENTORY_STATUS_META:
            entry['status'] = 'unaudited'
        # The adapter's registry-boundary message is not a discovered skill.
        if not entry.get('path') and entry.get('sources') == ['Claude-Plugin-Register']:
            notes.append('<aside class="inventory-notice"><strong>Grenze der Bestandsaufnahme:</strong> '
                         + html.escape(str(entry.get('description', 'Bestand unvollständig')))
                         + '<details><summary>Hilfe zur unvollständigen Bestandsaufnahme</summary>'
                         + guidance_html(entry) + '</details></aside>')
            continue
        status = entry['status']
        symbol, label, css_class = INVENTORY_STATUS_META[status]
        current = entry.get('current_scan')
        historical = entry.get('status_basis') == 'historical_warning'
        help_source = entry if historical or not current else current
        help_data = next_steps(help_source)
        coverage = coverage_label(entry.get('coverage', {}).get('status', 'unknown'))
        note = 'Warnung aus früherem Bericht; unbestätigt' if historical else ''
        if status in {'reject', 'caution'} and entry.get('coverage', {}).get('status') != 'complete_for_text_scope':
            note += (' · ' if note else '') + 'Zusätzliche Prüflücke: ' + coverage
        reason = (brief_reason(current) if current and not historical else
                  ('Ein älterer Prüfbericht im Skill-Ordner meldet dieses Ergebnis; seine Herkunft ist '
                   'unbestätigt. Der aktuelle Scan hebt die Warnung nicht auf, bitte die Fundstellen selbst prüfen.'
                   if historical else 'Für diesen Eintrag liegt kein aktueller Scan vor: ' + str(entry.get('verdict') or label)))
        path = html.escape(str(entry.get('path') or 'Unbekannter Pfad'))
        sources = html.escape(', '.join(str(source) for source in entry.get('sources', [])) or 'unbekannt')
        metadata = (
            '<details class="technical"><summary>Bestand und Berichtshistorie</summary><div class="technical-body">'
            '<p class="meta"><b>Status:</b> ' + html.escape(str(entry.get('verdict') or label))
            + '<br><b>Quelle:</b> ' + sources + '<br><b>Pfad:</b> <code>' + path + '</code>'
            + '<br><b>Risiko laut Befund:</b> ' + html.escape(str(entry.get('risk') or 'unbekannt'))
            + '<br><b>Aktuelle Prüfabdeckung:</b> ' + html.escape(coverage)
            + '<br><b>Statusgrundlage:</b> ' + html.escape({
                'current_scan': 'Aktueller Scan',
                'historical_warning': 'Warnung aus früherem Bericht; unbestätigt',
                'history_gap': 'Berichtshistorie unvollständig'
            }.get(entry.get('status_basis'), 'Kein aktueller Scan'))
            + '<br><b>Berichtshistorie:</b> ' + str(len(entry.get('history', []))) + ' zugeordnete Berichte'
            + '<br><b>Aktualitätsvergleich:</b> ' + html.escape(freshness_label(entry.get('freshness', {})))
            + '<br><b>Historiengrenze:</b> ' + html.escape(str(entry.get('history_limitations', 'unbekannt')))
            + '<br><b>Manuelle Bewertung:</b> ausstehend; Berichtsherkunft unbestätigt</p>'
            + '<details><summary>Ältere Berichte (' + str(len(entry.get('history', []))) + ')</summary><pre>'
            + html.escape(json.dumps(entry.get('history', []), ensure_ascii=False, indent=2))
            + '</pre></details></div></details>'
        )
        details = (guidance_html(entry) if not current or historical else '')
        if current:
            details += '<h4>Aktueller unabhängiger Scan</h4>' + report_sections_html(current)
        details += metadata
        name = str(entry.get('name') or 'Unbenannter Skill')
        assigned = categories.get(name, {})
        description = str(entry.get('description') or 'Keine Beschreibung verfügbar.')
        items.append({
            'id': 'objekt-' + str(len(items) + 1), 'name': name,
            'status': status, 'description': description,
            'category': assigned.get('category') or 'Ohne Kategorie',
            'summary': assigned.get('summary') or _short(description),
            'reason': reason, 'step': help_data['steps'][0], 'scope': coverage,
            'note': note, 'details': details,
        })
    if notice:
        notes.insert(0, '<aside class="inventory-notice">' + html.escape(notice) + '</aside>')
    return document(dashboard_sections(items, noun='Skills', notices=''.join(notes), layout='tiles'),
                    len(items), title='Skill-Bestandsübersicht', template_path=template_path)

def write_inventory_html(entries: list[dict], output_path: Path, categories: Optional[dict] = None,
                         notice: str = '') -> Path:
    """Schreibt das Dashboard nur an das ausdrücklich gewählte Ziel."""
    return write_new_output(output_path, render_inventory_html(entries, categories=categories, notice=notice),
                            getattr(entries, 'input_roots', [e["path"] for e in entries if e.get("path")]))


def print_inventory_summary(entries: list[dict]) -> None:
    total = len(entries)
    unaudited = sum(1 for e in entries if e.get("status") == "unaudited")
    caution = sum(1 for e in entries if e.get("status") == "caution")
    reject = sum(1 for e in entries if e.get("status") == "reject")
    stale = sum(1 for e in entries if e.get("status") == "stale")
    clear = sum(1 for e in entries if e.get("status") == "clear")
    insufficient = sum(1 for e in entries if e.get('status') in {'insufficient', 'unavailable'})
    print(f"Skills gefunden: {total}")
    print(f"  🟢 keine offensichtlichen Befunde: {clear}")
    print(f"  🟡 Hinweise:       {caution}")
    print(f"  🔴 nicht verwenden: {reject}")
    print(f"  🟠 veraltet, erneut prüfen: {stale}")
    print(f"  ⚪ nicht geprüft:   {unaudited}")
    print(f"  ⚪ nicht ausreichend geprüft: {insufficient}")

