"""Editionen sind Bereitstellungsprofile, keine Berechtigungsnachweise."""
import hashlib
import json
import os
import platform
import sys
from pathlib import Path
from .models import SkillAuditResult

# Eine Claude-Fassung für Terminal/Code-Tab, Desktop-Chat, claude.ai und Cowork (E-049).
EDITIONS = {
    'codex': {'name': 'codex-skill-auditor', 'version': '1.2.1',
              'surfaces': {'cli': 'P-CX', 'app': 'P-CX', 'ide': 'P-CX'}, 'default': 'cli',
              'inventory_surfaces': ('cli', 'app', 'ide')},
    'claude': {'name': 'skill-auditor', 'version': '2.7.1',
               'surfaces': {'cli': 'P-CC', 'desktop-chat': 'P-DT', 'web': 'P-WEB', 'cowork': 'P-CW'},
               'default': 'cli', 'inventory_surfaces': ('cli',)},
}

START_OPTIONS = ('pruefen', 'bestand', 'hilfe', 'erklaeren')


def package_status(package_root=None):
    """Prüft nur das eigene Paket gegen BUNDLE.json; liest kein Prüfobjekt."""
    root = Path(package_root) if package_root else Path(__file__).resolve().parents[2]
    manifest = root / 'BUNDLE.json'
    if not manifest.is_file():
        return {'status': 'unknown', 'reason': 'Kein BUNDLE.json neben dem Einstieg (Entwicklungsstand oder unvollständige Installation)'}
    try:
        files = json.loads(manifest.read_text(encoding='utf-8'))['files']
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'incomplete', 'reason': 'BUNDLE.json nicht lesbar'}
    missing, changed = 0, 0
    for relative, expected in files.items():
        target = root / relative
        if not target.is_file():
            missing += 1
        elif hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            changed += 1
    if missing or changed:
        return {'status': 'incomplete', 'missing_files': missing, 'changed_files': changed,
                'reason': 'Paket unvollständig oder verändert; bitte das komplette ZIP neu installieren'}
    return {'status': 'complete', 'files_checked': len(files)}


def _default_roots(edition):
    if edition == 'claude':
        from .claude_inventory import default_roots
        skills, plugins = default_roots()
    else:
        from .inventory import default_skill_roots, default_plugin_roots
        skills, plugins = default_skill_roots(), default_plugin_roots()
    return [*skills, *plugins]


def readable_root_count(edition, roots=None):
    """Nur Existenz und Leserecht der Standardwurzeln; kein Auflisten von Inhalten."""
    count = 0
    for root in (roots if roots is not None else _default_roots(edition)):
        try:
            if os.path.isdir(root) and os.access(root, os.R_OK):
                count += 1
        except OSError:
            continue
    return count


def start_offer(edition, surface, python_ok, roots_readable):
    config = EDITIONS[edition]
    inventory = python_ok and roots_readable > 0 and surface in config['inventory_surfaces']
    if inventory:
        note = None
    elif surface not in config['inventory_surfaces']:
        note = ('Bestandsübersicht nur im Terminal bzw. Code-Tab; in Chat, claude.ai und Cowork '
                'sind die lokalen Skill-Ordner nicht zugänglich.')
    elif not python_ok:
        note = 'Bestandsübersicht braucht Python ab 3.11.'
    else:
        note = 'Keine lesbaren Skill-Ordner gefunden.'
    options = [o for o in START_OPTIONS if o != 'bestand' or inventory]
    return options, inventory, note


def capability_report(edition, surface=None, roots=None, package_root=None):
    from . import SCANNER_VERSION
    config = EDITIONS[edition]
    surface = surface or config['default']
    profile = config['surfaces'][surface]
    python_ok = sys.version_info >= (3, 11)
    roots_readable = readable_root_count(edition, roots)
    options, inventory, note = start_offer(edition, surface, python_ok, roots_readable)
    return {'edition': config['name'], 'edition_version': config['version'], 'core_version': SCANNER_VERSION,
            'profile': profile, 'surface': surface, 'surface_evidence': 'caller_declared',
            'os': platform.system(), 'python': platform.python_version(),
            'minimum_python': '3.11', 'runtime_candidate': python_ok,
            'guard_implementation_available': sys.platform == 'win32' or sys.platform.startswith('linux'),
            'guard_active': False, 'scanner_allowed_by_profile': profile != 'P-CW',
            'package': package_status(package_root),
            'skill_roots_readable': roots_readable, 'skill_roots_evidence': 'measured',
            'inventory_available': inventory, 'offer': options, 'offer_note': note,
            'cowork_device_scanner': 'deferred', 'installation_performed': False,
            'limitations': 'Oberfläche ist eine Selbstauskunft; Python, Paket und Skill-Wurzeln werden gemessen. '
                           'Kein Zugriffs- oder Plattformtest; Wächter erst im Lauf aktiv.'}


def apply_profile(result, edition, surface):
    config = EDITIONS[edition]
    result.execution.profile = config['surfaces'][surface]
    result.execution.surface = surface
    result.input_details['edition'] = {'name': config['name'], 'version': config['version'],
                                      'surface_evidence': 'caller_declared'}
    return result


def no_scan_result(path, edition, surface):
    # Do not stat/resolve/list/open the supplied object here.
    result = SkillAuditResult(str(path), Path(path).name or 'Prüfobjekt')
    result.execution.scan_mode = 'content_review_only'
    result.execution.scanner_executed = False
    reason = ('Cowork-Geräte-Scanner vorläufig zurückgestellt; keine automatische Ausweichumgebung'
              if surface == 'cowork' else 'Scanner ausdrücklich nicht ausgeführt; Inhaltsprüfung durch Menschen/KI steht aus')
    result.skipped_files = [{'file': str(path), 'reason': reason}]
    return apply_profile(result, edition, surface)
