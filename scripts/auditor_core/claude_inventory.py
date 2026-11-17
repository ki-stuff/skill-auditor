"""Claude-Bestand aus freigegebenen Wurzeln; Herkunft ist keine Vertrauensstufe."""
from pathlib import Path
import os
from .safeio import guarded_path, linked
from .formats import strict_json
from .inventory import scan_installed_skills, InventoryEntries


def default_roots():
    return [Path.home() / '.claude' / 'skills', Path.cwd() / '.claude' / 'skills'], [Path.home() / '.claude' / 'plugins']


def registered_plugin_roots(root):
    """Nur deklarierte Installationen innerhalb der gewählten Plugin-Wurzel."""
    registry = root / 'installed_plugins.json'
    if not registry.exists():
        return [], 'Plugin-Register fehlt; registrierter Bestand unbekannt'
    with guarded_path(registry) as stream:
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError('Plugin-Register überschreitet Grenze')
    data = strict_json(raw.decode('utf-8'))
    if (not isinstance(data, dict) or (data.get('version') is not None and
            (type(data.get('version')) is not int or data['version'] not in {1, 2})) or not isinstance(data.get('plugins'), dict)):
        raise ValueError('Unbekanntes Claude-Plugin-Register')
    selected, gap = [], None
    for installs in data['plugins'].values():
        if not isinstance(installs, list):
            raise ValueError('Ungültiger Plugin-Eintrag')
        for item in installs:
            if not isinstance(item, dict) or not isinstance(item.get('installPath'), str) or not item['installPath']:
                raise ValueError('Ungültiger Plugin-Pfad')
            path = Path(item['installPath'])
            if not path.is_absolute() or not Path(os.path.abspath(path)).is_relative_to(Path(os.path.abspath(root))):
                gap = 'Plugin-Pfad außerhalb der freigegebenen Wurzel nicht verfolgt'
                continue
            # Parent-chain protection happens in the shared discovery reader too.
            try:
                with guarded_path(path, directory=True):
                    pass
            except (OSError, ValueError):
                gap = 'Registrierter Plugin-Pfad fehlt oder ist ein Link'
                continue
            selected.append(path)
    return list(dict.fromkeys(selected)), gap


def scan_claude_inventory(skill_roots, plugin_roots, reports_dir=None, profile='P-CC', surface='cli'):
    roots, gaps = [], []
    for root in plugin_roots:
        selected, gap = registered_plugin_roots(root)
        roots.extend(selected)
        if gap:
            gaps.append(gap)
    entries = scan_installed_skills(skill_roots, roots, reports_dir, profile=profile, surface=surface)
    for entry in entries:
        if any(s.startswith('plugin:') for s in entry.get('sources', [])):
            entry['source_status'] = 'registriert; Aktivierung und Herausgeber nicht bestätigt'
    if gaps:
        entries.append({'name': 'Grenze der Claude-Bestandsaufnahme', 'description': '; '.join(sorted(set(gaps))),
                        'status': 'unaudited', 'risk': None, 'coverage': {'status': 'unknown'},
                        'sources': ['Claude-Plugin-Register'], 'verdict': '⚪ BESTAND NICHT VOLLSTÄNDIG GEPRÜFT'})
    return InventoryEntries(entries, [*skill_roots, *plugin_roots])
