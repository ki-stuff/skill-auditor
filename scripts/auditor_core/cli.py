"""Kompatibler Kommandozeileneinstieg für die Codex-Edition."""
import argparse
import json
import sys
from pathlib import Path
from typing import Optional
from .models import SkillAuditResult
from .scanner import audit_skill
from .reports import result_to_dict, print_report, print_batch_summary, report_filename, write_json_report
from .privacy import safe_text
from .presentation import write_audit_html
from .editions import EDITIONS, capability_report, apply_profile, no_scan_result
from .inventory import (default_skill_roots, default_plugin_roots, scan_installed_skills,
                        write_inventory_json, write_inventory_html, print_inventory_summary)
class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse echoes arbitrary supplied arguments, which may be credentials.
        self.exit(2, 'Ungültige Argumente; erlaubte Optionen mit --help anzeigen.\n')


def build_parser(edition='codex') -> argparse.ArgumentParser:
    parser = SafeParser(
        description=EDITIONS[edition]['name'] + ': Agent-Erweiterungen statisch prüfen.',
    )
    parser.add_argument("skill_paths", nargs="*", help="Lokale Verzeichnisse, Einzeldateien oder ZIP/TAR-Archive")
    parser.add_argument("--inventory", action="store_true", help="Lokale Skills inventarisieren; nur Codex und Claude im Terminal/Code-Tab (--surface cli)")
    parser.add_argument("--output", type=Path, help="Explizites Ziel für JSON; ohne Option wird nichts gespeichert")
    parser.add_argument('--html', type=Path, help='Explizites HTML-Ziel für einen Auditlauf, auch für mehrere Prüfobjekte')
    parser.add_argument('--surface', choices=tuple(EDITIONS[edition]['surfaces']), default=EDITIONS[edition]['default'],
                        help='Deklarierter Sitzungskontext; kein Nachweis echter App-Fähigkeiten')
    parser.add_argument('--capabilities', action='store_true', help='Laufzeitkandidat und Profilgrenzen ohne Objektprüfung anzeigen')
    parser.add_argument('--content-review-only', action='store_true', help='Nichtausführungsbericht; Prüfobjekt nicht lesen')
    parser.add_argument(
        "--inventory-html",
        type=Path,
        help="Explizites Ziel für ein selbstenthaltenes HTML-Dashboard; nur mit --inventory",
    )
    parser.add_argument("--json", action="store_true", dest="json_stdout", help="JSON nur auf stdout ausgeben")
    parser.add_argument("--skills-root", action="append", type=Path, default=[], help="Skill-Verzeichnis; ersetzt die Standard-Skill-Wurzeln. Für mehrere Wurzeln wiederholen.")
    parser.add_argument("--plugins-root", action="append", type=Path, default=[], help="Plugin-Verzeichnis; ersetzt die Standard-Plugin-Wurzeln. Für mehrere Wurzeln wiederholen.")
    parser.add_argument("--reports-dir", type=Path, help="Ordner mit früheren Audit-Reports")
    parser.add_argument("--categories", type=Path,
                        help='JSON mit Themen je Skill für die Kacheln: {"skill": {"category": "...", "summary": "..."}}; '
                             'ändert kein Ergebnis')
    parser.add_argument("--render-inventory", type=Path,
                        help="Gespeicherte Bestandsdatei (aus --inventory --output) ohne neuen Scan als HTML darstellen; "
                             "nur mit --inventory-html")
    return parser


def _audit_output_path(requested: Path, result: SkillAuditResult, batch: bool) -> Path:
    if not batch and requested.suffix.lower() == ".json":
        return requested
    return requested / report_filename(result)


def _main(argv: Optional[list[str]] = None, edition='codex') -> int:
    parser = build_parser(edition)
    args = parser.parse_args(argv)
    if args.capabilities:
        if args.skill_paths or args.output or args.html or args.inventory or args.inventory_html:
            parser.error('Fähigkeitsabfrage nicht mit Prüf-/Ausgabeauftrag mischen')
        print(json.dumps(capability_report(edition, args.surface), ensure_ascii=False, indent=2))
        return 0

    inventory_allowed = args.surface in EDITIONS[edition]['inventory_surfaces']
    if args.render_inventory:
        if not inventory_allowed:
            parser.error('Kein Host-Inventar in diesem Profil')
        if args.inventory or args.skill_paths or not args.inventory_html or args.output or args.html:
            parser.error('--render-inventory nur mit --inventory-html und optional --categories verwenden')
        from .inventory import load_saved_inventory, load_categories
        if args.inventory_html.exists():
            raise ValueError("Zieldatei existiert bereits; bitte einen neuen Dateinamen wählen")
        entries = load_saved_inventory(args.render_inventory)
        categories = load_categories(args.categories) if args.categories else None
        html_path = args.inventory_html
        if html_path.suffix.lower() != ".html":
            html_path = html_path / "skill-inventar.html"
        write_inventory_html(entries, html_path, categories=categories,
                             notice='Dargestellt aus einer gespeicherten Bestandsdatei, ohne neuen Scan. '
                                    'Der Prüfstand entspricht dem Zeitpunkt, zu dem die Datei erstellt wurde.')
        print('HTML-Dashboard am gewählten Ziel gespeichert.', file=sys.stderr)
        return 0
    if args.categories and not args.inventory_html:
        parser.error('--categories wirkt nur zusammen mit --inventory-html')
    if args.inventory_html and not args.inventory:
        parser.error("--inventory-html kann nur zusammen mit --inventory verwendet werden")
    if args.html and args.inventory:
        parser.error('Im Inventarmodus --inventory-html verwenden')

    if args.inventory:
        if not inventory_allowed or args.content_review_only:
            parser.error('Kein Host-Inventar in diesem Profil')
        profile = EDITIONS[edition]['surfaces'][args.surface]
        if edition == 'claude':
            from .claude_inventory import default_roots, scan_claude_inventory
            default_skills, default_plugins = default_roots()
            skill_roots, plugin_roots = args.skills_root or default_skills, args.plugins_root or default_plugins
        else:
            skill_roots = args.skills_root or default_skill_roots()
            plugin_roots = args.plugins_root or default_plugin_roots()
        # Ausgabeziele vor dem (langen) Scan prüfen, nicht erst danach.
        for requested in (args.output, args.inventory_html):
            if requested and any(requested.resolve().is_relative_to(root.resolve())
                                 for root in [*skill_roots, *plugin_roots]):
                raise ValueError("Inventarausgabe innerhalb einer Eingabewurzel ist nicht erlaubt; "
                                 "bitte einen Speicherort außerhalb der Skill-Ordner wählen")
            if requested and requested.exists() and requested.suffix.lower() in {'.json', '.html'}:
                raise ValueError("Zieldatei existiert bereits; bitte einen neuen Dateinamen wählen")
        categories = None
        if args.categories:
            from .inventory import load_categories
            categories = load_categories(args.categories)  # vor dem Scan prüfen
        if edition == 'claude':
            entries = scan_claude_inventory(skill_roots, plugin_roots, args.reports_dir, profile, args.surface)
        else:
            entries = scan_installed_skills(skill_roots, plugin_roots, args.reports_dir, profile, args.surface)
        if args.output:
            output_path = args.output
            if output_path.suffix.lower() != ".json":
                output_path = output_path / "skill-inventory-raw.json"
            write_inventory_json(entries, output_path)
            print('JSON-Inventar am gewählten Ziel gespeichert.', file=sys.stderr)
        if args.inventory_html:
            html_path = args.inventory_html
            if html_path.suffix.lower() != ".html":
                html_path = html_path / "skill-inventar.html"
            write_inventory_html(entries, html_path, categories=categories)
            print('HTML-Dashboard am gewählten Ziel gespeichert.', file=sys.stderr)
        if args.json_stdout:
            print(json.dumps(entries, indent=2, ensure_ascii=False))
        else:
            print_inventory_summary(entries)
        return 0

    if not args.skill_paths:
        parser.print_help()
        return 2

    no_scan = args.content_review_only or args.surface == 'cowork'
    results = ([no_scan_result(path, edition, args.surface) for path in args.skill_paths] if no_scan else
               [apply_profile(audit_skill(path), edition, args.surface) for path in args.skill_paths])
    if args.json_stdout:
        payload = [result_to_dict(r) for r in results]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=False))
    else:
        for result in results:
            print_report(result)
        if len(results) > 1:
            print_batch_summary(results)

    if args.output:
        # Batch-Ziele vorab gegen alle Eingaben prüfen.
        for result in results:
            candidate = _audit_output_path(args.output, result, len(results) > 1).resolve()
            if any(candidate.is_relative_to(Path(r.skill_path).resolve()) for r in results):
                raise ValueError("Ausgabe innerhalb eines Prüfobjekts ist nicht erlaubt")
        for result in results:
            json_path = write_json_report(
                result,
                _audit_output_path(args.output, result, len(results) > 1),
            )
            if json_path and not args.json_stdout:
                print('JSON-Bericht am gewählten Ziel gespeichert.')

    if args.html:
        write_audit_html(results, args.html)
        print('HTML-Bericht am gewählten Ziel gespeichert.', file=sys.stderr)

    has_reject = any("REJECT" in r.short_verdict for r in results)
    has_error = any(r.error for r in results)
    return 2 if has_error or no_scan else (1 if has_reject else 0)



def main(argv: Optional[list[str]] = None, edition='codex') -> int:
    if sys.version_info < (3, 11):
        print("Python ab 3.11 erforderlich; keine automatische Installation.", file=sys.stderr)
        return 2
    try:
        return _main(argv, edition)
    except (OSError, ValueError) as exc:
        # Klartextgrund ausgeben, aber keine Pfade oder Rohinhalte: bei OSError
        # nur die Systemmeldung, bei ValueError die eigene, maskierte Meldung.
        if isinstance(exc, OSError):
            detail = exc.strerror or type(exc).__name__
        else:
            detail = safe_text(str(exc))[:300] or type(exc).__name__
        print(f"Auditor-Fehler: {detail}. Vorgang abgebrochen.", file=sys.stderr)
        return 2
