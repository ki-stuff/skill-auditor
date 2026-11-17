"""Konkrete nächste Schritte; Hilfsprompts enthalten keine Prüfobjekt-Texte."""
from pathlib import Path


def prompts():
    source = Path(__file__).resolve().parents[2] / 'references' / 'hilfe-bei-befunden.md'
    text = source.read_text(encoding='utf-8')
    blocks = [line[2:] for line in text.splitlines() if line.startswith('> ')]
    if len(blocks) != 3 or any(len(b) > 8000 for b in blocks):
        raise ValueError('Mitgelieferte Hilfsprompts unvollständig')
    return blocks


def next_steps(data):
    status = data.get('scanner_assessment', {}).get('status', data.get('status', 'unavailable'))
    coverage = data.get('coverage', {}).get('status', 'unknown')
    yellow, grey, red = prompts()
    if status == 'reject':
        steps = ['Installation und Nutzung zunächst aussetzen.',
                 'Jede rote Fundstelle im Original lesen und einordnen: Dokumentationstext, zweckgebundenes Werkzeugverhalten oder echtes Risiko.',
                 'Die Einordnung getrennt vom Originalbericht und mit Datum festhalten; die rote Ampel bleibt bestehen.',
                 'Bei echtem oder ungeklärtem Risiko eine Alternative ohne diese Erweiterung wählen.']
        prompt = red
        if coverage != 'complete_for_text_scope':
            steps.append('Zusätzlich die unter Prüflücken aufgeführten ungeprüften Teile klären; der rote Befund bleibt bestehen.')
            prompt += ' Zusätzlich ist die Prüfabdeckung unvollständig. Hilf mir, die im Bericht genannten Prüflücken und ungeprüften Teile separat zu klären. Eine Erklärung des roten Befunds ersetzt diese fehlende Prüfung nicht; Rot bleibt bestehen.'
        return {'kind': 'reject', 'title': 'Zunächst nicht verwenden',
                'steps': steps, 'prompt': prompt}
    if status == 'caution':
        steps = ['Befunde öffnen und Zweck, Datenzugriff und benötigte Rechte der betroffenen Stelle klären.',
                 'Nur den kleinsten nötigen Ausschnitt nach eigener Prüfung auf private Daten mit einer KI oder Fachperson besprechen.',
                 'Erst nach Klärung entscheiden; bis dahin nicht ungeprüft installieren.']
        if coverage != 'complete_for_text_scope':
            steps.append('Zusätzlich die Prüflücken klären; eine harmlose Erklärung ersetzt keine fehlende Prüfung.')
        return {'kind': 'caution', 'title': 'Auffälligkeiten gezielt klären', 'steps': steps, 'prompt': yellow}
    if coverage != 'complete_for_text_scope' or status in {'unavailable', 'insufficient', 'unaudited', 'stale'}:
        return {'kind': 'coverage', 'title': 'Fehlenden Prüfbereich klären',
                'steps': ['Prüflücken öffnen: Fehlen Dateien, Zugriff, Formatunterstützung oder eine geeignete Laufzeit?',
                          'Vollständigere bereinigte Quellen beim Anbieter erfragen oder eine bereits geeignete Prüfungsumgebung vorschlagen lassen.',
                          'Keine Schutzgrenzen lockern, nichts nachinstallieren und keine Dateien automatisch in andere Dienste übertragen.',
                          'Wenn die Lücke bleibt: vorerst verzichten oder gezielte Fachprüfung beauftragen.'],
                'prompt': grey}
    return {'kind': 'clear', 'title': 'Geprüften Umfang beachten',
            'steps': ['Zweck und benötigte Rechte vor Nutzung selbst einordnen. Bei geändertem Inhalt oder Prüfprofil erneut prüfen.'],
            'prompt': None}
