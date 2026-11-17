"""Text und statisches HTML aus demselben maskierten Schema-2-Bericht."""
import html
import json
from pathlib import Path

TITLES = {'run': 'Prüfobjekt, Lauf und Grenzen', 'formats': 'Erkannte Formate', 'components': 'Komponenten',
          'references': 'Verweise', 'chains': 'Erkannte Ausführungsketten',
          'findings': 'Befunde', 'partial_or_unexamined': 'Prüflücken'}
LABELS = {'kind': 'Art', 'name': 'Name', 'source': 'Quelle', 'target': 'Ziel',
          'status': 'Status', 'file': 'Datei', 'line': 'Zeile', 'risk': 'Risiko',
          'category': 'Regel', 'description': 'Beschreibung', 'reason': 'Grund',
          'declared_only': 'Nur deklariert', 'content_verified': 'Inhalt bestätigt',
          'command_values': 'Befehlswerte', 'target_findings': 'Zielbefunde',
          'reference_ids': 'Verweiskennungen', 'source_status': 'Quellenstatus'}


def groups(data):
    adapters = data.get('input_details', {}).get('adapters', {})
    return [('run', [{'Prüfobjekt': {k: v for k, v in data.get('artifact', {}).items() if k != 'components'},
                     'Ausführungsumgebung': data.get('execution', {}), 'Scannerkern': data.get('engine', {}),
                     'Regeln': data.get('ruleset', {}), 'Geprüfte Dateien': data.get('files_scanned', []),
                     'Ausnahmen': data.get('coverage', {}).get('exclusions', []),
                     'Grenzen': data.get('coverage', {}).get('limits', {}),
                     'Aktualität': data.get('freshness', {}),
                     'Ausgabemaskierung': data.get('input_details', {}).get('privacy', {})}]),
            ('formats', adapters.get('formats', [])),
            ('components', data.get('artifact', {}).get('components', [])),
            ('references', adapters.get('references', [])),
            ('chains', adapters.get('chains', [])),
            ('findings', data.get('findings', [])),
            ('partial_or_unexamined', data.get('coverage', {}).get('partial_or_unexamined', []))]


def value_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return 'unbekannt'
    if type(value) is bool:
        return 'ja' if value else 'nein'
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def dimensions(data):
    from .reports import coverage_label, risk_label
    return [('Scanner-Rohurteil', data['scanner_verdict']),
            ('Risiko', risk_label(data)),
            ('Prüfabdeckung', coverage_label(data['coverage']['status'])),
            ('Aktualität', 'Snapshot dieses Laufs; kein laufender Vergleich'),
            ('Manuelle Bewertung', 'ausstehend; keine automatische Freigabe'),
            ('Lauf', data['execution_status']),
            ('Geprüfte Dateien', str(len(data['files_scanned'])))]


def render_text(data):
    lines = ['Auditor: ' + data['skill'], 'Pfad: ' + data['path']]
    lines.extend(key + ': ' + value for key, value in dimensions(data))
    from .guidance import next_steps
    help_data = next_steps(data)
    lines.append('\nSo gehst du weiter: ' + help_data['title'])
    lines.extend('  - ' + step for step in help_data['steps'])
    if help_data['prompt']:
        lines.extend(['Hilfsprompt zum Kopieren (ohne Originalbelege):', help_data['prompt']])
    for error in data['errors']:
        lines.append('FEHLER: ' + error['message'])
    for key, rows in groups(data):
        lines.append('\n' + TITLES[key] + ': ' + str(len(rows)))
        for row in rows:
            lines.append('  · ' + '; '.join(LABELS.get(k, k) + ': ' + value_text(v)
                                          for k, v in row.items()))
    lines.append('\n' + data['limitations'])
    lines.append('Manuelle Einordnung: Zweck, Herkunft, benötigte Rechte, Prüflücken und verbleibendes Risiko getrennt begründen; Originalbericht unverändert erhalten.')
    lines.append(data.get('input_details', {}).get('privacy', {}).get('limitations', ''))
    return '\n'.join(lines)


def report_sections_html(data):
    """Nur maskierte Daten; technische Belege geschlossen, Hilfe separat sichtbar."""
    esc = html.escape
    blocks = [guidance_html(data)]
    blocks.extend('<p class="error">FEHLER: ' + esc(e['message']) + '</p>' for e in data['errors'])
    blocks.append('<details class="technical"><summary>Technische Details'
                  '<span class="detail-hint">Befunde, Fundstellen und Prüfumfang</span></summary>'
                  '<div class="technical-body"><dl class="dimensions">' + ''.join(
                      '<div><dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd></div>'
                      for k, v in dimensions(data)) + '</dl>')
    for key, rows in groups(data):
        body = ''.join('<li><dl>' + ''.join('<dt>' + esc(LABELS.get(k, k)) + '</dt><dd>'
                       + esc(value_text(v)) + '</dd>' for k, v in row.items()) + '</dl></li>' for row in rows)
        blocks.append('<details><summary>' + esc(TITLES[key]) + ' (' + str(len(rows))
                      + ')</summary><ol>' + body + '</ol></details>')
    blocks.append('<p class="meta">' + esc(data['limitations']) + '</p>')
    blocks.append('<p class="meta">Manuelle Einordnung: Zweck, Herkunft, benötigte Rechte, Prüflücken und verbleibendes Risiko getrennt begründen; Originalbericht unverändert erhalten.</p>')
    blocks.append('<p class="meta">' + esc(data.get('input_details', {}).get('privacy', {}).get('limitations', '')) + '</p>')
    return ''.join(blocks) + '</div></details>'

def guidance_html(data):
    from .guidance import next_steps
    help_data = next_steps(data)
    result = '<section class="guidance"><h4>So gehst du weiter: ' + html.escape(help_data['title']) + '</h4><ol>'
    result += ''.join('<li>' + html.escape(step) + '</li>' for step in help_data['steps']) + '</ol>'
    if help_data['prompt']:
        result += ('<details><summary>Hilfsprompt für deine KI</summary>'
                   '<p>Textfeld anklicken, alles markieren und kopieren. Danach nur selbst geprüfte, bereinigte Ausschnitte ergänzen.</p>'
                   '<textarea readonly rows="10" aria-label="Hilfsprompt zum Kopieren">'
                   + html.escape(help_data['prompt']) + '</textarea></details>')
    return result + '</section>'


# Labels describe existing assessment states; no risk or coverage is recomputed here.
STATUS_VIEW = {
    'reject': ('red', '×', 'Nicht verwenden'),
    'caution': ('amber', '!', 'Manuell prüfen'),
    'stale': ('amber', '↻', 'Veraltet – erneut prüfen'),
    'unaudited': ('gray', '–', 'Nicht geprüft'),
    'insufficient': ('gray', '–', 'Nicht ausreichend geprüft'),
    'unavailable': ('gray', '–', 'Prüfung nicht ausgeführt'),
    'clear': ('green', '✓', 'Keine offensichtlichen Befunde'),
}


def status_badge(status):
    color, symbol, label = STATUS_VIEW.get(status, STATUS_VIEW['unaudited'])
    return ('<span class="badge ' + color + '"><span aria-hidden="true">' + symbol
            + '</span>' + label + '</span>')


def brief_reason(data):
    """Short excerpt of an already masked finding, never a new assessment."""
    status = data.get('scanner_assessment', {}).get('status', 'unavailable')
    if data.get('errors'):
        return data['errors'][0]['message']
    for finding in data.get('findings', []):
        relevant = finding.get('is_reject') if status == 'reject' else finding.get('risk') not in {'CONTEXT', 'NONE'}
        if relevant and finding.get('description'):
            text = finding['description']
            return text[:400] + (' …' if len(text) > 400 else '')
    return {
        'reject': 'Ein schwerwiegender Befund liegt vor.',
        'caution': 'Eine Auffälligkeit braucht eine fachliche Klärung.',
        'clear': 'Im geprüften Textumfang wurden keine offensichtlichen Risiken erkannt.',
        'insufficient': 'Der Prüfbereich reicht für eine ausreichende Beurteilung nicht aus.',
        'unavailable': 'Es liegt kein ausgeführter Scannerlauf vor.',
    }.get(status, 'Die vorhandenen Angaben müssen eingeordnet werden.')


FILTERS = [('all', 'Alle'), ('red', 'Nicht verwenden'), ('amber', 'Prüfen'),
           ('gray', 'Prüfung offen'), ('green', 'Unauffällig')]


def tiles_section(items):
    """Kacheln nach Kategorie mit reinem CSS-Filter (Radio-Buttons, kein Skript)."""
    esc = html.escape
    order = {status: i for i, status in enumerate(STATUS_VIEW)}
    groups = {}
    for item in items:
        groups.setdefault(item.get('category') or 'Ohne Kategorie', []).append(item)
    names = sorted(groups, key=lambda name: (name == 'Ohne Kategorie', -len(groups[name]), name.lower()))
    counts = {color: sum(STATUS_VIEW[item['status']][0] == color for item in items)
              for color in ('green', 'amber', 'red', 'gray')}
    counts['all'] = len(items)
    blocks = ['<section id="alle-objekte"><div class="section-head"><div>'
              '<h2>Alle Skills nach Themen</h2><p>Kachel anklicken für Einordnung, nächsten Schritt '
              'und technische Details. Filter zeigt nur Skills mit dem gewählten Ergebnis.</p></div>'
              '<span class="section-label">' + str(len(items)) + ' Einträge · '
              + str(len(groups)) + (' Thema' if len(groups) == 1 else ' Themen') + '</span></div>']
    for key, _ in FILTERS:
        blocks.append('<input type="radio" name="ergebnisfilter" class="filter-input" id="filter-' + key + '"'
                      + (' checked' if key == 'all' else '') + '>')
    blocks.append('<div class="filter-bar" role="group" aria-label="Nach Ergebnis filtern">')
    for key, label in FILTERS:
        blocks.append('<label for="filter-' + key + '" class="filter-' + key + '">' + label
                      + ' <span>' + str(counts[key]) + '</span></label>')
    blocks.append('</div><div class="category-groups">')
    for name in names:
        group = sorted(groups[name], key=lambda item: (order.get(item['status'], 99), item['name'].lower()))
        blocks.append('<div class="category-group"><h3 class="category-title">' + esc(name)
                      + ' <span>(' + str(len(group)) + ')</span></h3><div class="tile-grid">')
        for item in group:
            color = STATUS_VIEW[item['status']][0]
            blocks.append('<details class="tile ' + color + '-tile" id="' + item['id'] + '" data-status="' + item['status'] + '" data-color="'
                          + color + '"><summary><span class="tile-head"><strong>' + esc(item['name'])
                          + '</strong>' + status_badge(item['status']) + '</span><span class="tile-summary">'
                          + esc(item.get('summary') or item['description']) + '</span>'
                          + ('<span class="row-note">' + esc(item['note']) + '</span>' if item['note'] else '')
                          + '</summary><div class="skill-content"><p class="plain-reason">' + esc(item['reason'])
                          + '</p>' + item['details'] + '</div></details>')
        blocks.append('</div></div>')
    blocks.append('</div></section>')
    return ''.join(blocks)


def dashboard_sections(items, noun='Prüfobjekte', notices='', layout='list'):
    """Shared passive layout for audit and inventory; inputs are public masked data."""
    esc = html.escape
    order = {status: i for i, status in enumerate(STATUS_VIEW)}
    items = sorted(items, key=lambda item: order.get(item['status'], 99))
    counts = {color: sum(STATUS_VIEW[item['status']][0] == color for item in items)
              for color in ('green', 'amber', 'red', 'gray')}
    attention = len(items) - counts['green']
    headline = (str(attention) + (' Eintrag braucht' if attention == 1 else ' Einträge brauchen')
                + ' deine Aufmerksamkeit.') if attention else (
                    'Keine auffälligen Befunde im geprüften Textumfang.' if items else 'Noch keine Prüfobjekte in dieser Auswertung.')
    blocks = [
        '<div class="hero"><div><p class="eyebrow">Deine Auswertung auf einen Blick</p>'
        '<h1>Deine Auswertung.<br><span>Klar eingeordnet.</span></h1>'
        '<p class="intro">Was ist unauffällig? Wo solltest du genauer hinsehen? '
        'Hier findest du die Ergebnisse und den jeweils nächsten Schritt.</p></div>'
        '<div class="summary-card"><div class="ring"><strong>' + str(len(items))
        + '</strong><span>' + esc(noun) + '</span></div><div class="summary-copy"><strong>'
        + esc(headline) + '</strong><p>Automatische Erstprüfung<br>Manuelle Einordnung bleibt ausstehend.</p>'
        '</div></div></div><div class="metrics" aria-label="Ergebnisse im Überblick">'
    ]
    for color, label, subtitle in [
            ('green', 'Ohne offensichtlichen Befund', 'Im geprüften Textumfang'),
            ('amber', 'Vorher prüfen', 'Manuell klären oder erneut prüfen'),
            ('red', 'Vorerst nicht verwenden', 'Schwerwiegende Befunde'),
            ('gray', 'Prüfung offen', 'Nicht ausgeführt oder unzureichend')]:
        first = next((item['id'] for item in items if STATUS_VIEW[item['status']][0] == color), 'alle-objekte')
        symbol = {'green': '✓', 'amber': '!', 'red': '×', 'gray': '–'}[color]
        blocks.append('<a class="metric ' + color + '" href="#' + first + '" data-count="' + str(counts[color])
                      + '"><div class="metric-top"><strong>' + str(counts[color])
                      + '</strong><span class="stat-icon" aria-hidden="true">' + symbol
                      + '</span></div><span class="metric-title">' + label
                      + '</span><small>' + subtitle + '</small></a>')
    blocks.append('</div><p class="scope-note">Snapshot dieses Berichts · '
                  'Keine Aussage über tatsächliche Nutzung oder Aktivierung · Keine Sicherheitsgarantie</p>' + notices)
    blocks.append('<section id="handlungsbedarf"><div class="section-head"><div>'
                  '<h2>Hier solltest du zuerst hinsehen.</h2>'
                  '<p>Auffällige Ergebnisse und offene Prüfbereiche.</p></div>'
                  '<span class="section-label">Handlungsbedarf</span></div>')
    red = [item for item in items if item['status'] == 'reject']
    if layout == 'tiles':
        # Bestandsübersicht: kompakt, damit die Themen-Kacheln nicht weit nach unten rutschen.
        if red:
            blocks.append('<div class="attention-grid">')
            for item in red:
                reason = ' '.join(str(item['reason']).split())
                reason = reason if len(reason) <= 120 else reason[:120].rsplit(' ', 1)[0] + ' …'
                blocks.append('<a class="attention-tile" href="#' + item['id'] + '"><span class="tile-head"><strong>'
                              + esc(item['name']) + '</strong>' + status_badge(item['status'])
                              + '</span><span class="tile-summary">' + esc(reason) + '</span>'
                              + ('<span class="row-note">' + esc(item['note']) + '</span>' if item['note'] else '')
                              + '</a>')
            blocks.append('</div>')
        amber = sum(STATUS_VIEW[item['status']][0] == 'amber' for item in items)
        gray = sum(STATUS_VIEW[item['status']][0] == 'gray' for item in items)
        if amber or gray:
            parts = []
            if amber:
                parts.append('<strong>' + str(amber) + '</strong> zum Prüfen (Filter „Prüfen“)')
            if gray:
                parts.append('<strong>' + str(gray) + '</strong> mit offener Prüfung (Filter „Prüfung offen“)')
            blocks.append('<p class="attention-more">' + ('Außerdem ' if red else '') + ' und '.join(parts)
                          + '. <a href="#alle-objekte">Zu den Themen-Kacheln ↓</a></p>')
        red = []
    if red:
        blocks.append('<div class="urgent-grid">')
        for item in red:
            blocks.append('<article class="urgent">' + status_badge(item['status'])
                          + '<h3>' + esc(item['name']) + '</h3><p>' + esc(item['reason'])
                          + '</p><div class="next-step"><span class="step-symbol" aria-hidden="true">↳</span>'
                          '<p><strong>Nächster Schritt</strong><br>' + esc(item['step']) + '</p></div>'
                          + ('<p class="coverage-note">' + esc(item['note']) + '</p>' if item['note'] else '')
                          + '<a href="#' + item['id'] + '">Zum Eintrag mit allen Details ↗</a></article>')
        blocks.append('</div>')
    other = [item for item in items if item['status'] not in {'clear', 'reject'}] if layout != 'tiles' else []
    if other:
        blocks.append('<div class="review-strip">')
        for item in other:
            color, symbol, _ = STATUS_VIEW[item['status']]
            blocks.append('<div class="review-box"><span class="mini-symbol ' + color + '" aria-hidden="true">'
                          + symbol + '</span><div><strong><a href="#' + item['id'] + '">'
                          + esc(item['name']) + '</a></strong>' + status_badge(item['status'])
                          + '<p>' + esc(item['reason']) + '</p></div></div>')
        blocks.append('</div>')
    if not attention:
        blocks.append('<p class="empty">' + ('Keine auffälligen Befunde im geprüften Textumfang. '
                      'Die manuelle Bewertung bleibt ausstehend.' if items else 'Keine Prüfobjekte vorhanden.')
                      + '</p>')
    blocks.append('</section>')
    if layout == 'tiles':
        blocks.append(tiles_section(items))
        return ''.join(blocks) + reading_guide(tiles=True)
    blocks.append('<section id="alle-objekte"><div class="section-head"><div>'
                  '<h2>Alle Einträge im Überblick</h2><p>Eintrag aufklappen für Einordnung, nächsten Schritt '
                  'und technische Details.</p></div><span class="section-label">' + str(len(items))
                  + ' Einträge</span></div><div class="skill-list">'
                  '<div class="list-heading" aria-hidden="true"><span>Name / Einordnung</span>'
                  '<span class="source-heading">Prüfumfang</span><span>Ergebnis</span><span></span></div>')
    for item in items:
        color, symbol, _ = STATUS_VIEW[item['status']]
        blocks.append('<details class="skill-row" id="' + item['id'] + '" data-status="' + item['status'] + '">'
                      '<summary><span class="skill-icon ' + color + '" aria-hidden="true">' + symbol
                      + '</span><span class="skill-name"><strong>' + esc(item['name']) + '</strong><small>'
                      + esc(item['description']) + '</small>'
                      + ('<span class="row-note">' + esc(item['note']) + '</span>' if item['note'] else '')
                      + '</span><span class="source">' + esc(item['scope']) + '</span>'
                      + status_badge(item['status']) + '<span class="chevron" aria-hidden="true"></span>'
                      '</summary><div class="skill-content"><p class="plain-reason">' + esc(item['reason'])
                      + '</p>' + item['details'] + '</div></details>')
    blocks.append('</div></section>')
    return ''.join(blocks) + reading_guide()


def reading_guide(tiles=False):
    return ('<aside class="reading-guide" id="einordnung">'
            '<span class="guide-icon" aria-hidden="true">i</span><div><h3>So liest du diese Auswertung.</h3>'
            '<p>Grün bedeutet: Im geprüften Textumfang gibt es keinen offensichtlichen Befund. '
            'Es ist keine Freigabe oder Sicherheitsgarantie. Gelb braucht eine Klärung oder erneute Prüfung. '
            'Rot bedeutet: zunächst nicht verwenden. Grau zeigt eine nicht ausgeführte oder unzureichende Prüfung. '
            'Eine Prüflücke kann auch zusätzlich zu einem roten Befund bestehen. '
            'Historische Warnungen bleiben als unbestätigte Berichtsangaben erkennbar.'
            + (' Themen und Kurzbeschreibungen der Kacheln stammen aus einer manuellen Zuordnung '
               'und ändern kein Ergebnis.' if tiles else '') + '</p></div></aside>')


def render_audit_html(results):
    from .reports import result_to_dict, coverage_label
    from .guidance import next_steps
    items = []
    for index, result in enumerate(results, 1):
        data = result_to_dict(result)
        status = data['scanner_assessment']['status']
        help_data = next_steps(data)
        gap = data['coverage']['status'] != 'complete_for_text_scope'
        items.append({
            'id': 'objekt-' + str(index), 'name': data['skill'], 'status': status,
            'description': help_data['title'], 'reason': brief_reason(data),
            'step': help_data['steps'][0], 'scope': coverage_label(data['coverage']['status']),
            'note': 'Zusätzliche Prüflücke · ' + coverage_label(data['coverage']['status'])
                    if gap and status in {'reject', 'caution'} else '',
            'details': '<p class="meta"><b>Prüfpfad:</b> <code>' + html.escape(data['path'])
                       + '</code></p>' + report_sections_html(data),
        })
    return document(dashboard_sections(items), len(items), 'Audit-Auswertung')

def document(sections, count, title='Skill-Inventar', template_path=None):
    import datetime
    trusted = Path(__file__).parent.parent / 'inventory_template.html'
    if template_path and Path(template_path).resolve() != trusted.resolve():
        raise ValueError('Nur die mitgelieferte passive Dashboard-Vorlage ist zugelassen')
    template = trusted.read_text(encoding='utf-8')
    # Substitute in one pass: source text containing a placeholder remains data.
    import re
    replacements = {'GENERATED_AT': html.escape(datetime.datetime.now().astimezone().isoformat(timespec='seconds')),
                    'TOTAL': str(count), 'TITLE': html.escape(title), 'STATUS_SECTIONS': sections}
    return re.sub(r'\{\{(GENERATED_AT|TOTAL|TITLE|STATUS_SECTIONS)\}\}',
                  lambda m: replacements[m.group(1)], template)


def write_audit_html(results, path):
    from .reports import write_new_output
    return write_new_output(path, render_audit_html(results), [r.skill_path for r in results])
