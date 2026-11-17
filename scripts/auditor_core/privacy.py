"""Zentrale, begrenzte Ausgabemaskierung; Rohwerte bleiben nur im Scanprozessspeicher."""
import json
import re
import unicodedata
from urllib.parse import quote, unquote, urlsplit, urlunsplit, parse_qsl

MASK = "[MASKIERT]"
STRUCTURAL_KEYS = set('''skill_path skill_name findings files_scanned skipped_files content_hash source_commit source_commit_note error artifact execution audited_at input_details category risk label file line description snippet is_reject in_code_fence original_risk context_reason path name type source version target_platform components profile surface os runtime interpreter scan_mode scanner_executed limits identity hash_algorithm hard_guard container_format container_sha256 bytes_read entries wall_clock_guard memory_metric adapters formats references chains id key kind target status active target_findings reference_ids claim format_version command_values declared_only pinned integrity_declared content_verified effective shadowed reason runtime_surface env_names credential_values endpoint auth_type values verified enabled declared_root path source_file_sha256 declared_name declared_version source_status source_verified declared_source_host privacy snippets sensitive_values_detected content_comparison limitations schema_version scanner_version scanner_base_commit skill scanner_verdict max_risk total_findings verdict_findings rule_id engine ruleset coverage scanner_assessment manual_assessment freshness execution_status errors report_trust bundle_sha256 release sha256 checked partial_or_unexamined exclusions hash_scope hash_limitations assessment checked_at content rules configuration configuration_id comparison code message report report_kind sources current_scan history association snapshot_type note observed_at'''.split())
SECRET_KEY = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization|credential|cookie|private[_-]?key", re.I)
ASSIGN = re.compile(r'''(?ix)(?<![\w.-])(?:["']?)(?:[\w.-]{0,80}(?:password|passwd|secret|token|api[_-]?key|authorization|credential|cookie)[\w.-]{0,80})(?:["']?)\s*(?:=|:)\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;\r\n}]+))''')
FLAGS = re.compile(r'''(?ix)--[\w-]{0,80}(?:password|secret|token|api-key|credential)[\w-]{0,80}(?:=|\s+)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s;]+))''')
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+")
PEM = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)", re.S)
TOKEN = re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]", re.M)

class Redactor:
    def __init__(self, secrets=()):
        self.secrets = set()
        self.exhausted = False
        self.context_incomplete = False
        self.detected = False
        self.characters = 0
        for value in secrets:
            self.remember(value)

    def remember(self, value):
        if not isinstance(value, str) or not value or value in {MASK, "withheld", "pending", "unknown", "none"}:
            return
        if re.fullmatch(r"\$\{[^}]+\}", value):
            return
        self.detected = True
        if len(self.secrets) >= 256 or len(value) > 8192 or sum(map(len, self.secrets)) + len(value) > 131072:
            self.exhausted = True
            return
        self.secrets.add(value)

    def observe_text(self, text):
        for pattern in (ASSIGN, FLAGS):
            for match in pattern.finditer(text):
                self.remember(next((g for g in match.groups() if g is not None), ""))
        for match in re.finditer(r"(?i)\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)", text):
            self.remember(match.group(1))
        for match in TOKEN.finditer(text):
            self.remember(match.group(0))
        for match in PEM.finditer(text):
            self.remember(match.group(0))
            self.detected = True
        for match in URL.finditer(text):
            try:
                parsed = urlsplit(match.group(0))
                self.remember(parsed.password)
                if parsed.password:
                    self.remember(unquote(parsed.password))
                if parsed.username is not None:
                    self.remember(parsed.username)
                    self.remember(unquote(parsed.username))
                if parsed.query or parsed.fragment:
                    self.detected = True
                    for _, value in parse_qsl(parsed.query, keep_blank_values=False):
                        self.remember(value)
                    self.remember(unquote(parsed.fragment))
            except ValueError:
                self.detected = True

    def observe_tree(self, data):
        pending = [(data, False, 0)]
        nodes = 0
        while pending:
            value, sensitive, depth = pending.pop()
            nodes += 1
            if nodes > 50000 or depth > 48:
                self.exhausted = True
                break
            if isinstance(value, dict):
                for key, child in value.items():
                    name = str(key)
                    private = sensitive or bool(SECRET_KEY.search(name)) or name.lower() in {"env", "headers", "http_headers", "env_http_headers"}
                    pending.append((child, private, depth + 1))
            elif isinstance(value, (list, tuple)):
                pending.extend((child, sensitive, depth + 1) for child in value)
            elif isinstance(value, str):
                if sensitive:
                    self.remember(value)
                self.observe_text(value)

    def observe_file(self, name, text):
        self.observe_text(text)
        lower = name.lower()
        if lower.endswith(('.json', '.toml')):
            try:
                from .formats import strict_json, check_tree
                if lower.endswith('.toml'):
                    import tomllib
                    data = check_tree(tomllib.loads(text))
                else:
                    data = strict_json(text)
                self.observe_tree(data)
            except (ValueError, RecursionError):
                pass
        if lower.rsplit('/', 1)[-1].startswith('.env'):
            self.detected = True
            for line in text.splitlines():
                if '=' in line and not line.lstrip().startswith('#'):
                    self.remember(line.split('=', 1)[1].strip().strip('"\''))

    def clean(self, value, limit=8192):
        if not isinstance(value, str):
            value = str(value)
        # Detect before stripping controls or truncating: otherwise a cropped token may leak.
        self.observe_text(value)
        value = PEM.sub(MASK, value)
        value = ANSI.sub('', value)
        self.characters += len(value)
        if self.characters > 4 * 1024 * 1024:
            self.exhausted = True
            return '[Ausgabegrenze erreicht]'
        def url_clean(match):
            try:
                p = urlsplit(match.group(0))
                host = p.hostname or "[Adresse]"
                if ':' in host:
                    host = '[' + host + ']'
                port = ':' + str(p.port) if p.port else ''
                return urlunsplit((p.scheme, host + port, p.path, '', ''))
            except ValueError:
                return '[Adresse maskiert]'
        value = URL.sub(url_clean, value)
        variants = set()
        for secret in self.secrets:
            variants.update((secret, quote(secret, safe=''), json.dumps(secret, ensure_ascii=True)[1:-1]))
        for secret in sorted(variants, key=len, reverse=True):
            if secret:
                value = (value.replace(secret, MASK) if len(secret) >= 4 else
                         re.sub(r'(?<!\w)' + re.escape(secret) + r'(?!\w)', lambda _: MASK, value))
        value = TOKEN.sub(MASK, value)
        value = ANSI.sub('', value)
        value = ''.join(c if unicodedata.category(c) not in {'Cc', 'Cf', 'Cs'} else ' ' for c in value)
        if len(value) > limit:
            value = value[:limit] + ' … [gekürzt]'
        return value

    def tree(self, data, depth=0, budget=None):
        budget = [0] if budget is None else budget
        budget[0] += 1
        if budget[0] > 100000 or depth > 48:
            raise ValueError('Ausgabestruktur überschreitet Grenze')
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                safe_key = key if key in STRUCTURAL_KEYS else self.clean(str(key), 512)
                if safe_key in result:
                    safe_key += '_feld_' + str(len(result))
                if key in {'risk', 'original_risk', 'max_risk'} and (isinstance(value, str) or value is None) and value in {'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'CONTEXT', None}:
                    result[safe_key] = value
                else:
                    result[safe_key] = self.tree(value, depth + 1, budget)
            return result
        if isinstance(data, (list, tuple)):
            return [self.tree(v, depth + 1, budget) for v in data]
        if isinstance(data, str):
            return self.clean(data)
        return data

def safe_text(value):
    return Redactor().clean(value)

def safe_tree(value, redactor=None):
    redactor = redactor or Redactor()
    redactor.characters = 0
    redactor.observe_tree(value)
    if redactor.exhausted:
        raise ValueError('Maskierungsgrenze überschritten; keine ungeschützte Ausgabe')
    result = redactor.tree(value)
    if redactor.exhausted:
        raise ValueError('Ausgabegrenze überschritten; keine ungeschützte Ausgabe')
    return result

def public_result(result):
    """Dataclass-Kopie für alle Renderer; interner Originalpfad bleibt für Schreibgrenzen erhalten."""
    from dataclasses import asdict
    from .models import SkillAuditResult, Artifact, Execution, Finding
    from .errors import ERROR_MESSAGES
    redactor = getattr(result, '_redactor', Redactor())
    redactor.characters = 0
    raw = asdict(result)
    error_code = raw.get('error_code')
    if error_code not in ERROR_MESSAGES:
        error_code = None
    # Edition identity is supplied by our entry point, never by a scanned file.
    from .editions import EDITIONS
    edition = raw['input_details'].get('edition', {})
    trusted_edition = next(({'name': c['name'], 'version': c['version'],
                            'surface_evidence': 'caller_declared'} for c in EDITIONS.values()
                           if edition.get('name') == c['name'] and edition.get('version') == c['version']), None)
    redactor.observe_tree(raw)
    # No arbitrary raw code excerpts leave the scanner, even if detection misses an opaque secret.
    for finding in raw['findings']:
        finding['snippet'] = '[Belegtext zurückgehalten; Datei und Fundstelle prüfen]' if finding['snippet'] else ''
    if redactor.exhausted or redactor.context_incomplete:
        for finding in raw['findings']:
            finding.update(file='[Datei zurückgehalten]', label='Befund', description='Befund; Ausgabemaskierung begrenzt', context_reason=None)
        raw['skill_name'] = '[Name zurückgehalten]'
        raw['skill_path'] = '[Pfad zurückgehalten]'
        raw['artifact']['path'] = raw['skill_path']
        raw['artifact']['name'] = raw['skill_name']
        raw['artifact']['components'] = []
        raw['artifact'].update(source=None, version=None)
        raw['source_commit_note'] = 'Details zurückgehalten'
        raw['input_details'] = {'limits': raw['input_details'].get('limits', {}), 'identity': 'incomplete'}
        raw['files_scanned'] = ['[Datei zurückgehalten]' for _ in raw['files_scanned']]
        raw['skipped_files'] = [{'file': '[Datei zurückgehalten]', 'reason': 'Ausgabe begrenzt'} for _ in raw['skipped_files']]
        if redactor.exhausted:
            error_code = 'privacy_limit'
        raw['error'] = ERROR_MESSAGES.get(error_code, 'Prüfung abgebrochen; Details zurückgehalten.')
    if redactor.detected or redactor.exhausted or redactor.context_incomplete:
        raw['content_hash'] = None
        raw['input_details'].pop('container_sha256', None)
        for component in raw['artifact']['components']:
            component.pop('source_file_sha256', None)
        raw['source_commit'] = None
    raw['input_details']['privacy'] = {
        'version': 'ap4-1', 'snippets': 'withheld', 'sensitive_values_detected': redactor.detected,
        'status': 'limited' if redactor.exhausted or redactor.context_incomplete else 'applied',
        'content_comparison': 'unknown_sensitive_content' if redactor.detected else 'hash_available_if_complete',
        'limitations': 'Maskiert erkannte Werte und hält Rohbelege zurück; keine Garantie für unbekannte oder verschleierte Geheimnisse.'}
    clean = redactor.tree(raw)
    if redactor.exhausted and raw['input_details']['privacy']['status'] != 'limited':
        # Newly exceeded output budget: rebuild once with the conservative view.
        result._redactor = redactor
        return public_result(result)
    # Machine fields never become source-controlled text through a matching secret.
    clean['execution'] = raw['execution'].copy()
    clean['execution']['interpreter'] = redactor.clean(raw['execution']['interpreter'])
    clean['audited_at'] = raw['audited_at']
    clean['input_details']['privacy'] = raw['input_details']['privacy']
    if trusted_edition:
        clean['input_details']['edition'] = trusted_edition
    clean['error_code'] = error_code
    if error_code:
        clean['error'] = ERROR_MESSAGES[error_code]
    for original, finding in zip(raw['findings'], clean['findings']):
        finding['category'] = original['category']
        finding['risk'] = original['risk']
        finding['original_risk'] = original['original_risk']
    clean['artifact'] = Artifact(**clean['artifact'])
    clean['execution'] = Execution(**clean['execution'])
    clean['findings'] = [Finding(**f) for f in clean['findings']]
    return SkillAuditResult(**clean)
