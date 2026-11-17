"""Gemeinsame Berichte, lesender Altimport und getrennte Statusdimensionen."""
import datetime
import hashlib
import json
import re
from pathlib import Path
from dataclasses import asdict
from typing import Optional
from . import SCANNER_VERSION, SCANNER_BASE_COMMIT
from .models import Finding, SkillAuditResult, Execution
from .rules import *
from .privacy import public_result, safe_text, safe_tree

COVERAGE_LABELS = {"complete_for_text_scope": "Textumfang geprüft",
                   "partial": "teilweise geprüft", "insufficient": "nicht ausreichend geprüft",
                   "unknown": "unbekannt"}

def coverage_label(status: str) -> str:
    return COVERAGE_LABELS.get(status, "unbekannt")

def risk_label(data: dict) -> str:
    """Befundstufe verständlich einordnen; gespeicherte Labels nie übernehmen."""
    risk = data.get('max_risk')
    if risk not in (None, 'NONE'):
        return risk
    if not data.get('execution', {}).get('scanner_executed'):
        return 'nicht ermittelt'
    if data.get('coverage', {}).get('status') != 'complete_for_text_scope':
        return 'keine Risikobefunde im geprüften Umfang; keine Entwarnung für ungeprüfte Teile'
    return 'keine Risikobefunde im geprüften Textumfang'

def freshness_label(freshness: dict) -> str:
    labels = {"same": "gleich", "changed": "geändert", "unknown": "unbekannt"}
    return "; ".join(name + ": " + labels.get(freshness.get(key), "unbekannt")
                     for key, name in (("content", "Inhalt"), ("engine", "Kern"),
                                       ("rules", "Regeln"), ("configuration", "Prüfprofil")))
def result_to_dict(result: SkillAuditResult) -> dict:
    result = public_result(result)
    data = {
        "schema_version": 2,
        "scanner_version": SCANNER_VERSION,
        "scanner_base_commit": SCANNER_BASE_COMMIT,
        "skill": result.skill_name,
        "path": result.skill_path,
        "scanner_verdict": result.scanner_verdict,
        "max_risk": result.max_risk,
        "audited_at": result.audited_at,
        "content_hash": result.content_hash,
        "source_commit": result.source_commit,
        "source_commit_note": result.source_commit_note,
        "files_scanned": result.files_scanned,
        "skipped_files": result.skipped_files,
        "total_findings": len(result.findings),
        "verdict_findings": len(result.verdict_findings),
        "findings": [
            {
                "category": f.category,
                "label": f.label,
                "risk": f.risk,
                "original_risk": f.original_risk,
                "file": f.file,
                "line": f.line,
                "description": f.description,
                "snippet": f.snippet,
                "is_reject": f.is_reject,
                "in_code_fence": f.in_code_fence,
                "context_reason": f.context_reason,
            }
            for f in result.findings
        ],
        "limitations": (
            "Automatisches Scanner-Rohurteil; die manuelle Gesamtbewertung bleibt separat "
            "und ist kein vollständiges Security-Review."
        ),
    }



    data.update({
        "engine": engine_identity(),
        "ruleset": ruleset_identity(),
        "artifact": {**asdict(result.artifact), "content_hash": result.content_hash},
        "execution": asdict(result.execution),
        "coverage": result.coverage,
        "input_details": result.input_details,
        "scanner_assessment": result.assessment,
        "manual_assessment": {"status": "pending", "assessment": None},
        "freshness": {
            "checked_at": result.audited_at,
            "content": "snapshot_only" if result.content_hash else "unknown",
            "rules": "snapshot_only", "configuration": "snapshot_only",
            "configuration_id": configuration_id(result.execution.profile, result.input_details.get("limits")),
            "comparison": "not_compared",
            "limitations": "Keine Aussage zu Remote-Code, Abhängigkeiten oder unveränderter Umgebung.",
        },
        "execution_status": result.execution_status,
        "errors": [{"code": result.error_code or "scan_error", "message": result.error}] if result.error else [],
        "report_trust": "unverified_local_output",
    })
    for finding in data["findings"]:
        finding["rule_id"] = finding["category"]
    data['risk_label'] = risk_label(data)
    from .guidance import next_steps
    data['next_steps'] = next_steps(data)
    return data

def report_filename(result: SkillAuditResult) -> str:
    result = public_result(result)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", result.skill_name).strip("-") or "skill"
    digest = (result.content_hash or "sha256:unbekannt").split(":", 1)[-1][:12]
    return f"{safe_name}-{digest}-audit.json"



def engine_identity() -> dict:
    digest = hashlib.sha256()
    core = Path(__file__).parent
    sources = list(core.glob("*.py")) + list(core.joinpath("schemas").glob("*.json"))
    for source in sorted(sources):
        digest.update(source.relative_to(core).as_posix().encode("utf-8"))
        digest.update(source.read_bytes())
    help_source = core.parent.parent / 'references' / 'hilfe-bei-befunden.md'
    digest.update(b'references/hilfe-bei-befunden.md')
    digest.update(help_source.read_bytes())
    return {"name": "skill-auditor-core", "version": SCANNER_VERSION,
            "bundle_sha256": digest.hexdigest(), "release": True}

def ruleset_identity() -> dict:
    payload = json.dumps(PATTERNS, sort_keys=True, ensure_ascii=True).encode("ascii")
    return {"version": "1.0.3", "sha256": hashlib.sha256(payload).hexdigest()}

def configuration_id(profile: str = "core-local", limits=None) -> str:
    from .safeio import Limits
    payload = json.dumps({"profile": profile, "mode": "static-text",
                          "readable_extensions": sorted(READABLE_EXTENSIONS),
                          "readable_filenames": sorted(READABLE_FILENAMES),
                          "max_file_bytes": MAX_SCAN_FILE_BYTES,
                          "input_limits": limits if limits is not None else asdict(Limits())},
                         sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def write_new_output(out_path: Path, text: str, input_roots=()) -> Path:
    """Explizite Ausgabe außerhalb der Eingaben; atomare Nicht-Überschreibprüfung."""
    out_path = Path(out_path)
    resolved = out_path.resolve()
    if any(resolved.is_relative_to(Path(root).resolve()) for root in input_roots):
        raise ValueError("Ausgabe innerhalb eines Prüfobjekts ist nicht erlaubt")
    if out_path.is_symlink() or out_path.exists():
        raise FileExistsError("Vorhandene Berichte werden nicht überschrieben")
    from .safeio import write_exclusive
    write_exclusive(out_path, text)
    return out_path

def write_json_report(result: SkillAuditResult, out_path: Path) -> Optional[Path]:
    """Auch abgebrochene Läufe erhalten auf Wunsch einen getrennten Bericht."""
    return write_new_output(out_path,
                            json.dumps(result_to_dict(result), indent=2, ensure_ascii=False),
                            [result.skill_path])

def read_report(report: Path) -> dict:
    """Nur lesen; fremde Berichte bleiben unbestätigte Behauptungen."""
    try:
        from .safeio import guarded_path
        with guarded_path(report) as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("Berichtsgrößengrenze überschritten")
        from .formats import strict_json
        data = strict_json(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Bericht ist kein Objekt")
        version = data.get("schema_version")
        if 'schema_version' not in data and isinstance(data.get('path'), str) and isinstance(data.get('skill'), str) and isinstance(data.get('max_risk'), str) and data['max_risk'] in {*RISK_ORDER, 'NONE'} and isinstance(data.get('overall_risk'), str):
            # Historical Claude reports had no schema marker. Normalize only
            # the in-memory view; never rewrite or upgrade the source file.
            legacy = {key: data.get(key) for key in ('path', 'max_risk', 'audited_at', 'content_hash')}
            legacy['schema_version'] = 1
            return {'kind': 'legacy', 'data': _safe_import(legacy), 'trust': 'unverified'}
        if type(version) is not int:
            raise ValueError("Schema fehlt oder ist ungültig")
        if version == 1:
            if not isinstance(data.get("path"), str):
                raise ValueError("Altbericht ohne Pfad")
            return {"kind": "legacy", "data": _safe_import(data), "trust": "unverified"}
        if version != 2:
            return {"kind": "unsupported", "data": {}, "trust": "unverified"}
        _validate_v2(data)
        return {"kind": "schema2", "data": _safe_import(data), "trust": "unverified"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        return {"kind": "invalid", "data": {}, "trust": "unverified",
                "error": type(exc).__name__}

def _validate_v2(data: dict) -> None:
    for field_name in ("engine", "ruleset", "artifact", "execution", "coverage",
                       "scanner_assessment", "manual_assessment", "freshness"):
        if not isinstance(data.get(field_name), dict):
            raise ValueError("Fehlende Feldgruppe: " + field_name)
    if not isinstance(data.get("input_details", {}), dict):
        raise ValueError("Ungültige Eingabeprüfdaten")
    components = data['artifact'].get('components', [])
    if not isinstance(components, list) or any(not isinstance(c, dict) for c in components):
        raise ValueError('Ungültige Komponenten')
    adapters = data.get('input_details', {}).get('adapters', {})
    if not isinstance(adapters, dict):
        raise ValueError('Ungültige Adapter')
    for key in ('formats', 'references', 'chains'):
        items = adapters.get(key, [])
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ValueError('Ungültige Adapterliste')
    for field_name in ("findings", "files_scanned", "skipped_files", "errors"):
        if not isinstance(data.get(field_name), list):
            raise ValueError("Fehlende Liste: " + field_name)
    for field_name in ("path", "skill", "audited_at", "execution_status"):
        if not isinstance(data.get(field_name), str):
            raise ValueError("Fehlendes Textfeld")
    if data["artifact"].get("path") != data["path"] or data["artifact"].get("content_hash") != data.get("content_hash"):
        raise ValueError("Widersprüchliches Prüfobjekt")
    if data["manual_assessment"] != {"status": "pending", "assessment": None}:
        raise ValueError("Fremde manuelle Bewertungen werden nicht automatisch übernommen")
    if set(data["execution"]) != set(Execution.__dataclass_fields__):
        raise ValueError("Unvollständige Ausführungsangaben")
    execution = Execution(**data["execution"])
    if any(not isinstance(getattr(execution, name), str)
           for name in Execution.__dataclass_fields__ if name != "scanner_executed"):
        raise ValueError("Ungültige Ausführungsangaben")
    if type(execution.scanner_executed) is not bool:
        raise ValueError("Ungültiger Ausführungsstatus")
    if execution.scan_mode not in {'static-text', 'content_review_only'} or not isinstance(execution.profile, str):
        raise ValueError("Unbekannter Scanmodus")
    if execution.scan_mode == 'content_review_only' and execution.scanner_executed:
        raise ValueError('Inhaltsprüfung darf keinen Scannerlauf behaupten')
    if any(not isinstance(path, str) for path in data["files_scanned"]):
        raise ValueError("Ungültige Dateiliste")
    for gap in data["skipped_files"]:
        if not isinstance(gap, dict) or not all(isinstance(gap.get(k), str) for k in ("file", "reason")):
            raise ValueError("Ungültige Abdeckung")
    findings = []
    for item in data["findings"]:
        if not isinstance(item, dict) or item.get("rule_id") != item.get("category"):
            raise ValueError("Ungültige Regelkennung")
        finding = Finding(**{k: v for k, v in item.items() if k != "rule_id"})
        if finding.risk not in RISK_ORDER or type(finding.is_reject) is not bool:
            raise ValueError("Ungültiges Risiko")
        if type(finding.line) is not int or finding.line < 0:
            raise ValueError("Ungültige Fundstelle")
        if type(finding.in_code_fence) is not bool or (finding.original_risk is not None and finding.original_risk not in RISK_ORDER):
            raise ValueError('Ungültiger Befundkontext')
        for name in ("category", "label", "file", "description", "snippet"):
            if not isinstance(getattr(finding, name), str):
                raise ValueError("Ungültiger Befund")
        findings.append(finding)
    if (type(data.get('total_findings')) is not int or data['total_findings'] != len(findings)
            or type(data.get('verdict_findings')) is not int
            or data['verdict_findings'] != sum(f.risk != 'CONTEXT' for f in findings)):
        raise ValueError('Widersprüchliche Befundanzahl')
    errors = data["errors"]
    if any(not isinstance(e, dict) or not isinstance(e.get("message"), str) for e in errors):
        raise ValueError("Ungültige Fehlerliste")
    reconstructed = SkillAuditResult(
        skill_path=data["path"], skill_name=data["skill"], findings=findings,
        files_scanned=data["files_scanned"], skipped_files=data["skipped_files"],
        error=errors[0]["message"] if errors else None, execution=execution,
        input_details=data.get("input_details", {}))
    expected_coverage = reconstructed.coverage
    # Frühe Schema-2-Berichte verwendeten diesen exakten Fallback. Nur lesend
    # akzeptieren; alle übrigen Abdeckungs- und Urteilsprüfungen bleiben bestehen.
    legacy_limits = {"max_text_file_bytes": MAX_SCAN_FILE_BYTES,
                     "global_resource_limits": "not_implemented_ap2"}
    if (not reconstructed.input_details.get('limits')
            and data['coverage'].get('limits') == legacy_limits):
        expected_coverage['limits'] = legacy_limits
    if (reconstructed.assessment != data["scanner_assessment"]
            or expected_coverage != data["coverage"]
            or reconstructed.execution_status != data["execution_status"]
            or reconstructed.max_risk != data.get("max_risk")
            or reconstructed.verdict != data.get("scanner_verdict")):
        raise ValueError("Befund, Abdeckung und Rohurteil widersprechen sich")
    for field_name, keys in (("engine", ("version", "bundle_sha256")),
                             ("ruleset", ("version", "sha256")),
                             ("freshness", ("checked_at", "configuration_id"))):
        if any(not isinstance(data[field_name].get(k), str) for k in keys):
            raise ValueError("Fehlende Vergleichskennung")

def report_status(report: Path, skill_dir: Path, current_hash: str,
                  embedded: bool = False, profile: str = "core-local") -> Optional[dict]:
    parsed = read_report(report)
    data = parsed["data"]
    if not data:
        return None
    try:
        if Path(data["path"]).resolve() != skill_dir.resolve():
            return None
    except (OSError, ValueError):
        return None
    freshness = {
        "content": "unknown" if not current_hash or not data.get("content_hash") else "same" if data.get("content_hash") == current_hash else "changed",
        "engine": "unknown", "rules": "unknown", "configuration": "unknown",
    }
    result = {"status": "unaudited", "verdict": "⚪ Altbericht – neue Prüfabdeckung unbekannt",
              "audited_at": data.get("audited_at"), "content_hash": current_hash,
              "report": str(report), "report_kind": parsed["kind"], "report_trust": "unverified",
              "coverage": {"status": "unknown"}, "risk": data.get("max_risk"),
              "freshness": freshness, "manual_assessment": {"status": "pending"}}
    if parsed["kind"] == "legacy":
        if data.get("max_risk") == "CRITICAL":
            result.update(status="reject", verdict="🔴 Altbericht meldet Ablehnungsbefund; unbestätigt")
        return result
    for key, actual, stored in (
        ("engine", engine_identity(), data["engine"]),
        ("rules", ruleset_identity(), data["ruleset"]),
        ("configuration", configuration_id(profile), data["freshness"]["configuration_id"]),
    ):
        freshness[key] = "same" if actual == stored else "changed"
    assessment = data["scanner_assessment"]
    result.update(coverage=data["coverage"], risk=assessment["risk"],
                  verdict=data["scanner_verdict"], manual_assessment=data["manual_assessment"])
    if assessment["status"] == "reject":
        result["status"] = "reject"  # Rot bleibt auch bei veraltetem Bericht sichtbar.
    elif embedded:
        result.update(status="unaudited", verdict="⚪ Mitgelieferter Bericht – unabhängig neu prüfen")
    elif any(v != "same" for v in freshness.values()):
        result["status"] = "stale"
    else:
        result["status"] = {"clear": "clear", "caution": "caution"}.get(assessment["status"], "unaudited")
    result["verdict"] += " (Berichtsangabe, Herkunft unbestätigt)"
    return result

def print_batch_summary(results: list[SkillAuditResult]) -> None:
    print("\n")
    print("BATCH-AUDIT")
    print("═" * 55)
    print(f"{'Skill':<30} {'Risiko':<10} {'Verdict'}")
    print("─" * 55)
    for r in results:
        r = public_result(r)
        risk = risk_label(result_to_dict(r))
        print(f"{r.skill_name:<30} {risk:<10} {r.short_verdict}")
    print("─" * 55)
    total = len(results)
    flags = sum(1 for r in results if r.findings)
    rejects = sum(1 for r in results if "REJECT" in r.short_verdict)
    print(f"Gesamt: {total} Skills | {flags} mit Flags | {rejects} Rejections")
    print("═" * 55)


def _safe_import(data):
    """Nur eine maskierte Ansicht importieren; Quelldatei niemals umschreiben."""
    from .privacy import Redactor
    redactor = Redactor()
    redactor.observe_tree(data)
    if data.get('schema_version') == 1:
        data = {key: data.get(key) for key in ('schema_version', 'path', 'max_risk', 'audited_at', 'content_hash')}
    for item in data.get('findings', []):
        if isinstance(item, dict) and 'snippet' in item:
            item['snippet'] = '[Historischer Rohbeleg zurückgehalten]'
    if redactor.detected:
        data['content_hash'] = None
        data['source_commit'] = None
        if isinstance(data.get('artifact'), dict):
            data['artifact']['content_hash'] = None
            for component in data['artifact'].get('components', []):
                component.pop('source_file_sha256', None)
        data.get('input_details', {}).pop('container_sha256', None)
    # Typed conclusions were validated before masking and must not be rewritten
    # by a matching sensitive value. They remain unverified historical claims.
    keep = {key: data[key] for key in ('schema_version', 'max_risk', 'scanner_assessment',
            'scanner_verdict', 'execution_status', 'manual_assessment') if key in data and data.get('schema_version') == 2}
    cleaned = safe_tree(data, redactor)
    cleaned.update(keep)
    if data.get('schema_version') == 2:
        from .guidance import next_steps
        cleaned['risk_label'] = risk_label(cleaned)
        cleaned['next_steps'] = next_steps(cleaned)
    if data.get('schema_version') == 1 and data.get('max_risk') in RISK_ORDER:
        cleaned['max_risk'] = data['max_risk']
    return cleaned


def print_report(result: SkillAuditResult) -> None:
    from .presentation import render_text
    print(render_text(result_to_dict(result)))

