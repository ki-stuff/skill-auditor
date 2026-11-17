"""Begrenzte Strukturparser. Keine Imports, Resolver oder Schemas aus Prüfobjekten."""
import json
import math
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from .safeio import InputError, valid_name

MAX_NODES = 50000
MAX_DEPTH = 48

def check_tree(value, max_nodes=MAX_NODES):
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > max_nodes or depth > MAX_DEPTH:
            raise ValueError("Strukturgrenze überschritten")
        if isinstance(node, dict):
            pending.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            pending.extend((v, depth + 1) for v in node)
        elif isinstance(node, float) and not math.isfinite(node):
            raise ValueError("Nicht endliche Zahl")
    return value

def strict_json(text, max_nodes=MAX_NODES):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("Doppelter JSON-Schlüssel")
            out[key] = value
        return out
    return check_tree(json.loads(text, object_pairs_hook=pairs,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON-Konstante"))),
                      max_nodes)

def schema_errors(value, schema, root=None, key="$", depth=0):
    """Nur benötigte Keywords der fest mitgelieferten MCPB-Schemas, kein externer $ref."""
    root = schema if root is None else root
    if depth > MAX_DEPTH:
        return [(key, "Schema-Tiefengrenze")]
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return [(key, "Externe Schemareferenz ungeprüft")]
        target = root
        for part in ref[2:].split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        return schema_errors(value, target, root, key, depth + 1)
    if "anyOf" in schema:
        if not any(not schema_errors(value, s, root, key, depth + 1) for s in schema["anyOf"]):
            return [(key, "Kein erlaubter Strukturtyp")]
    kind = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "boolean": bool}
    if kind in types and not isinstance(value, types[kind]):
        return [(key, "Falscher Feldtyp")]
    if kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return [(key, "Falscher Zahltyp")]
    errors = []
    if "const" in schema and value != schema["const"]:
        errors.append((key, "Widersprüchliche Formatversion"))
    if "enum" in schema and value not in schema["enum"]:
        errors.append((key, "Unbekannter Feldwert"))
    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                errors.append((key + "/" + field, "Pflichtfeld fehlt"))
        props = schema.get("properties", {})
        for field, child in value.items():
            sub = props.get(field, schema.get("additionalProperties", {}))
            if sub is False:
                errors.append((key + "/" + field, "Unbekanntes Feld"))
            elif isinstance(sub, dict):
                errors.extend(schema_errors(child, sub, root, key + "/" + field, depth + 1))
    if isinstance(value, list) and "items" in schema:
        for index, child in enumerate(value):
            errors.extend(schema_errors(child, schema["items"], root, key + "/" + str(index), depth + 1))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append((key, "Text zu kurz"))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append((key, "Feldmuster passt nicht"))
        # Formatanmerkungen sind bewusst nur syntaktische Plausibilitätsprüfungen.
        if schema.get("format") == "uri" and not urlsplit(value).scheme:
            errors.append((key, "URI ohne Schema"))
        if schema.get("format") == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+", value):
            errors.append((key, "E-Mail-Syntax unklar"))
    return errors[:200]

def mcpb_schema(version):
    if version not in {"0.1", "0.2", "0.3", "0.4"}:
        raise ValueError("Unbekannte MCPB-Version")
    return json.loads(Path(__file__).with_name("schemas").joinpath("mcpb-" + version + ".json").read_text(encoding="utf-8"))

def local_reference(base, value):
    if not isinstance(value, str) or not value:
        raise ValueError("Leerer oder ungültiger Dateiverweis")
    for marker in ("${CLAUDE_PLUGIN_ROOT}", "${CODEX_PLUGIN_ROOT}", "${__dirname}"):
        if value == marker or value.startswith(marker + "/"):
            value = value[len(marker):].lstrip("/")
            break
    if re.search(r"[$%{}*?]", value):
        raise ValueError("Dynamischer Dateiverweis nicht auflösbar")
    if value.startswith("./"):
        value = value[2:]
    valid_name(value)
    joined = str(PurePosixPath(base) / value) if base else value
    return valid_name(joined)

def safe_value(value):
    """Konfigurationswerte nicht als Rohgeheimnisse in den neuen Strukturbericht übernehmen."""
    if not isinstance(value, str):
        return "[kein Text]"
    value = re.sub(r"[\x00-\x1f\x7f]", "?", value)
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z_0-9.]*\}", value):
        return value
    return "[Wert nicht ausgegeben]"
