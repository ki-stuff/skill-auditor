"""Plattformregeln auf festen Dokumentationsständen; keine Host-/Netzwerkauflösung."""
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from .formats import mcpb_schema, schema_errors
from .adapters import base_dir

PLUGIN_COMMON = set("$schema name version description author homepage repository license keywords".split())
PLUGIN_COMPAT = PLUGIN_COMMON | set("skills commands agents hooks mcpServers lspServers outputStyles settings interface apps onboardingSkill dependencies extensions".split())
MCP_KEYS = set("type command args env cwd url headers http_headers env_http_headers bearer_token_env_var env_vars enabled required startup_timeout_sec startup_timeout_ms tool_timeout_sec enabled_tools disabled_tools oauth extensions platform_overrides tools tool_config auth".split())
HOOK_EVENTS = set("SessionStart SessionEnd Setup InstructionsLoaded UserPromptSubmit UserPromptExpansion MessageDisplay PreToolUse PermissionRequest PostToolUse PostToolUseFailure PostToolBatch PermissionDenied Notification SubagentStart SubagentStop TaskCreated TaskCompleted Stop StopFailure TeammateIdle ConfigChange CwdChanged DirectoryAdded FileChanged WorktreeCreate WorktreeRemove PreCompact PostCompact PreModelSwitch PostModelSwitch Elicitation ElicitationResult".split())

def joined(base, name):
    return str(PurePosixPath(base) / name) if base else name

def auth(a, file, key, value):
    obj = a.unknown(value, {"type", "client", "authorizationUrl", "tokenUrl", "baseScopes", "scheme", "scopes", "resource", "client_id", "callback_port"}, file, key)
    kind = obj.get("type")
    if kind is not None and kind not in {"none", "oauth", "mixed", "api_key"}:
        a.gap(file, key, "Unbekannte Authentifizierungsart")
    a.component("auth-declaration", file, key, auth_type=kind if isinstance(kind, str) else None,
                values="withheld", verified=False)
    if obj:
        a.gap(file, key, "Authentifizierung/Scopes nur deklariert; keine Verbindung oder Rechteprüfung")

def mcp_map(a, file, servers, base=None, scope=None, active="declared", portable=False):
    servers = a.obj(servers, file, "$/mcpServers")
    base = base_dir(file) if base is None else base
    for name, value in servers.items():
        key = "$/mcpServers/" + name
        value = a.unknown(value, MCP_KEYS, file, key)
        component = a.component("mcp-server", file, key, server_name=name, active=active,
                                transport=value.get("type") if isinstance(value.get("type"), str) else None,
                                env_names=list(value.get("env", {})) if isinstance(value.get("env", {}), dict) else [],
                                credential_values="withheld")
        edge_start = len(a.refs)
        if scope is not None:
            slot = (scope, name)
            if slot in a.mcp_effective:
                previous = a.mcp_effective[slot]
                previous["active"] = "shadowed"
                for edge in a.refs:
                    if edge["id"] in previous.get("reference_ids", []):
                        edge["active"] = "shadowed"
            a.mcp_effective[slot] = component
        remote = "url" in value
        local = "command" in value
        if remote == local:
            a.gap(file, key, "Genau eine lokale Start- oder entfernte URL-Konfiguration erwartet")
        if portable and value.get("type") not in {"stdio", "streamable-http", "sse"}:
            a.gap(file, key, "Portabler Transporttyp fehlt oder ist unbekannt")
        if value.get("type") not in {None, "stdio", "http", "sse", "streamable-http"}:
            a.gap(file, key, "Unbekannter MCP-Transport")
        if (remote and value.get("type") == "stdio") or (local and value.get("type") in {"http", "sse", "streamable-http"}):
            a.gap(file, key, "Transport und Start-/URL-Felder widersprechen sich")
        if remote:
            url = value["url"]
            try:
                parsed = urlsplit(url) if isinstance(url, str) else None
                if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ValueError()
                component["endpoint"] = parsed.scheme + "://" + parsed.hostname
                if parsed.scheme != "https":
                    a.finding("M_PLAINTEXT", "MEDIUM", file, key, "Unverschlüsselte HTTP-Verbindung deklariert")
                if parsed.username or parsed.password or parsed.query:
                    a.finding("M_CREDENTIAL", "MEDIUM", file, key, "Zugangsdaten/Querywerte in URL; Werte nicht ausgegeben")
            except ValueError:
                a.gap(file, key, "Ungültige entfernte Adresse")
            a.gap(file, key, "Remote-Servercode und tatsächliche Werkzeuge/Rechte nicht geprüft")
        if local:
            a.command(file, key, value.get("command"), value.get("args", []), base, active)
        for field in ("env", "headers", "http_headers", "env_http_headers"):
            if field in value:
                mapping = a.obj(value[field], file, key + "/" + field)
                if any(not isinstance(v, str) for v in mapping.values()):
                    a.gap(file, key + "/" + field, "Konfigurationswerte müssen Texte sein")
                a.gap(file, key + "/" + field, "Deklarierte Werte nicht aus Hostumgebung aufgelöst; Werte nicht ausgegeben")
        for field in ("enabled_tools", "disabled_tools", "env_vars"):
            if field in value:
                a.strings(value[field], file, key + "/" + field)
                a.gap(file, key + "/" + field, "Deklarierte Auswahl; tatsächliche Rechte nicht verifiziert")
        if "cwd" in value:
            a.reference(file, key + "/cwd", value["cwd"], base)
            a.gap(file, key + "/cwd", "Abweichendes Arbeitsverzeichnis; Startpfade nicht als wirksam aufgelöst")
        if "platform_overrides" in value:
            overrides = a.obj(value["platform_overrides"], file, key + "/platform_overrides")
            for platform, override in overrides.items():
                override = a.unknown(override, {"command", "args", "env"}, file, key + "/platform_overrides/" + platform)
                merged = {k: v for k, v in value.items() if k != "platform_overrides"}
                merged.update(override)
                mcp_map(a, file, {name + "@" + platform: merged}, base, active="platform-conditional")
        for field in ("oauth", "auth"):
            if field in value:
                auth(a, file, key + "/" + field, value[field])
        if "extensions" in value:
            extensions = a.unknown(value["extensions"], {"com.openai"}, file, key + "/extensions")
            if "com.openai" in extensions:
                openai = a.unknown(extensions["com.openai"], {"auth"}, file, key + "/extensions/com.openai")
                if "auth" in openai:
                    auth(a, file, key + "/extensions/com.openai/auth", openai["auth"])
        for field in ("tools", "tool_config"):
            if field in value:
                a.gap(file, key + "/" + field, "Werkzeugbeschreibung/-rechte nur als Text geprüft")
        for field in ("enabled", "required"):
            if field in value and type(value[field]) is not bool:
                a.gap(file, key + "/" + field, "Boolescher Wert erwartet")
        if value.get("enabled") is False:
            component["enabled"] = False
        component["reference_ids"] = [edge["id"] for edge in a.refs[edge_start:]]

def hooks(a, file, events, base, active="declared"):
    events = a.obj(events, file, "$/hooks")
    for event, groups in events.items():
        if event not in HOOK_EVENTS:
            a.gap(file, "$/hooks/" + event, "Unbekanntes Hook-Ereignis")
        if not isinstance(groups, list):
            a.gap(file, "$/hooks/" + event, "Hook-Gruppenliste erwartet")
            continue
        for i, group in enumerate(groups):
            key = "$/hooks/" + event + "/" + str(i)
            group = a.unknown(group, {"matcher", "hooks"}, file, key, ("hooks",))
            handlers = group.get("hooks", [])
            if not isinstance(handlers, list):
                a.gap(file, key, "Hook-Liste erwartet")
                continue
            for j, handler in enumerate(handlers):
                loc = key + "/hooks/" + str(j)
                handler = a.unknown(handler, set("type command prompt url headers allowedEnvVars timeout statusMessage once async asyncRewake model if".split()), file, loc, ("type",))
                a.component("hook", file, loc, event=event, active=active)
                if handler.get("type") == "command":
                    a.command(file, loc, handler.get("command"), base=base, active=active)
                    a.finding("M_HOOK", "MEDIUM", file, loc, "Ereignisgesteuerter Codepfad; fachliche Notwendigkeit prüfen")
                else:
                    a.gap(file, loc, "Prompt-/Agent-/HTTP-/MCP- oder unbekannter Hook: Verhalten nicht ausgeführt")
                if "if" in handler:
                    a.gap(file, loc, "Hook-Bedingung nicht ausgewertet")

def plugin(a, file, data):
    path = PurePosixPath(file)
    flavor = "claude" if path.parent.name == ".claude-plugin" else "codex" if path.parent.name == ".codex-plugin" else "portable"
    base = base_dir(str(path.parent)) if flavor != "portable" else base_dir(file)
    a.component("plugin", file, flavor=flavor, runtime_surface="not_tested")
    known = PLUGIN_COMMON | {"extensions"} if flavor == "portable" else PLUGIN_COMPAT
    a.unknown(data, known, file, required=("name",))
    a.text(data.get("name"), file, "$/name")
    if flavor == "portable" and data.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
        a.gap(file, "$/$schema", "Unbekannte/fehlende portable Schemafassung")
    options = data
    active = "declared"
    if flavor == "portable":
        extensions = a.unknown(data.get("extensions", {}), {"com.openai"}, file, "$/extensions")
        options = a.obj(extensions.get("com.openai", {}), file, "$/extensions/com.openai")
        a.unknown(options, {"interface", "apps", "hooks", "onboardingSkill", "review", "publication"}, file, "$/extensions/com.openai")
    if flavor == "codex":
        portable_file = joined(base, "plugin.json")
        if portable_file in a.texts:
            portable = a.parse(portable_file)
            ext = portable.get("extensions", {}) if isinstance(portable, dict) else {}
            if isinstance(ext, dict) and "com.openai" in ext:
                active = "shadowed"
                a.component("precedence", file, effective=portable_file, shadowed=file,
                            reason="com.openai vorhanden; Codex-Kompatibilitätseinstellungen nicht zusammengeführt")
    for field in ("skills", "commands", "agents", "outputStyles", "apps", "lspServers"):
        if field not in options:
            continue
        value = options[field]
        entries = value if isinstance(value, list) else [value]
        for item in entries:
            if isinstance(item, str):
                a.reference(file, "$/" + field, item, base, active=active)
            elif isinstance(item, dict) and field == "commands":
                for name, definition in item.items():
                    definition = a.obj(definition, file, "$/commands/" + name)
                    if "source" in definition:
                        a.reference(file, "$/commands/" + name, definition["source"], base)
                    if "content" in definition:
                        a.component("inline-command", file, "$/commands/" + name, text_rules="manifest-scanned")
                    a.unknown(definition, {"source", "content", "description", "argumentHint", "model", "allowedTools"}, file, "$/commands/" + name)
            else:
                a.gap(file, "$/" + field, "Komponentenform nicht vollständig aufgelöst")
        if field in {"apps", "lspServers"}:
            a.gap(file, "$/" + field, "Registrierte Dienste/LSP nur deklarativ; keine Verbindung oder vollständiger Adapter")
    # Default directories belong to the package even without explicit manifest references.
    for folder in ("skills", "commands", "agents"):
        if any(p.startswith(joined(base, folder) + "/") for p in a.texts):
            a.component("plugin-directory", file, "$defaults/" + folder, path=joined(base, folder), active="default")
    hook_default = joined(base, "hooks/hooks.json")
    hook_specs = options.get("hooks", [])
    hook_specs = hook_specs if isinstance(hook_specs, list) else [hook_specs]
    if hook_default in a.texts:
        hook_specs = ["./hooks/hooks.json"] + hook_specs
    for spec in hook_specs:
        if isinstance(spec, str):
            edge = a.reference(file, "$/hooks", spec, base, active=active)
            obj = a.parse(edge["target"]) if edge["status"] == "text_observed" else None
            if obj is not None:
                a.handled.add(edge["target"])
                a.unknown(obj, {"hooks"}, edge["target"], required=("hooks",))
                hooks(a, edge["target"], obj.get("hooks"), base, active)
        elif isinstance(spec, dict):
            hooks(a, file, spec, base, active)
        else:
            a.gap(file, "$/hooks", "Ungültige Hook-Komponente")
    if flavor == "portable":
        specs = ["./mcp.json"] if joined(base, "mcp.json") in a.texts else []
    else:
        specs = options.get("mcpServers", [])
        specs = specs if isinstance(specs, list) else [specs]
        if joined(base, ".mcp.json") in a.texts:
            specs = ["./.mcp.json"] + specs
    for spec in specs:
        source = file
        if isinstance(spec, str):
            edge = a.reference(file, "$/mcpServers", spec, base, active=active)
            if edge["status"] != "text_observed" or not spec.endswith(".json"):
                a.gap(file, "$/mcpServers", "MCP-Verweis nicht als lokale JSON-Konfiguration auflösbar; kein Download/inneres Archiv")
                continue
            source = edge["target"]
            a.handled.add(source)
            obj = a.parse(source)
            if obj is None:
                continue
            spec = obj.get("mcpServers", obj)
        if isinstance(spec, dict):
            mcp_map(a, source, spec, base, scope=file, active=active, portable=flavor == "portable")
        else:
            a.gap(file, "$/mcpServers", "Ungültige MCP-Komponente")
    for field in ("settings", "dependencies", "interface", "onboardingSkill", "review", "publication"):
        if field in options:
            a.gap(file, "$/" + field, "Zusätzliche Plugin-Einstellungen nur Textprüfung")
    a.gap(file, "$", "Wirksamkeit gilt nur für bereitgestelltes Paket; Host-/Projektprioritäten und Clientoberflächen ungeprüft")

def mcpb(a, file, data):
    version = data.get("manifest_version", data.get("dxt_version"))
    a.component("mcpb", file, format_version=version if isinstance(version, str) else None)
    if "manifest_version" in data and "dxt_version" in data and data["manifest_version"] != data["dxt_version"]:
        a.gap(file, "$", "manifest_version und dxt_version widersprechen sich")
    if isinstance(version, str) and version in {"0.1", "0.2", "0.3", "0.4"}:
        for key, reason in schema_errors(data, mcpb_schema(version)):
            a.gap(file, key, reason)
    else:
        a.gap(file, "$/manifest_version", "Unbekannte/fehlende MCPB-Fassung")
    server = a.obj(data.get("server"), file, "$/server")
    if "entry_point" in server:
        a.reference(file, "$/server/entry_point", server["entry_point"], kind="launch")
    if "mcp_config" in server:
        mcp_map(a, file, {"bundle": server["mcp_config"]})
    if server.get("type") == "uv":
        a.finding("M_RUNTIME_FETCH", "MEDIUM", file, "$/server", "UV-Laufzeit kann Abhängigkeiten dynamisch installieren")
        a.reference(file, "$/server/type", "pyproject.toml")
        a.gap(file, "$/server", "UV-Hostlaufzeit nicht ausgeführt; 0.4-Anleitung und Schema bei mcp_config abweichend")
    if server.get("type") == "binary":
        a.gap(file, "$/server", "Binärer Servercode nicht analysiert")
    if any(data.get(field) for field in ("tools", "tools_generated", "prompts_generated", "user_config", "_meta", "localization")):
        a.gap(file, "$", "Werkzeuge, Rechte, Nutzereinstellungen und Lokalisierung nur deklariert; keine Laufzeitprüfung")

def platform_file(a, file, data):
    name = PurePosixPath(file).name
    if name == "plugin.json":
        plugin(a, file, data)
    elif name == "manifest.json":
        if any(k in data for k in ("manifest_version", "dxt_version", "server")):
            mcpb(a, file, data)
        else:
            a.gap(file, "$", "Unbekannte Manifestfamilie")
    elif name in {".mcp.json", "mcp.json", "claude_desktop_config.json"}:
        a.unknown(data, {"$schema", "mcpServers"}, file, required=("mcpServers",))
        portable = name == "mcp.json"
        if portable and data.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json":
            a.gap(file, "$/$schema", "Portables MCP-Schema fehlt oder ist unbekannt")
        mcp_map(a, file, data.get("mcpServers", {}), portable=portable)
    elif name == "config.toml":
        a.unknown(data, {"mcp_servers"}, file)
        if "mcp_servers" in data:
            mcp_map(a, file, data["mcp_servers"])
            a.gap(file, "$", "Codex-Konfigurationsausschnitt; andere Host-/Projekt-/Policy-Ebenen nicht eingelesen")
        else:
            a.gap(file, "$", "Keine bekannte MCP-Konfiguration in TOML")
    elif name in {"hooks.json", "settings.json"}:
        a.unknown(data, {"hooks"}, file)
        if "hooks" in data:
            # A standalone hooks file has no proven plugin root: do not invent one.
            hooks(a, file, data["hooks"], base_dir(file))
            a.gap(file, "$", "Standalone-Hooks: Basisverzeichnis/Hostkontext nur lokal beobachtet")
    elif name == ".app.json":
        a.gap(file, "$", "Registrierte Dienstzuordnung nur Textprüfung; Anbieter/Remote-Code nicht geprüft")
