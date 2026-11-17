"""Statische Adapter auf bereits begrenzt gelesenen virtuellen Dateien."""
import configparser
import ast
from email.parser import Parser
from pathlib import PurePosixPath
import re
import shlex
import tomllib
from urllib.parse import urlsplit
from .formats import strict_json, check_tree, local_reference, mcpb_schema, schema_errors
from .models import Finding
from .safeio import InputError

FORMAT_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pyproject.toml",
                "setup.cfg", "setup.py", "METADATA", "PKG-INFO", "WHEEL", "entry_points.txt",
                "manifest.json", "plugin.json", ".mcp.json", "mcp.json", "config.toml",
                "claude_desktop_config.json", "hooks.json", "settings.json", ".app.json"}

def is_metadata(name):
    return PurePosixPath(name).name in FORMAT_FILES

def base_dir(name):
    parent = str(PurePosixPath(name).parent)
    return "" if parent == "." else parent

class Adapters:
    def __init__(self, reader):
        self.reader = reader
        self.result = reader.result
        self.texts = {}
        self.text_bytes = 0
        self.refs = []
        self.parsed = {}
        self.limit = min(reader.budget.limits.findings, 2000)
        self.report = {"version": "ap3-1", "formats": [], "references": self.refs,
                       "scope": "Statische Struktur- und Verweisprüfung; keine Ausführung oder vollständige Datenflussanalyse"}
        self.result.input_details["adapters"] = self.report
        self.mcp_effective = {}
        self.handled = set()

    def capture(self, name, text, size):
        if self.text_bytes + size > 32 * 1024 * 1024:
            self.gap(name, "$", "Adapter-Textspeichergrenze 32 MiB; Rest nur Musterprüfung")
            return
        self.texts[name] = text
        self.text_bytes += size

    def tick(self):
        self.reader.budget.check()
        if len(self.result.artifact.components) + len(self.refs) > self.limit:
            raise InputError("Adapter-Komponenten-/Verweisbudget überschritten")

    def gap(self, file, key, reason):
        self.reader.gap(file, str(key)[:300] + ": " + reason)

    def finding(self, rule, risk, file, key, description, reject=False):
        if len(self.result.findings) >= self.reader.budget.limits.findings:
            raise InputError("Befundbudget überschritten")
        self.result.findings.append(Finding(rule, risk, "Strukturprüfung", file, 0,
                                            key[:300] + ": " + description, "", is_reject=reject))
        self.reader.progress(self.result)

    def component(self, kind, file, key="$", **details):
        self.tick()
        if not hasattr(self, "file_hashes"):
            self.file_hashes = {name: digest for name, _, digest in self.reader.records}
        obj = {"kind": kind, "file": file, "key": key,
               "source_file_sha256": self.file_hashes.get(file), **details}
        if kind in {"npm-package", "npm-lock", "python-project", "plugin", "mcpb"}:
            data = self.parsed.get(file) or {}
            if kind == "python-project":
                data = data.get("project", {})
            if not isinstance(data, dict):
                data = {}
            for source_key in ("name", "version"):
                value = data.get(source_key)
                obj["declared_" + source_key] = (value if isinstance(value, str)
                    and re.fullmatch(r"[A-Za-z0-9@._/+~-]{1,160}", value) else None)
            origin = data.get("repository", data.get("homepage"))
            if isinstance(origin, dict):
                origin = origin.get("url")
            obj["source_status"] = "declared_unverified" if origin else "not_declared"
            obj["source_verified"] = False
            obj["declared_source_host"] = None
            if isinstance(origin, str):
                try:
                    obj["declared_source_host"] = urlsplit(origin.removeprefix("git+")).hostname
                except ValueError:
                    pass
        self.result.artifact.components.append(obj)
        return obj

    def obj(self, value, file, key):
        if not isinstance(value, dict):
            self.gap(file, key, "Objekt erwartet")
            return {}
        return value

    def unknown(self, value, known, file, key="$", required=()):
        value = self.obj(value, file, key)
        for field in value:
            self.tick()
            if field not in known:
                self.gap(file, key + "/" + field, "Unbekanntes oder nicht semantisch ausgewertetes Feld")
        for field in required:
            if field not in value:
                self.gap(file, key + "/" + field, "Pflichtfeld fehlt")
        return value

    def text(self, value, file, key):
        if not isinstance(value, str) or not value:
            self.gap(file, key, "Nichtleerer Text erwartet")
            return None
        return value

    def strings(self, value, file, key):
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
            self.gap(file, key, "Liste von Textwerten erwartet")
            return []
        return value

    def parse(self, file):
        if file in self.parsed:
            return self.parsed[file]
        try:
            text = self.texts[file]
            data = check_tree(tomllib.loads(text)) if file.endswith(".toml") else strict_json(text)
            if not isinstance(data, dict):
                raise ValueError("Wurzel kein Objekt")
        except (ValueError, RecursionError, KeyError):
            self.gap(file, "$", "Manifest fehlt, ist ungültig, mehrdeutig oder zu tief verschachtelt")
            data = None
        self.parsed[file] = data
        return data

    def reference(self, file, key, value, base=None, kind="file", active="declared"):
        self.tick()
        base = base_dir(file) if base is None else base
        edge = {"id": "ref-" + str(len(self.refs) + 1), "source": file, "key": key,
                "kind": kind, "target": None, "status": "unresolved", "active": active}
        self.refs.append(edge)
        try:
            target = local_reference(base, value)
        except (ValueError, InputError):
            self.gap(file, key, "Verweis außerhalb des Objekts, dynamisch oder ungültig; nicht verfolgt")
            return edge
        edge["target"] = target
        all_names = self.reader.names.paths.values()
        if target not in all_names:
            self.gap(file, key, "Referenzierte Datei/Verzeichnis fehlt: " + target[:300])
            edge["status"] = "missing"
        elif target in self.texts:
            edge["status"] = "text_observed"
        elif any(path.startswith(target + "/") for path in self.texts):
            edge["status"] = "directory_observed"
        else:
            edge["status"] = "not_text_checked"
            self.gap(file, key, "Referenzziel nicht inhaltlich geprüft")
        return edge

    def command(self, file, key, command, args=None, base=None, active="declared"):
        self.component("start", file, key, active=active, command_values="withheld")
        if not isinstance(command, str) or not command:
            self.gap(file, key, "Startbefehl fehlt oder hat falschen Typ")
            return
        self.finding("M_EXECUTION", "LOW", file, key, "Deklarierter Start-/Ausführungspfad; keine Aussage über schädliche Absicht")
        if args is None:
            try:
                tokens = shlex.split(command, posix=True)
            except ValueError:
                self.gap(file, key, "Befehlszeichenfolge nicht eindeutig zerlegbar")
                return
        else:
            tokens = [command] + self.strings(args, file, key + "/args")
        if not tokens:
            return
        joined = " ".join(tokens)
        program = PurePosixPath(tokens[0].replace("\\", "/")).name.lower().removesuffix(".exe")
        if re.search(r"[|;&`\n\r]|\$\(", joined) or program in {"sh", "bash", "cmd", "powershell", "pwsh"}:
            self.gap(file, key, "Shell-/Wrappersemantik nur statisch teilweise auflösbar")
            self.finding("M_SHELL", "MEDIUM", file, key, "Shell-Wrapper oder zusammengesetzter Befehl")
        if program in {"npx", "npm", "pnpm", "yarn", "uv", "uvx", "pip", "pip3"}:
            self.gap(file, key, "Paketmanager kann fremde Inhalte laden; keine Auflösung oder Ausführung")
            self.finding("M_FETCH", "MEDIUM", file, key, "Möglicher Nachlade-/Installationspfad")
        linked = False
        for index, token in enumerate(tokens):
            if token.startswith(("https://", "http://")):
                self.gap(file, key, "Entfernter Befehlsbestandteil nicht abgerufen")
            if token.startswith("-"):
                continue
            if (token.endswith((".py", ".js", ".mjs", ".cjs", ".sh", ".ps1", ".cmd", ".bat"))
                    or (index == 0 and ("/" in token or "\\" in token))):
                self.reference(file, key, token, base, "launch", active)
                linked = True
        if not linked:
            self.gap(file, key, "Ausführbarer Inhalt nicht an eine bereitgestellte Textdatei gebunden")
        if any(t in {"-c", "-e", "-m", "--eval", "-Command", "-EncodedCommand"} for t in tokens):
            self.gap(file, key, "Inline-Code oder Modulauflösung nicht vollständig verfolgt")

    def dependencies(self, file, key, values):
        if isinstance(values, dict):
            entries = values.items()
        elif isinstance(values, list) and all(isinstance(v, str) for v in values):
            entries = [(str(i), v) for i, v in enumerate(values)]
        else:
            self.gap(file, key, "Ungültige Abhängigkeitsliste")
            return
        any_entries = False
        for name, spec in entries:
            any_entries = True
            self.component("dependency", file, key + "/" + str(name), declared_only=True,
                           pinned=bool(isinstance(spec, str) and re.fullmatch(r"(?:[\w.-]+==)?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?", spec)))
            if not isinstance(spec, str):
                self.gap(file, key, "Abhängigkeit hat keinen einfachen Textwert")
            elif spec.startswith(("file:", "./", "../")):
                self.reference(file, key + "/" + str(name), spec.removeprefix("file:"))
        if any_entries:
            self.gap(file, key, "Abhängigkeiten nur deklariert; Lockdatei/Versionsbindung beweist keine Inhaltsprüfung")

    def npm(self, file, data):
        known = set("name version description keywords homepage bugs license author contributors funding files main browser bin man directories repository scripts config dependencies devDependencies optionalDependencies peerDependencies peerDependenciesMeta bundledDependencies bundleDependencies engines os cpu libc private publishConfig workspaces exports imports type packageManager overrides devEngines sideEffects types typings module".split())
        self.unknown(data, known, file, required=("name", "version"))
        for field in ("name", "version"):
            self.text(data.get(field), file, "$//" + field)
        self.component("npm-package", file)
        scripts = self.obj(data.get("scripts", {}), file, "$/scripts")
        for name, command in scripts.items():
            self.command(file, "$/scripts/" + name, command)
            if name in {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack"}:
                self.finding("P_LIFECYCLE", "MEDIUM", file, "$/scripts/" + name, "Installations-/Build-Lebenszyklus kann Code ausführen")
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides"):
            if field in data:
                self.dependencies(file, "$/" + field, data[field])
        for field in ("main", "bin"):
            if field in data:
                value = data[field]
                for target in value.values() if isinstance(value, dict) else [value]:
                    self.reference(file, "$/" + field, target, kind="launch")
        for field in ("exports", "imports", "browser", "workspaces", "config", "publishConfig"):
            if data.get(field):
                self.gap(file, "$/" + field, "Bedingte Paket-/Workspace-Konfiguration nicht vollständig aufgelöst")
        prefix = base_dir(file)
        sibling = lambda name: str(PurePosixPath(prefix) / name) if prefix else name
        if sibling("binding.gyp") in self.texts and "install" not in scripts and "preinstall" not in scripts:
            self.finding("P_NATIVE_BUILD", "MEDIUM", file, "$", "binding.gyp kann impliziten nativen Installationsbuild auslösen")
            self.gap(file, "$", "Nativer Build nicht ausgeführt oder analysiert")
        shrink, lock = sibling("npm-shrinkwrap.json"), sibling("package-lock.json")
        if shrink in self.texts and lock in self.texts:
            self.component("precedence", file, effective=shrink, shadowed=lock, reason="npm-shrinkwrap hat Vorrang")

    def npm_lock(self, file, data):
        version = data.get("lockfileVersion")
        self.component("npm-lock", file, format_version=version if type(version) is int else None)
        self.unknown(data, {"name", "version", "lockfileVersion", "requires", "packages", "dependencies"}, file, required=("lockfileVersion",))
        if type(version) is not int or version not in (1, 2, 3):
            self.gap(file, "$/lockfileVersion", "Unbekanntes Lockformat")
        containers = []
        if version in (2, 3):
            containers.append(("$/packages", self.obj(data.get("packages"), file, "$/packages")))
        if "dependencies" in data or version == 1:
            containers.append(("$/dependencies", self.obj(data.get("dependencies"), file, "$/dependencies")))
        pending = [(key + "/" + name, value) for key, entries in containers for name, value in entries.items()]
        while pending:
            key, item = pending.pop()
            self.tick()
            item = self.unknown(item, set("name version resolved integrity link dev optional devOptional inBundle bundled hasInstallScript hasShrinkwrap license engines os cpu libc funding bin dependencies optionalDependencies peerDependencies peerDependenciesMeta requires workspaces extraneous peer".split()), file, key)
            self.component("locked-dependency", file, key, integrity_declared=bool(item.get("integrity")), content_verified=False)
            if item.get("hasInstallScript") is True:
                self.finding("P_LOCK_INSTALL", "MEDIUM", file, key, "Lockdatei deklariert Installationsskript; dessen Inhalt bleibt zu prüfen")
            if item.get("link") is True or str(item.get("resolved", "")).startswith("file:"):
                self.gap(file, key, "Lokale/Workspace-Bindung nicht vollständig aufgelöst")
            children = item.get("dependencies", {})
            if isinstance(children, dict):
                pending.extend((key + "/dependencies/" + n, v) for n, v in children.items() if isinstance(v, dict))
        if pending or containers:
            self.gap(file, "$", "Lockmetadaten einschließlich transitiver Einträge sind kein Inhaltsnachweis")

    def python_project(self, file, data):
        self.unknown(data, {"build-system", "project", "tool", "dependency-groups"}, file)
        self.component("python-project", file)
        if "build-system" in data:
            build = self.unknown(data["build-system"], {"requires", "build-backend", "backend-path"}, file, "$/build-system", ("requires",))
            self.dependencies(file, "$/build-system/requires", build.get("requires", []))
            self.finding("P_BUILD", "MEDIUM", file, "$/build-system", "Build-Backend kann Code ausführen; kein Build gestartet")
            backend = build.get("build-backend")
            if backend is not None:
                self.module_reference(file, "$/build-system/build-backend", backend, build.get("backend-path", []))
            for item in self.strings(build.get("backend-path", []), file, "$/build-system/backend-path"):
                if item == ".":
                    self.component("backend-path", file, declared_root=True)
                else:
                    self.reference(file, "$/build-system/backend-path", item)
        else:
            self.gap(file, "$/build-system", "Build-Backend/implizite Defaults nicht bestimmt")
        project = self.unknown(data.get("project", {}), set("name version description readme requires-python license license-files authors maintainers keywords classifiers urls scripts gui-scripts entry-points dependencies optional-dependencies dynamic import-names import-namespaces".split()), file, "$/project", ("name",))
        if "version" not in project and "version" not in project.get("dynamic", []):
            self.gap(file, "$/project/version", "Version fehlt")
        if project.get("dynamic"):
            self.gap(file, "$/project/dynamic", "Dynamische Metadaten nicht ausgeführt/aufgelöst")
        for key in ("dependencies",):
            if key in project:
                self.dependencies(file, "$/project/" + key, project[key])
        for group, deps in self.obj(project.get("optional-dependencies", {}), file, "$/project/optional-dependencies").items():
            self.dependencies(file, "$/project/optional-dependencies/" + group, deps)
        for group in ("scripts", "gui-scripts"):
            for name, ref in self.obj(project.get(group, {}), file, "$/project/" + group).items():
                self.module_reference(file, "$/project/" + group + "/" + name, ref)
        for group, items in self.obj(project.get("entry-points", {}), file, "$/project/entry-points").items():
            for name, ref in self.obj(items, file, "$/project/entry-points/" + group).items():
                self.module_reference(file, "$/project/entry-points/" + group + "/" + name, ref)
        if data.get("tool") or data.get("dependency-groups"):
            self.gap(file, "$", "Werkzeugspezifische Konfiguration/Abhängigkeitsgruppen nur Textprüfung")

    def module_reference(self, file, key, value, roots=None):
        if not isinstance(value, str) or not re.fullmatch(r"[\w.]+(?::[\w.]+)?", value, re.ASCII):
            self.gap(file, key, "Dynamischer/ungültiger Python-Modulverweis")
            return
        module = value.split(":")[0].replace(".", "/")
        root_values = roots if isinstance(roots, list) and roots else [".", "src"]
        candidates = []
        for root in root_values:
            if not isinstance(root, str):
                self.gap(file, key, "Ungültiger Backend-Pfad")
                continue
            for suffix in (".py", "/__init__.py"):
                target = module + suffix if root == "." else root + "/" + module + suffix
                try:
                    resolved = local_reference(base_dir(file), target)
                except (ValueError, InputError):
                    self.gap(file, key, "Modulpfad außerhalb der Eingabe")
                    continue
                if resolved in self.texts:
                    candidates.append(target)
        if len(candidates) == 1:
            self.reference(file, key, candidates[0], kind="launch")
        else:
            self.gap(file, key, "Modulauflösung fehlt oder ist mehrdeutig; nichts importiert")

    def python_ini(self, file):
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(self.texts[file])
        except configparser.Error:
            self.gap(file, "$", "Ungültige/mehrdeutige INI-Struktur")
            return
        self.component("python-ini", file)
        for section in parser.sections():
            for key, value in parser.items(section):
                self.tick()
                loc = section + "/" + key
                if PurePosixPath(file).name == "entry_points.txt" or section == "options.entry_points":
                    for item in value.splitlines():
                        if item.strip():
                            self.module_reference(file, loc, item.split("=", 1)[-1].strip())
                elif key in {"install_requires", "setup_requires", "tests_require"} or section == "options.extras_require":
                    self.dependencies(file, loc, [x.strip() for x in value.splitlines() if x.strip()])
                elif "attr:" in value or "file:" in value:
                    self.gap(file, loc, "Dynamische/file:-Metadaten nicht importiert oder nachgeladen")
                elif section not in {"metadata", "options"} or key not in {"name", "version", "description", "author", "license", "url", "packages", "python_requires", "zip_safe", "include_package_data"}:
                    self.gap(file, loc, "INI-Feld nur Textprüfung")

    def python_metadata(self, file):
        message = Parser().parsestr(self.texts[file])
        wheel = PurePosixPath(file).name == "WHEEL"
        version_key = "Wheel-Version" if wheel else "Metadata-Version"
        version = message.get(version_key)
        self.component("wheel" if wheel else "python-metadata", file, format_version=version)
        known_versions = {"1.0"} if wheel else {"1.0", "1.1", "1.2", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6"}
        if version not in known_versions:
            self.gap(file, version_key, "Unbekannte Metadatenversion")
        required = (version_key, "Root-Is-Purelib", "Tag") if wheel else (version_key, "Name", "Version")
        for key in required:
            if not message.get(key):
                self.gap(file, key, "Pflichtfeld fehlt")
            if key != "Tag" and len(message.get_all(key, [])) > 1:
                self.gap(file, key, "Widersprüchliches doppeltes Pflichtfeld")
        known = set("Metadata-Version Name Version Dynamic Platform Supported-Platform Summary Description Description-Content-Type Keywords Home-page Download-URL Author Author-email Maintainer Maintainer-email License License-Expression License-File Classifier Requires-Dist Requires-Python Requires-External Project-URL Provides-Extra Provides-Dist Obsoletes-Dist Import-Name Import-Namespace Requires Provides Obsoletes".lower().split())
        if wheel:
            known = {"wheel-version", "generator", "root-is-purelib", "tag", "build"}
        for key in message.keys():
            if key.lower() not in known:
                self.gap(file, key, "Unbekanntes Metadatenfeld")
        if message.defects or message.get_all("Dynamic"):
            self.gap(file, "$", "Fehlerhafte oder dynamische Metadaten")
        self.dependencies(file, "Requires-Dist", message.get_all("Requires-Dist", []))
        self.gap(file, "$", "Metadaten strukturell erfasst; keine Installation, vollständige Wheel-/RECORD- oder Semantikvalidierung")

    def script_references(self, file):
        """Explizite statische Python-Aufrufe; keine Auswertung von Ausdrücken."""
        if not file.endswith(".py"):
            return
        try:
            tree = ast.parse(self.texts[file])
        except (SyntaxError, ValueError, RecursionError):
            # A .py file can be prose used by a fixture or unsupported syntax.
            self.gap(file, "$", "Python-Syntax nicht strukturell auflösbar; nur Musterprüfung")
            return
        aliases = {"subprocess": "subprocess", "os": "os"}
        direct = {}
        for node in ast.walk(tree):
            self.tick()
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"subprocess", "os"}:
                        aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module in {"subprocess", "os"}:
                for alias in node.names:
                    direct[alias.asname or alias.name] = node.module + "." + alias.name
        for node in ast.walk(tree):
            self.tick()
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = direct.get(func.id) if isinstance(func, ast.Name) else None
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                name = aliases.get(func.value.id, "") + "." + func.attr
            if name not in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output", "os.system"}:
                continue
            loc = "Python-Aufruf Zeile " + str(node.lineno)
            argument = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in {"args", "command"}), None)
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                self.command(file, loc, argument.value)
            elif isinstance(argument, (ast.List, ast.Tuple)) and argument.elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in argument.elts):
                values = [e.value for e in argument.elts]
                self.command(file, loc, values[0], values[1:])
            else:
                self.gap(file, loc, "Dynamischer Prozessaufruf nicht auflösbar; keine Auswertung")
            self.gap(file, loc, "Aufruf syntaktisch vorhanden; Kontrollfluss und Aliasüberschreibung nicht verifiziert")

    def run(self):
        from .platform_adapters import platform_file
        for file in sorted(self.texts, key=lambda p: (PurePosixPath(p).name != "plugin.json", p)):
            self.tick()
            if file in self.handled:
                continue
            name = PurePosixPath(file).name
            self.script_references(file)
            if name in {"setup.cfg", "entry_points.txt"}:
                self.python_ini(file)
                continue
            if name in {"METADATA", "PKG-INFO", "WHEEL"}:
                self.python_metadata(file)
                continue
            if name == "setup.py":
                self.component("python-setup", file)
                self.finding("P_SETUP", "MEDIUM", file, "$", "setup.py ist ausführbarer Buildcode; nur als Text gelesen")
                self.gap(file, "$", "Dynamische setup.py-Metadaten nicht aufgelöst")
                continue
            if name in {"pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "requirements.txt"}:
                self.gap(file, "$", "Kein semantischer Parser für dieses Abhängigkeitsformat")
            if file.endswith(".md"):
                for match in re.finditer(r"\[[^\]\n]*\]\(([^\s)]+)\)", self.texts[file]):
                    target = match.group(1).split("#")[0]
                    if target and not re.match(r"[A-Za-z][\w+.-]*:", target):
                        self.reference(file, "Markdown-Link", target, kind="documentation")
            if file.endswith((".yaml", ".yml")):
                self.gap(file, "$", "YAML nur als Text geprüft; kein struktureller Adapter")
            if not file.endswith((".json", ".toml")):
                continue
            data = self.parse(file)
            if data is None:
                continue
            before = len(self.result.skipped_files)
            if name == "package.json":
                self.npm(file, data)
            elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
                self.npm_lock(file, data)
            elif name == "pyproject.toml":
                self.python_project(file, data)
            elif not is_metadata(file) and "mcpServers" in data:
                from .platform_adapters import mcp_map
                self.unknown(data, {"$schema", "mcpServers"}, file)
                mcp_map(self, file, data["mcpServers"])
            elif not is_metadata(file) and "mcp_servers" in data:
                from .platform_adapters import mcp_map
                self.unknown(data, {"mcp_servers"}, file)
                mcp_map(self, file, data["mcp_servers"])
                self.gap(file, "$", "Konfiguration ohne belegten Host-/Projektkontext")
            elif not is_metadata(file):
                self.gap(file, "$", "Keine erkannte Strukturfamilie; nur Textprüfung")
            else:
                platform_file(self, file, data)
            self.report["formats"].append({"file": file, "status": "partial" if len(self.result.skipped_files) > before else "structure_checked"})
        # Explicit edges only. Risk from unrelated files is never combined into a chain.
        for edge in self.refs[:]:
            if edge["kind"] != "launch" or edge["status"] != "text_observed":
                continue
            severe = [f for f in self.result.findings if f.file == edge["target"] and f.risk in {"HIGH", "CRITICAL"} and f.category != "M_EXEC_CHAIN"]
            if severe:
                edge["target_findings"] = sorted({f.category for f in severe})
                self.finding("M_EXEC_CHAIN", "HIGH", edge["source"], edge["key"],
                             "Expliziter Startverweis auf Datei mit Risikobefund: " + edge["target"] + "; keine vollständige Datenflussanalyse")
        # Preserve explicit multi-hop evidence without propagating unrelated words.
        adjacency = {}
        for edge in self.refs:
            if edge["kind"] == "launch" and edge["status"] == "text_observed":
                adjacency.setdefault(edge["source"], []).append(edge)
        chains = []
        for start in adjacency:
            pending = [(start, [], {start})]
            while pending:
                current, edges, visited = pending.pop()
                self.tick()
                for edge in adjacency.get(current, []):
                    if edge["target"] in visited:
                        self.gap(start, "$chain", "Zyklischer Startverweis; nicht rekursiv verfolgt")
                        continue
                    path = edges + [edge["id"]]
                    if edge.get("target_findings"):
                        chains.append({"source": start, "reference_ids": path,
                                       "target": edge["target"], "claim": "declared_launch_path_to_finding"})
                    if len(chains) + len(pending) > self.limit:
                        raise InputError("Verweiskettenbudget überschritten")
                    if len(path) < 8:
                        pending.append((edge["target"], path, visited | {edge["target"]}))
                    elif edge["target"] in adjacency:
                        self.gap(start, "$chain", "Kettentiefe auf acht Verweise begrenzt")
        self.report["chains"] = chains
        self.reader.progress(self.result)
