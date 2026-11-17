"""Unveränderte Muster und Grenzen des Scanners 1.0.3."""
PATTERNS = {
    "A_NETWORK": {
        "risk": "HIGH",
        "label": "Netzwerk / Datenexfiltration",
        "patterns": [
            (r"\bcurl\b",                         "curl-Aufruf"),
            (r"\bwget\b",                         "wget-Aufruf"),
            (r"requests\.(get|post|put|delete)",  "Python requests"),
            (r"\burllib\b",                       "urllib"),
            (r"fetch\(",                          "JS fetch()"),
            (r"\baxios\b",                        "axios"),
            (r"XMLHttpRequest",                   "XHR"),
        ],
        # Beide Seiten der Kombi-Regex nutzen dieselben Wortgrenzen wie die
        # "patterns"-Liste oben (\bcurl\b, requests\.(get|post|...), etc.) statt
        # loser Bare-Words - sonst matcht z. B. "unformed requests only" als
        # Netzwerkaufruf. "token"/"secret" bleiben bewusst ohne \b, weil sie so
        # auch UNTERSTRICH-geschriebene Env-Var-Namen wie SECRET_TOKEN treffen
        # (\b wuerde davor keine Wortgrenze finden, da "_" ein Wortzeichen ist);
        # Bindestrich-Komposita wie "brand-token" bleiben ein bekanntes Restrisiko
        # fuer False Positives - das faengt Phase 4 (manuelle Pruefung) ab, nicht
        # der Scanner (siehe SKILL.md "Wann NICHT aktivieren"-Philosophie: lieber
        # ein Feature/Praezision weglassen als ein irrefuehrendes Signal geben).
        "reject_if": [
            r"(~/.ssh|~/.aws|\.env\b|\bapi[_-]?key\b|\bpassword\b|token|secret).*?"
            r"(\bcurl\b|fetch\(|requests\.(get|post|put|delete)|\burllib\b|\bwget\b)",
            r"(\bcurl\b|fetch\(|requests\.(get|post|put|delete)|\burllib\b|\bwget\b).*?"
            r"(~/.ssh|~/.aws|\.env\b|\bapi[_-]?key\b|\bpassword\b|token|secret)",
            r"base64\.(encode|b64encode).*?(\bsend\b|\bpost\b|\bupload\b|\bcurl\b|fetch\()",
            r"\b(whoami|hostname)\b.*?(\bcurl\b|fetch\(|\bpost\b|\bsend\b)",
        ],
    },
    "B_ENCODING": {
        "risk": "HIGH",
        "label": "Obfuskierung / Encoding",
        "patterns": [
            (r"\bbase64\b",                       "base64"),
            (r"\batob\(",                         "atob()"),
            (r"String\.fromCharCode",             "fromCharCode"),
            (r"\\x[0-9a-fA-F]{2}",               "Hex-Escape"),
            (r"\\u[0-9a-fA-F]{4}",               "Unicode-Escape"),
            (r"\beval\s*\(",                       "eval()"),
        ],
        "reject_if": [],
    },
    "C_EXEC": {
        "risk": "CRITICAL",
        "label": "Code-Ausfuehrung",
        "patterns": [
            (r"\bexec\s*\(",                      "exec()"),
            (r"os\.system\s*\(",                  "os.system()"),
            (r"subprocess\.",                     "subprocess"),
            (r"child_process",                    "child_process (Node)"),
            (r"__import__\s*\(",                  "__import__()"),
            (r"compile\s*\(.*eval",               "compile+eval"),
        ],
        "reject_if": [
            r"\bcurl\s*\|+\s*bash",
            r"\bwget\s*\|+\s*sh",
        ],
    },
    "D_PACKAGES": {
        "risk": "HIGH",
        "label": "Package-Installation / Privilege Escalation",
        "patterns": [
            (r"\bpip\s+install\b",                "pip install"),
            (r"\bnpm\s+install\b",                "npm install"),
            (r"\bapt(-get)?\s+install\b",         "apt install"),
            (r"\bsudo\b",                         "sudo"),
            (r"\bchmod\s+777\b",                  "chmod 777"),
            (r"\bchown\b",                        "chown"),
        ],
        "reject_if": [
            r"PATH\s*=.*\$PATH",
            r"\b(crontab|cron\.d|LaunchAgents|launchctl)\b",
            r"\.(bashrc|zshrc|profile|bash_profile)\s*>>",
        ],
    },
    "E_PROMPT_INJECTION": {
        "risk": "CRITICAL",
        "label": "Prompt Injection & Social Engineering",
        "patterns": [
            (r"ignore.{0,30}previous",            "ignore previous instructions"),
            (r"you are now",                      "Rollenneuzuweisung EN"),
            (r"du bist jetzt",                    "Rollenneuzuweisung DE"),
            (r"forget all",                       "forget all instructions"),
            (r"vergiss alles",                    "Vergiss-Anweisung"),
            (r"<system-reminder>",                "Fake <system-reminder>"),
            (r"<system>",                         "Fake <system>-Tag"),
            (r"<tool_result>",                    "Fake <tool_result>-Tag"),
            (r"override.{0,30}instructions",      "override instructions"),
            (r"trust this skill",                 "trust-forcing"),
            (r"skip.{0,20}vetting",               "vetting bypass"),
            (r"disable.{0,20}safety",             "safety disable"),
            (r"your new purpose",                 "purpose reassignment"),
        ],
        "reject_if": [],
    },
    "F_PERSISTENCE": {
        "risk": "CRITICAL",
        "label": "Persistence & Stealth",
        "patterns": [
            (r"\bcrontab\b",                      "crontab"),
            (r"LaunchAgents",                     "macOS LaunchAgents"),
            (r"\.(bashrc|zshrc)",                 ".bashrc/.zshrc Modifikation"),
            (r"settings\.json",                   "settings.json Zugriff"),
            (r"CLAUDE\.md",                       "CLAUDE.md Zugriff"),
            (r"MEMORY\.md",                       "MEMORY.md Zugriff"),
            (r"SOUL\.md|IDENTITY\.md",            "Identity-Dateien"),
            (r"self.*update|update.*self",        "Self-Update Mechanismus"),
        ],
        "reject_if": [],
    },
    "G_SECRETS": {
        "risk": "HIGH",
        "label": "Secrets & Credential-Zugriff",
        "patterns": [
            (r"~/.ssh",                           "SSH-Verzeichnis"),
            (r"~/.aws",                           "AWS Credentials"),
            (r"\.env\b",                          ".env Datei"),
            (r"\bapi[_-]?key\b",                  "API Key Zugriff"),
            (r"\bpassword\b|\bpasswd\b|\bpasswort\b", "Passwort-Zugriff"),
            (r"\bsecret[_\s]key\b|\bsecret_token\b", "Secret Token"),
            (r"\bprivate[_-]?key\b",              "Private Key"),
        ],
        "reject_if": [],
    },
    "H_TIMEBOMB": {
        "risk": "MEDIUM",
        "label": "Time Bombs / Bedingte Logik",
        "patterns": [
            (r"datetime\.now\(\)|Date\.now\(\)|time\.time\(\)", "Zeitabfrage"),
            (r"if.{0,50}date.{0,30}>",           "Datums-Bedingung"),
            (r"if.{0,50}version.{0,30}[><=]",   "Versions-Bedingung"),
        ],
        "reject_if": [],
    },
    "I_CODEX_CONTROL": {
        "risk": "HIGH",
        "label": "Codex-Konfiguration / Steuerung",
        "patterns": [
            (
                r"(write|modify|edit|append|create|install|register|enable|disable|"
                r"schreib\w*|aender\w*|änder\w*|erstell\w*|installier\w*|aktivier\w*|deaktivier\w*)"
                r".{0,60}(AGENTS\.md|\.codex[/\\\\]config\.toml|\.codex-plugin[/\\\\]plugin\.json|hooks?)",
                "Will Codex-Steuerdatei oder Hook verändern",
            ),
            (
                r"(AGENTS\.md|\.codex[/\\\\]config\.toml|\.codex-plugin[/\\\\]plugin\.json|hooks?)"
                r".{0,60}(write|modify|edit|append|create|install|register|enable|disable|"
                r"schreib\w*|aender\w*|änder\w*|erstell\w*|installier\w*|aktivier\w*|deaktivier\w*)",
                "Codex-Steuerdatei oder Hook mit Änderungsanweisung",
            ),
            (r"\bmcp_servers?\b", "MCP-Konfiguration"),
        ],
        "reject_if": [],
    },
    "L_EXTERNAL_CONTENT": {
        "risk": "MEDIUM",
        "label": "Externe Fremdinhalte / indirekte Prompt Injection",
        "patterns": [
            (
                r"\b(x-api|twitter[ -]?api|social[ -]?media[ -]?api)\b",
                "Externe Social-Media-Schnittstelle oder Live-Quelle",
            ),
            (
                r"\b(pull|fetch|retrieve|collect|gather|scrape|abruf\w*|lad\w*|sammel\w*)\b"
                r".{0,100}\b(posts?|threads?|site copy|website content|user-generated|"
                r"public(?:ly)? available (?:text|content|sources?)|fremdinhalte?)\b",
                "Externe oder nutzergenerierte Inhalte sollen eingelesen werden",
            ),
        ],
        "reject_if": [],
    },
}

READABLE_EXTENSIONS = {
    ".md", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".json", ".yaml", ".yml", ".toml", ".html", ".css", ".xml", ".ini",
    ".cfg", ".rb", ".php", ".pl",
}
READABLE_FILENAMES = {".gitignore", "LICENSE", "Makefile", "Dockerfile"}
MAX_SCAN_FILE_BYTES = 2_000_000

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CONTEXT": 4}
RISK_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "CONTEXT": "⚪"
}

