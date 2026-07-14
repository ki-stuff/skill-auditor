# 🛡️ Skill-Auditor

## 🇩🇪 Kurzbeschreibung

Ein Claude-Code-Skill, der *andere* Skills vor der Installation prüft. Man gibt ihm ein Skill-Verzeichnis (von GitHub, ClawdHub oder unbekannter Quelle), er führt einen automatischen Muster-Scan plus einen manuellen Prüf-Workflow durch — gegen Prompt Injection, Datenexfiltration, Rechteausweitung, Persistenz und Social Engineering. Ergebnis: eine strukturierte Erstbewertung (🟢/🟡/🔴), kein Ersatz für ein vollständiges Security-Review. Seit v2.2 zusätzlich ein Inventar-Modus: eine Übersicht über alle bereits installierten Skills, thematisch kategorisiert, mit Security-Status je Skill und als HTML-Dashboard. Details zu Funktionsumfang, Einschränkungen und Changelog: siehe unten.

---

A Claude Code / Claude coding-agent skill that vets *other* skills before you
install them. Point it at a skill directory (from GitHub, ClawdHub, or any
unknown source) and it runs a structured security review: an automated
pattern scan plus a manual review workflow covering prompt injection, data
exfiltration, privilege escalation, persistence, and social engineering.

Built for one problem: skills are prompt-driven, some ship scripts, and both
can be adversarial. This gives you a repeatable first pass before you ever
run one.

Since v2.2 it also has an **inventory mode**: instead of vetting one new
skill, it surveys everything you already have installed and gives you a
categorized, security-annotated dashboard of your whole skill set.

## What it checks

- **Network / exfiltration** — curl, wget, requests, fetch, and combinations
  that read a secret and send it somewhere
- **Code execution** — eval, exec, subprocess, child_process, `curl | bash`
- **Obfuscation** — base64, hex/unicode escapes, `String.fromCharCode`
- **Package installs / privilege escalation** — pip/npm/apt install, sudo,
  chmod 777, PATH tampering, cron/launch-agent persistence
- **Prompt injection & social engineering** — "ignore previous instructions",
  role reassignment, fake `<system-reminder>`/`<system>` tags, vetting-bypass
  language
- **Persistence & stealth** — crontab, shell rc-file edits, modifying
  `CLAUDE.md`/`settings.json`/`MEMORY.md`, self-update mechanisms
- **Secrets access** — `.ssh`, `.aws`, `.env`, API keys, passwords, private keys
- **Time bombs** — date/version-gated conditional logic that behaves
  differently on review day than later

Findings are split into `CRITICAL` / `HIGH` / `MEDIUM`, plus a `REJECT` tier
for pattern *combinations* (e.g. reading `.ssh` **and** piping it to curl in
the same file) that auto-fail regardless of individual pattern severity.
Patterns inside markdown code fences are skipped for most categories — a
regex shown as a documentation example isn't a live injection.

## Inventory mode

Beyond vetting a single new skill, the auditor can also survey your entire
installed skill set (manual installs under `~/.claude/skills/` plus active
marketplace plugins) and produce a dashboard:

1. `scripts/audit.py --inventory` collects every installed skill's name,
   description, and — if it exists — the status from a previous
   `audit-result.json` (🟢 safe / 🟡 caution / 🔴 reject / 🔵 marketplace
   plugin / ⚪ not yet audited). This step is deterministic, no LLM
   judgment involved.
2. The agent reads all descriptions and groups skills into a handful of
   thematic categories — this part isn't pattern matching, so the scanner
   deliberately leaves it to the agent.
3. If any skills are unaudited, it asks whether to run a fresh audit on
   them now, on a selection, or skip.
4. It asks where to save the result — never writes silently.
5. It writes a self-contained HTML dashboard: skills grouped by category,
   a status badge per skill, no dependency on any single user's branding.

## Setup

Copy `skill-auditor/` into your agent's skills directory, e.g.
`~/.claude/skills/skill-auditor/` (or `%USERPROFILE%\.claude\skills\skill-auditor\`
on Windows). No dependencies beyond Python 3.

## Usage

Ask your agent to audit a skill, or just try installing an unfamiliar one —
the skill is written to trigger proactively before any new/external skill
gets used. It resolves its own install location and runs the scanner from
there, e.g.:

```bash
python3 <wherever-you-installed-this-skill>/scripts/audit.py <skill-directory-to-check>
```

then follows up with the manual review phases in `SKILL.md` (provenance,
content review, permission scope) that a regex scan alone can't cover.

Batch mode: pass multiple directories to get a summary table across all of
them.

One extra output beyond the console report: **`audit-result.json`**, written
into the scanned directory — structured findings for scripting/CI use.

For a survey of everything you've already installed instead of a single
new skill, ask the agent for a skill inventory/overview, or run:

```bash
python3 <wherever-you-installed-this-skill>/scripts/audit.py --inventory --output <path>/skill-inventory-raw.json
```

## Structure

```
skill-auditor/
├── SKILL.md          # the agent workflow (7 phases + manual grep patterns)
├── README.md
├── CHANGELOG.md
└── scripts/
    ├── audit.py                 # automated pattern scanner + inventory scan
    └── inventory_template.html  # style reference for the inventory dashboard
```

## Limitations

This is a pragmatic first pass, not a full security audit. It catches known
patterns; it won't catch a genuinely novel obfuscation technique or a purely
prose-based social-engineering attempt with no matching keywords. Treat a
clean scan as "no obvious red flags," not "certified safe" — the manual
phases in `SKILL.md` (Phase 0 provenance, Phase 4 content review) exist
because the regex scan alone isn't enough.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT.
