# 🛡️ Skill-Auditor

## 🇩🇪 Kurzbeschreibung

**Skills sind Prompts. Manche bringen Scripts mit. Beides kann feindlich
sein, und beim Kopieren nach `~/.claude/skills/` prüft das niemand.**

Der Skill-Auditor prüft *andere* Skills, bevor du sie installierst: Skill-Ordner,
einzelne Dateien, ZIP-Archive, Agent-Plugins, npm-/Python-Pakete und
MCP-Konfigurationen. Er liest statisch, führt nichts aus und meldet Prompt
Injection, Datenabfluss, Rechteausweitung, Persistenz und Social Engineering.
Ergebnis ist eine Ampel (🟢 / 🟡 / 🔴 / ⚪ nicht ausreichend geprüft) mit
konkretem nächsten Schritt, kein Ersatz für ein vollständiges Security-Review.

Eine Fassung für **Claude Code, Claude Desktop, claude.ai und Cowork**. Im
Terminal bzw. Code-Tab gibt es zusätzlich einen **Inventar-Modus**: eine
Übersicht über *alle* installierten Skills mit Prüfstatus je Skill, auf Wunsch
als HTML-Dashboard.

> **Neu in v2.7:** eine Fassung für alle Claude-Oberflächen (löst
> `skill-auditor-desktop` ab). Vor dem Start prüft der Auditor Paket, Python und
> erreichbare Skill-Ordner und bietet nur an, was dort funktioniert. Fester
> Startdialog („Was möchtest du tun?“) und nach jedem Ergebnis „Wie geht es
> weiter?“ mit Hilfe, jetzt auch bei Rot. Details im [CHANGELOG](CHANGELOG.md).
>
> **Installation:** das ZIP **unverändert** hochladen bzw. den kompletten Ordner
> kopieren, nie nur die `SKILL.md`. Siehe [Setup](#setup).
>
> **Schon eine ältere Version installiert?** Bitte zuerst
> [Upgrading from an earlier version](#upgrading-from-an-earlier-version) lesen.
> Ältere Fassungen hatten Erkennungslücken: Bis v2.5 konnte Schadcode in
> Code-Blöcken der `SKILL.md` ein grünes Ergebnis ergeben. Ein Update wird
> empfohlen.
>
> **Fehler, Fehlalarme, Fragen:** bitte als
> [GitHub-Issue](https://github.com/ki-stuff/skill-auditor/issues) melden. Das
> Projekt wird freiwillig gepflegt; Antwort oder Behebung sind nicht zugesagt.

> **Nicht verwechseln** mit `getsentry/skills` → `security-review` (prüft
> eigenen Anwendungscode, nicht fremde Skills). Das Pendant dort heißt
> `skill-scanner`. Siehe [How this compares](#how-this-compares-to-similar-tools).

> Für Codex gibt es [codex-skill-auditor](https://github.com/ki-stuff/codex-skill-auditor).

---

A Claude skill for Claude Code, Claude Desktop, claude.ai and Cowork that vets *other* skills before you install them. Point it
at a skill directory, a single file, an archive (ZIP/MCPB/DXT/Wheel/TAR), an
agent plugin, an npm/Python package or an MCP configuration. It runs a static
review, never executes the target, and combines an automated pattern scan with
a manual review workflow covering prompt injection, data exfiltration,
privilege escalation, persistence and social engineering.

In Claude Code it also has an **inventory mode**: instead of vetting one new
skill, it surveys everything you already have installed and gives you a
security-annotated dashboard of your whole skill set.

Every session starts the same way: the auditor checks its own package, the
Python version and which skill folders are reachable, then asks one question
(*check a skill / inventory / help with a result / what can it do*) and only
offers what works in your environment. Every result ends with "Wie geht es
weiter?" (what next?) and an offer to help you assess the findings.

## What it checks

- **Network / exfiltration**: curl, wget, requests, fetch, and combinations
  that read a secret and send it somewhere
- **Code execution**: eval, exec, subprocess, child_process, `curl | bash`
- **Obfuscation**: base64, hex/unicode escapes, `String.fromCharCode`
- **Package installs / privilege escalation**: pip/npm/apt install, sudo,
  chmod 777, PATH tampering, cron/launch-agent persistence
- **Prompt injection & social engineering**: "ignore previous instructions",
  role reassignment, fake `<system-reminder>`/`<system>` tags, vetting-bypass
  language
- **Persistence & stealth**: crontab, shell rc-file edits, modifying
  `CLAUDE.md`/`settings.json`/`MEMORY.md`, self-update mechanisms
- **Secrets access**: `.ssh`, `.aws`, `.env`, API keys, passwords, private keys
- **Time bombs**: date/version-gated conditional logic
- **Package and plugin metadata**: install scripts, declared MCP servers,
  start commands and references to files that are missing

Findings are rated `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, plus a `REJECT` tier
for dangerous pattern *combinations* (e.g. reading `~/.ssh` **and** sending it
with curl within a few lines) that auto-fail regardless of individual severity.

Context handling is deliberately conservative: a warning word such as "never"
or "do not" in the lines before a dangerous instruction does **not** clear it,
because attackers can add such words trivially. Hits next to warning words or
inside code blocks of `SKILL.md` (which the agent reads as instructions) are
lowered to yellow at most, never to green. Code blocks in README or reference
docs are treated as documentation context, unless they contain a dangerous
combination and another file of the skill points to them ("follow the setup in
README.md"); then they are yellow too.

## Result: four colours, kept separate

| Colour | Meaning |
|---|---|
| 🟢 | No obvious findings in the checked text scope. Not a certificate. |
| 🟡 | Something needs clarification before use. |
| 🔴 | Do not use until the finding is resolved. |
| ⚪ | Not sufficiently checked (missing files, unsupported format, limits). |

Risk, coverage (what was actually read) and freshness are reported separately,
so a partial scan never turns into a green light. Yellow, grey and red results
come with concrete next steps and their own copyable help prompt for your AI
assistant. For red, the prompt asks to read each finding in the original and
sort it into documentation text, purpose-bound tool behaviour or real risk; the
red result itself always stays.
Detected secrets are masked in reports and raw evidence lines are withheld.

## The review workflow

The scan is the fast, deterministic part. The phases around it are what a
regex can't cover:

- **Provenance**: where the skill comes from, who published it. skills.sh trust
  badges (Socket / Snyk / Gen Agent Trust Hub) are a second signal, never a verdict.
- **Automated static scan**: `scripts/audit.py` over the whole input, archives
  read directly with size, time and memory limits, nothing extracted or run.
- **Triage in context**: read each yellow/red hit at its location.
- **Content review**: social engineering has no greppable keywords, only
  phrasing that tells the agent something different than it tells you.
- **Permission scope**: does the skill actually need what it touches?
- **Verdict**: colour, coverage and next step, as a decision basis. The
  decision stays with you.

## How this compares to similar tools

- **This is not `getsentry/skills` → `security-review`.** That skill reviews
  *your own application code* for OWASP-style vulnerabilities. The skill in
  that repo that does what this tool does is `skill-scanner`.
- **skills.sh badges are a second signal, not a verdict.**

Key properties of this tool:

- **`REJECT` combination logic**: combinations of patterns that together
  indicate harmful intent are reported as red.
- **Conservative context handling**: documentation examples in README/references
  don't produce false alarms, but warning words never hide a payload.
- **Separate coverage**: unreadable or unsupported parts are reported as grey
  instead of silently passing.
- **Inventory mode**: a dashboard of your entire installed skill set.

## Inventory mode

Only in Claude Code (terminal or Code tab). In Claude Desktop chat, claude.ai
and Cowork your local skill folders are not reachable, so the auditor does not
offer it there.

Ask your agent for a skill inventory/overview. It scans once, groups your skills
into topics that fit your collection, writes a one-line German summary per skill
and renders a dashboard of tiles grouped by topic, with a traffic light per skill
and a filter by result. Topics never change a result. Manually:

```bash
python -I -B <this-skill>/scripts/audit.py --inventory --output <dir>/inventar.json
# write <dir>/kategorien.json: {"skill-name": {"category": "Topic", "summary": "One sentence."}}
python -I -B <this-skill>/scripts/audit.py --render-inventory <dir>/inventar.json --categories <dir>/kategorien.json --inventory-html <dir>/skill-inventar.html
```

It covers personal and project skills plus plugin skills registered in
`installed_plugins.json`. Registration is not a trust signal; marketplace
plugins are scanned like everything else. A previous `audit-result.json`
written by versions up to 2.5 is recognised by its exact format, listed as an
exclusion and read only as unconfirmed history. Output is written only to a new
file outside the scanned folders.

## Setup

Requires **Python 3.11 or newer** in the environment where the skill runs,
standard library only.

**Claude Desktop and claude.ai:** enable code execution / file creation in the
settings, then upload the release ZIP `skill-auditor-<version>.zip`
**unchanged** under *Customize → Skills → Upload a skill*. An uploaded skill
belongs to your account; in our test on 2026-11-08 it was available in Desktop
chat, Cowork and the Claude Code tab of the desktop app.

**Claude Code without the desktop app:** unzip and copy the complete
`skill-auditor/` folder into `~/.claude/skills/skill-auditor/`
(`%USERPROFILE%\.claude\skills\skill-auditor\` on Windows), then start a new
session.

Always install the **complete package**, never just `SKILL.md`: without
`scripts/` and `references/` the auditor cannot scan and reports "Installation
unvollständig". When you replace an older version, the new `SKILL.md` can be
much shorter (2.5 → 2.6: about 230 → 30 lines); that is expected, the
procedure lives in `references/`. Keep only **one** auditor per account or
skills folder.

## Which model?

The traffic light comes from the Python scanner and does not depend on the
model. The model decides how well results are explained, how topics for the
inventory are chosen and how findings are assessed. Recommendation (as of
November 2026): a current mid-size model for single checks; for the inventory
and for assessing red findings the strongest available model with extended
thinking (at the time of writing Claude Sonnet 5.5 or Opus 5.5). A smaller
model never changes a result, it only explains less precisely.

## Upgrading from an earlier version

There is no automatic update.

**From `skill-auditor-desktop` 1.x:** this package replaces it. Remove
`skill-auditor-desktop` under *Customize → Skills*, then upload this ZIP, so
only one auditor responds.

**From 2.6:** replace the skill (upload the new ZIP or swap the folder), nothing
else changes.

**From 2.5 or older:** these versions had a detection gap: harmful
instructions inside code blocks of a `SKILL.md` could produce a green result.
Updating is recommended.

1. **Check Python.** Run `python --version`. Version 2.6 needs **Python 3.11 or
   newer**; older versions ran with any Python 3. With an older Python the
   auditor only reports "Python ab 3.11 erforderlich" and does not scan.
2. **Replace the folder, don't copy over it.** Back up
   `~/.claude/skills/skill-auditor/` outside the skills directory, delete it,
   then copy in the new `skill-auditor` folder. Version 2.5 used a lowercase
   `skill.md` and kept `audit-result.json` and `skill-inventory-cache.json` in
   that folder; copying over it would leave them behind (on macOS/Linux you
   would end up with both `skill.md` and `SKILL.md`). Start a new Claude Code
   session afterwards.
3. **Old reports in your other skills.** Versions up to 2.5 wrote an
   `audit-result.json` into every skill they checked. Version 2.6 recognises
   these files by their exact format and no longer counts them as skill
   content. If such an old file reported red, the inventory still shows that
   skill as a red *warning from an earlier report (unconfirmed)*, even when the
   current scan finds less. Some of these old verdicts came from scanner bugs
   fixed in 2.4. Check the findings, then delete the old `audit-result.json`
   from that skill's folder. The auditor never modifies checked skills, so it
   does not clean these files up itself.
4. **No more automatic report files.** 2.6 only writes a report when you ask
   for one (`--output`, `--html`, `--inventory-html`) and never into the
   checked folder. If a script of yours read `audit-result.json`, add
   `--output <file>.json`.

Installed via `git clone`? Run `git pull` in the clone, then delete the
leftover `audit-result.json` and `skill-inventory-cache.json` in the auditor
folder (they are not tracked by git).

## Usage

Ask your agent to audit a skill, upload one in a chat, or just try installing an
unfamiliar one: the skill triggers proactively. It resolves its own install
location, checks the environment and runs:

```bash
python -I -B <this-skill>/scripts/audit.py --capabilities --surface <cli|desktop-chat|web|cowork>
python -I -B <this-skill>/scripts/audit.py <path-to-check> [<more-paths> ...] --surface <surface>
```

In Cowork the device scanner is deferred for now; `--surface cowork` only
produces a "not executed" report and the auditor assesses visible text with that
limitation stated.

Useful options: `--json` (machine-readable output on stdout), `--html <new-file>`
and `--output <new-file>.json` (save a report), `--inventory`,
`--skills-root` / `--plugins-root` (limit the inventory), `--capabilities`
(package, Python and reachable skill folders, plus the start options offered).
Exit code 1 means a red result, 2 means an error or
no scan; exit code 0 is not a security approval.

## Structure

```
skill-auditor/
├── SKILL.md                      # agent workflow
├── README.md, CHANGELOG.md, LICENSE
├── BUNDLE.json                   # file hashes of this package
├── references/                   # review procedure, help for yellow/grey/red, Cowork guide
└── scripts/
    ├── audit.py                  # entry point
    ├── inventory_template.html   # passive dashboard template
    └── auditor_core/             # shared static scanner core
```

## Limitations

This is a pragmatic first pass, not a full security audit. It catches known
patterns; it won't catch a genuinely novel obfuscation technique or a purely
prose-based social-engineering attempt with no matching keywords. A warning
word placed directly in the same line as a payload lowers it to yellow, not
red. Treat a clean scan as "no obvious red flags", not "certified safe".

## Reporting issues

Bugs, false alarms and questions: please open a
[GitHub issue](https://github.com/ki-stuff/skill-auditor/issues). This project
is maintained voluntarily; no response or fix is promised.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT.
