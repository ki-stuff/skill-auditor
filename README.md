# 🛡️ Skill-Auditor

## 🇩🇪 Kurzbeschreibung

**Skills sind Prompts. Manche bringen Scripts mit. Beides kann feindlich
sein — und beim Kopieren nach `~/.claude/skills/` prüft das niemand.**

Der Skill-Auditor schließt genau diese Lücke: Er prüft *andere* Skills,
bevor du sie installierst. Übergib ihm ein Skill-Verzeichnis — von GitHub,
ClawdHub, skills.sh oder aus unbekannter Quelle — und er führt einen
automatischen Muster-Scan plus einen manuellen Prüf-Workflow durch: gegen
Prompt Injection, Datenexfiltration, Rechteausweitung, Persistenz und
Social Engineering. Ergebnis ist eine strukturierte Erstbewertung
(🟢 / 🟡 / 🔴), kein Ersatz für ein vollständiges Security-Review.

Seit v2.2 zusätzlich ein **Inventar-Modus** — der eigentliche Unterschied
zu vergleichbaren Scannern: eine Übersicht über *alle* bereits installierten
Skills, thematisch kategorisiert, mit Security-Status je Skill und als
HTML-Dashboard.

> **Nicht verwechseln** mit `getsentry/skills` → `security-review` (prüft
> eigenen Anwendungscode, nicht fremde Skills). Das Pendant dort heißt
> `skill-scanner`. Details zur Abgrenzung: siehe
> [How this compares](#how-this-compares-to-similar-tools).

---

A Claude Code / Claude coding-agent skill that vets *other* skills before you
install them. Point it at a skill directory (from GitHub, ClawdHub, or any
unknown source) and it runs a structured security review: an automated
pattern scan plus a manual review workflow covering prompt injection, data
exfiltration, privilege escalation, persistence, and social engineering.

Built for one problem: skills are prompt-driven, some ship scripts, and both
can be adversarial. This gives you a repeatable first pass before you ever
run one.

Since v2.2 it also has an **inventory mode** — the main thing that sets it
apart from comparable scanners: instead of vetting one new skill, it surveys
everything you already have installed and gives you a categorized,
security-annotated dashboard of your whole skill set.

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

## Example output

Running the scanner against a directory produces a console report and a
machine-readable `audit-result.json`:

```
$ python3 ~/.claude/skills/skill-auditor/scripts/audit.py ./awesome-seo-skill

── Pattern scan ─────────────────────────────
CRITICAL  scripts/setup.sh:14   secrets-access   ~/.ssh/id_rsa
CRITICAL  scripts/setup.sh:15   exfiltration     curl -X POST …
HIGH      scripts/setup.sh:3    code-execution   curl | bash
MEDIUM    SKILL.md:88           obfuscation      base64 -d

REJECT    Combination in setup.sh: secrets-access + exfiltration

── Verdict ──────────────────────────────────
🔴 Do not install. 2 critical · 1 high · 1 medium · 1 reject combination
→ audit-result.json written
→ Manual phases still open: provenance, content review, permission scope
```

The 🔴 verdict here is driven by the REJECT combination, not just the
individual findings — reading a private key and piping it to curl in the
same file auto-fails regardless of how each line would score alone.

## The review workflow

The scan is the fast, deterministic part. The phases around it are what a
regex can't cover, and they're where most real judgment happens:

- **Phase 0 — Provenance.** Where the skill comes from, who published it,
  repo age, adoption. Optionally cross-check skills.sh trust badges (Socket /
  Snyk / Gen Agent Trust Hub) as a *second* signal, never a verdict.
- **Phase 1 — Inventory the files.** What's actually in the directory,
  which files carry logic, which ship executable scripts.
- **Phase 2 — Automated pattern scan.** `audit.py` over the whole tree,
  eight categories, console report + `audit-result.json`.
- **Phase 3 — Severity triage.** CRITICAL / HIGH / MEDIUM / REJECT, read in
  context rather than taken at face value.
- **Phase 4 — Content review.** Read the prompt text itself. Social
  engineering has no greppable keywords — only phrasing that tells the agent
  something different than it tells you.
- **Phase 5 — Permission scope.** Does the skill actually need what it
  touches? A text formatter with network access isn't a finding, but it's a
  question.
- **Phase 6 — Verdict.** 🟢 / 🟡 / 🔴 with locations, as a decision basis —
  the decision stays with you.
- **Phase 7 — Inventory mode.** Survey everything already installed (below).

## How this compares to similar tools

Skill-vetting tools are easy to mix up. Two clarifications:

- **This is not `getsentry/skills` → `security-review`.** That skill reviews
  *your own application code* for OWASP-style vulnerabilities (SQLi, XSS,
  auth bugs) — it doesn't look at third-party agent skills at all. The skill
  in that same repo that does what this tool does is `skill-scanner`
  (`npx skills add getsentry/skills --skill skill-scanner`): automated
  pattern scan plus LLM intent review, functionally close to Phase 2–4 here.
- **skills.sh badges are a signal, not a verdict.** skills.sh shows
  Socket / Snyk / Gen Agent Trust Hub badges per skill page. Useful as a
  second opinion (see Phase 0 in `SKILL.md`), but the underlying scanners
  have documented false positives — e.g. Snyk flagging a URL-detection regex
  as if it were a live network call — and have been shown to miss
  deliberately obfuscated payloads. Treat a green badge as one data point,
  not proof; a red one is worth cross-checking against this tool's own
  codefence filter before you act on it.

What technically sets this tool apart from comparable pattern scanners
(including `skill-scanner`):

- **`REJECT` combination logic** — certain pattern *pairs* (e.g. reading
  `~/.ssh` **and** piping it to curl in the same file) auto-fail regardless
  of each pattern's individual severity, catching intent that a
  single-pattern scanner misses.
- **Codefence masking** — patterns inside markdown code fences are excluded
  from most categories, so a regex shown as a documentation example doesn't
  get flagged as live code. This is the same class of false positive that
  trips up the skills.sh Snyk badge.
- **Inventory mode** (below) — a dashboard of your entire installed skill
  set, not just a one-off check before installing something new. Neither the
  common blog-post workflow nor `skill-scanner` has this.

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
