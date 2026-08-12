# Changelog: skill-auditor

## v2.4 — 2026-08-12 — Scanner-Bugfix: Wortgrenzen in REJECT-Mustern

Beim ersten vollen Inventar-Lauf (Phase 7, 180 Skills) fielen 5 False-Positive-🔴-REJECT-Verdikte auf (komplette hyperframes-Familie + media-use). Ursache in `scripts/audit.py`:

- `eval\s*\(` ohne führende `\b` matchte `retrieval (` — "eval" als Substring in "retrieval", nicht als eigenständiger Aufruf.
- Die REJECT-Kombinationsmuster in Kategorie A_NETWORK nutzten lose Bare-Words (`curl|fetch|requests|urllib|wget`, `token|secret|...`) statt der bereits korrekt skalierten Patterns aus der eigenen `patterns`-Liste — dadurch wertete der Scanner z. B. "unformed requests only" (Fließtext) als Netzwerkaufruf.
- `whoami|hostname.*?(curl|fetch|post|send)` hatte einen Gruppierungsfehler ohne Klammern — das bloße Wort `whoami` allein löste bereits ein REJECT aus, unabhängig vom Rest der Zeile.
- `collect_files()` sammelte auch die eigenen Output-Artefakte (`audit-result.json`, `skill-inventory-*.json`) als Scan-Input ein — ein wiederholter Lauf vergiftete sich dadurch mit den eigenen vorherigen Findings-Snippets.

Fix: `\b`-Wortgrenzen an den betroffenen Stellen ergänzt (`eval`, curl/wget/urllib/requests/fetch in der Kombi-Logik, crontab/LaunchAgents, api_key/password/private_key), Gruppierungsfehler bei whoami/hostname behoben, eigene Artefaktdateien von `collect_files()` ausgeschlossen. `token`/`secret` bleiben bewusst ohne `\b` (sonst keine Erkennung von Unterstrich-Env-Var-Namen wie `SECRET_TOKEN` mehr) — Bindestrich-Komposita wie `brand-token` (Design-Token-Terminologie) bleiben ein bekanntes, akzeptiertes Restrisiko für Phase 4 (manuelle Prüfung), kein Scanner-fixbares Problem.

Verifiziert gegen die 5 ursprünglich betroffenen Skills (3 vollständig behoben, 2 weiterhin korrekt als 🟡/🔴 markiert — aus anderen, legitimen Gründen: Design-Token-Terminologie bzw. Dateinamens-Kollision mit `MEMORY.md`) sowie gegen vier synthetische Angriffsmuster (unverändert erkannt).

## v2.3 — 2026-08-12 — skills.sh-Abgleich

Abgleich gegen den aktuellen Stand von skills.sh (Vercel) und getsentry/skills; Ergebnis in drei Änderungen.

- **`SKILL.md`**: `description` präzisiert — "skill" jetzt explizit als "Claude Code / coding-agent skill (SKILL.md-based package)" gefasst (grenzt gegen generischen Sprachgebrauch und den `code-review`-Skill ab), skills.sh und `npx skills add` als bekannte Quellen ergänzt.
- **`SKILL.md`**: Phase 0 um optionalen skills.sh-Badge-Check erweitert (Socket/Snyk/Gen Agent Trust Hub als Zusatzsignal, ausdrücklich keine alleinige Entscheidungsgrundlage — bekannte False-Positive-Muster bei Snyk, Scanner laut Trail-of-Bits-Research schon umgangen). Bei Snyk-Fail: erst eigenen Codefence-Filter gegenprüfen. Neues Report-Feld "Zusatzsignal skills.sh" in Phase 6.
- **`README.md`**: neuer Abschnitt "How this compares to similar tools" — Abgrenzung zu `getsentry/skills` → `security-review` (häufige Verwechslung; das eigentliche Pendant dort heißt `skill-scanner`), REJECT-Kombinationslogik und Codefence-Masking als technische Differenzierung gegenüber reinen Pattern-Matchern, Inventar-Modus als Hauptunterschied stärker herausgestellt.

## v2.2 — 2026-07-13 — Inventar-Modus

Neue Funktion: Überblick über alle installierten Skills mit Security-Status, thematischer Kategorisierung und HTML-Dashboard.

- **`SKILL.md`**: Neue Phase 7 "Inventar-Modus". Scannt installierte Skills, fragt bei ungeprüften Skills aktiv nach (Audit nachholen ja/nein), fragt aktiv nach dem Speicherort — nie stillschweigend schreiben.
- **`scripts/audit.py`**: Neuer CLI-Modus `--inventory [--output <pfad>]`. Sammelt manuell installierte Skills (`~/.claude/skills/`) und aktive Marketplace-Plugins (über `~/.claude/plugins/installed_plugins.json`), liest Name/Description aus dem Frontmatter und den Status aus vorhandenen `audit-result.json`-Dateien. Liefert nur Rohdaten als JSON — die thematische Kategorisierung übernimmt Claude beim Ausführen, da das semantisches Verständnis der Beschreibungen erfordert, kein Pattern-Matching.
- **`write_json_report()`**: Feld `audited_at` (Zeitstempel) ergänzt, fehlte bisher.
- **`scripts/inventory_template.html`** (neu): Stil-Referenz für das HTML-Dashboard (dunkles/helles Karten-Layout, nach Kategorie gruppiert, Status-Badges, Footer-Link zum Repo). Wird nicht automatisch befüllt, sondern von Claude als Vorlage für den echten Output verwendet.
- Bugfix in `scan_file()`: Exception-Handler beim Dateilesen gab `findings, urls` zurück (`urls` war eine nicht mehr existierende Variable aus einer älteren Version) — hätte bei nicht lesbaren Dateien zum Absturz geführt. Jetzt korrekt `findings`.
- Bugfix in `parse_frontmatter()`: YAML-Block-Scalars (`description: |` mit eingerückten Folgezeilen, z. B. bei mehreren offiziellen Plugin-Skills) wurden bisher nicht erkannt und lieferten eine leere Description.

## v2.1 — 2026-07-07 — Merge & Community-Release

Zwei parallel existierende Kopien (eine ältere v1.0-Version, eine aktuellere v2.0-Version) wurden zu einer einzigen Quelle zusammengeführt und als eigenständiges Repo veröffentlicht.

- **`scripts/audit.py`**: JSON-Report-Export (`audit-result.json` je geprüftem Verzeichnis) aus der alten v1.0-Version zurückgeholt, an die v2.0-Datenstruktur angepasst.
- **`SKILL.md`**: Pfad zum Audit-Script wird jetzt relativ zum eigenen Skill-Ordner abgeleitet statt fest verdrahtet (der alte hartkodierte Pfad war Setup-spezifisch und ist auf anderen Systemen falsch).
- Bewusst NICHT übernommen aus v1.0: Sammlung externer URLs mit Safe-List für "bekannte" Domains (GitHub, CDNs etc.). Eine Domain-Allowlist bei einem Security-Tool suggeriert Sicherheit, ohne über den tatsächlichen Inhalt etwas auszusagen — gerade GitHub/raw.githubusercontent.com sind ein gängiger Hosting-Ort für bösartigen Code. Die Liste würde außerdem laufend altern (Repos/Domains ändern sich). v2.0 hatte dieses Feature schon nicht mehr, das war offenbar eine bewusste Entscheidung.
- Alte Duplikate entfernt: `projects/security skill/` (v1.0), Root-Ordner `security skill/`, `skill-auditor.zip`, `skill_old.md`. Ab jetzt gibt es nur noch diese eine Quelle.
- Veröffentlicht unter github.com/ki-stuff/skill-auditor.

## v2.0 — 2026-04-23

### audit.py — Vollständige Neuentwicklung
- Strukturierter Pattern-Scanner mit 8 Risiko-Kategorien (A–H)
- `REJECT`-Logik: kombinierte Muster die automatisch zur Ablehnung führen
- Code-Fence-Masking: Patterns in Markdown-Codeblöcken werden nicht als Befund gewertet
- Datenklassen `Finding` und `SkillAuditResult` für saubere Ausgabe
- Batch-Modus: mehrere Skills in einem Aufruf prüfen mit Zusammenfassung
- Neue Kategorie H: Time Bombs / bedingte Logik (Datumsabfragen, Versions-Guards)
- Windows-kompatibles UTF-8-Output

### skill.md — Erweiterte Audit-Phasen
- Phase 0 (Provenienz) neu: Quelle und Trust-Stufen vor dem Dateilesen prüfen
- Phase 1–6 statt bisher 5 Schritte
- Detaillierte REJECT-Kriterien je Kategorie
- Häufige Angriffsmuster als Referenztabelle (Trojan Skill, Config Poisoning, Time Bomb etc.)
- Batch-Modus dokumentiert

---

## v1.0 — 2026-03-23

- Initiale Version: `SKILL.md` + `audit.py` selbst entwickelt
- skill-auditor als installierter Skill registriert unter `~/.claude/skills/skill-auditor/`
- Grundworkflow: automatischer Scan via `audit.py`, Fallback auf manuellen Grep-Scan
- 6 Risiko-Kategorien: Netzwerk, Code-Ausführung, Installation, Dateizugriff, Prompt Injection, Obfuskation
- Trigger: proaktive Aktivierung bei neuen Skill-Installationen
