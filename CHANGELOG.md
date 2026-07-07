# Changelog: skill-auditor

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
