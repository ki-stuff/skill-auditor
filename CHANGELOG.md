# Changelog: skill-auditor

## v2.7.1 – 2026-11-17 – Neutrale Darstellung, Kontaktweg

- **Neutrales Dashboard:** Kopfzeile und Fußzeile zeigen nur noch „Skill Auditor“, ohne Anbieterkennzeichen und ohne externe Links.
- **Kernname** im JSON-Bericht jetzt `skill-auditor-core` (gemeinsamer Kern 1.2.1). Berichte älterer Fassungen mit dem bisherigen Kernnamen bleiben lesbar; sie werden wie bei jeder Kernänderung als „Kern geändert“ markiert.
- **README:** Hinweis auf Erkennungslücken älterer Fassungen, Kontaktweg über GitHub-Issues, Vergleichsaussagen über andere Werkzeuge entfernt.
- Scannerregeln, Ampellogik und Schutzgrenzen unverändert.

## v2.7.0 – 2026-11-08 – Eine Fassung für alle Claude-Oberflächen, aktive Hilfe

- **Eine Fassung statt zwei:** `skill-auditor` gilt jetzt für Claude Code, Claude Desktop, claude.ai und Cowork und löst `skill-auditor-desktop` ab. Anlass: Ein in Claude Desktop hochgeladener Skill steht im ganzen Konto zur Verfügung (Chat, Cowork, Code-Tab); zwei Fassungen hätten sich dort überschnitten.
- **Umgebungsprüfung vor dem Start:** `--capabilities --surface <oberfläche>` misst Paketvollständigkeit (gegen `BUNDLE.json`), Python ab 3.11 und lesbare Skill-Ordner, ohne deren Inhalt aufzulisten, und nennt die passenden Startoptionen. Die Oberfläche selbst bleibt eine Selbstauskunft.
- **Fester Startdialog** „Was möchtest du tun?“: Skill prüfen, Bestandsübersicht (nur im Terminal bzw. Code-Tab), Hilfe zu einem Ergebnis, kurz erklären.
- **Fester Abschluss** „Wie geht es weiter?“ nach jedem Ergebnis, mit aktivem Hilfsangebot bei Gelb, Grau und Rot.
- **Hilfe bei Rot:** eigener Hilfsprompt und Leseschritt. Fundstellen werden im Original gelesen und als Dokumentationstext, zweckgebundenes Werkzeugverhalten oder echtes Risiko eingeordnet; die rote Ampel bleibt bestehen.
- **Installation unvollständig:** Fehlt `scripts/audit.py` oder weicht das Paket von `BUNDLE.json` ab, meldet der Auditor das sofort, statt zu improvisieren.
- **Bestandsübersicht** und `--render-inventory` nur noch im Terminal bzw. Code-Tab (`--surface cli`). In Chat, claude.ai und Cowork wird sie nicht angeboten.
- **Cowork:** Geräte-Scanner bleibt vorläufig zurückgestellt; die Cowork-Anleitung ist jetzt Teil dieses Pakets.
- README: Installation je Oberfläche, Hinweis „komplettes ZIP, nie nur die SKILL.md“, Umstieg von `skill-auditor-desktop`, unverbindliche Modell-Empfehlung.
- Scannerregeln und Ampellogik unverändert.

## v2.6.0 – 2026-11-08 – Gemeinsamer Kern, sichere Auswertung

- **Gemeinsamer Scanner-Kern 1.1.0** für Codex, Claude Code und Claude Desktop. Neben Skill-Ordnern werden jetzt auch Einzeldateien, ZIP/MCPB/DXT/Wheel- und TAR-Archive (direkt gelesen, nie entpackt), Agent-Plugins, npm-/Python-Pakete und MCP-Konfigurationen statisch geprüft.
- **Getrennte Aussagen:** Risiko, Prüfabdeckung (was wurde tatsächlich gelesen) und Aktualität werden einzeln ausgewiesen. Grau bedeutet „nicht ausreichend geprüft“ und wird nie zu Grün.
- **Konkrete nächste Schritte** und ein kopierbarer Hilfsprompt für gelbe und graue Ergebnisse.
- **HTML-Auswertung** mit Überblick, Kennzahlen, „Hier solltest du zuerst hinsehen“ und aufklappbaren technischen Details. Passives HTML ohne Skripte und ohne externe Ressourcen.
- **Schutz beim Lesen:** Größen-, Zeit- und Speichergrenzen, keine Links/Reparse-Punkte, keine Ausführung von Prüfobjektcode. Erkannte Geheimwerte werden in Berichten maskiert, Rohbelege zurückgehalten.
- **Keine automatische Ablage mehr im geprüften Skill:** Berichte entstehen nur noch an einem ausdrücklich gewählten neuen Ziel (`--output`, `--html`, `--inventory-html`).
- **Warnwörter sind kein Freifahrtschein:** Steht vor einer gefährlichen Anweisung ein Satz mit „never“, „avoid“ oder „do not“, bleibt eine gefährliche Musterkombination ein automatisches Rot. Treffer neben Warnwörtern oder in Codeblöcken der SKILL.md werden höchstens auf Gelb gesenkt, nie auf Grün. Codeblöcke in README und Referenzen bleiben reiner Dokumentationskontext.
- **Altberichte:** Eine `audit-result.json` früherer Fassungen im Skill-Ordner wird am exakten Format erkannt, als Ausnahme ausgewiesen und nicht mehr als Skill-Inhalt gescannt. Vorher verursachten ihre alten Fundstellen-Auszüge falsche Treffer und graue Abdeckung. Verweist eine andere Datei des Skills auf die `audit-result.json`, wird sie trotzdem vollständig geprüft, damit sich darin keine Anweisung verstecken lässt.
- **Verweise auf Codebeispiele:** Eine gefährliche Musterkombination in einem Codeblock von README oder Referenzdateien wird gelb, sobald eine andere Datei auf diese Datei verweist (z. B. „folge dem Setup in README.md“). Ohne Verweis bleibt sie Dokumentationskontext. In der SKILL.md selbst ist eine solche Kombination immer mindestens gelb.
- **Inventar robuster:** Die Maskierung arbeitet pro Skill. Erreicht ein einzelner Skill die Grenze, wird nur dieser Eintrag zurückgehalten, statt das ganze Inventar abzubrechen. Das Ausgabeziel wird vor dem Scan geprüft, Fehlermeldungen nennen den Grund im Klartext.
- Python ab 3.11 erforderlich, nur Standardbibliothek, keine automatische Nachinstallation.
- **Bestandsübersicht als Themen-Kacheln:** Das Inventar-Dashboard zeigt die Skills wieder als Kacheln, gruppiert nach Themen, mit deutscher Kurzbeschreibung und Ampel, dazu ein Filter nach Ergebnis (ohne JavaScript). Die Themen vergibt die KI passend zum jeweiligen Bestand (`--categories`); sie ändern nie die Ampel. `--render-inventory` stellt eine gespeicherte Bestandsdatei ohne erneuten Scan dar.
- **Claude-Code-Inventar:** persönliche und projektbezogene Skills sowie registrierte Plugin-Skills (`installed_plugins.json`). Registrierung ist kein Vertrauensnachweis; Marketplace-Plugins werden genauso geprüft.
- **Geändert gegenüber v2.5:** `audit-result.json` wird nicht mehr in den geprüften Ordner geschrieben. Das Inventar ordnet frühere Berichte nur lesend als unbestätigte Historie zu.

## v2.5 — 2026-09-11 — Desktop-Edition ausgegliedert

Für claude.ai/Claude Desktop gibt es jetzt eine eigene, separate Fassung: [skill-auditor-desktop](https://github.com/ki-stuff/skill-auditor-desktop). Grund für ein eigenes Repo statt eines Flags/Modus in diesem hier: claude.ai/Desktop-Skills laufen in einer isolierten Sandbox ohne Zugriff auf das lokale Dateisystem des Nutzers — diese CLI-Fassung setzt direkten Zugriff auf `~/.claude/skills/` und beliebige lokale Verzeichnisse voraus, das lässt sich nicht als Option in derselben Codebasis abbilden, ohne den Inventar-Modus (Phase 7) auf der Desktop-Seite vorzutäuschen.

- **`SKILL.md`**, **`README.md`**: Verweis auf die Desktop-Fassung ergänzt, direkt am Anfang, damit Nutzer der falschen Umgebung sofort zur passenden Fassung finden.
- Keine funktionalen Änderungen an dieser CLI-Fassung.

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
- **`SKILL.md`**: Phase 0 um optionalen skills.sh-Badge-Check erweitert (Socket/Snyk/Gen Agent Trust Hub als Zusatzsignal, ausdrücklich keine alleinige Entscheidungsgrundlage). Bei einem auffälligen Badge: erst eigenen Codefence-Filter gegenprüfen. Neues Report-Feld "Zusatzsignal skills.sh" in Phase 6.
- **`README.md`**: neuer Abschnitt "How this compares to similar tools" — Abgrenzung zu `getsentry/skills` → `security-review` (häufige Verwechslung; das eigentliche Pendant dort heißt `skill-scanner`), REJECT-Kombinationslogik, Codefence-Masking und Inventar-Modus beschrieben.

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
