# Cowork: eigener Prüfbereich innerhalb des Skill Auditors für Claude

Stand 2026-11-08. Cowork ist eine Oberfläche des Skill Auditors `skill-auditor` (`--surface cowork`), keine eigene Edition. Die Geräte-VM und ein Cloud-Arbeitsbereich sind unterschiedliche Umgebungen; weder Pfade noch Python-Versionen oder Freigaben sind übertragbar.

## Aktueller Status

Der vollständige Cowork-Geräte-Scanner ist **vorläufig zurückgestellt**. Im übermittelten Geräte-Test wurde Python 3.10.12 festgestellt; erforderlich bleibt mindestens 3.11. Das ist ein datierter Befund, keine Behauptung über jede heutige Cowork-Sitzung. In begrenzten Suchorten wurde damals keine geeignete Alternative gefunden. Keine automatische Installation, Absenkung der Mindestversion, Nutzung einer Cloud-Laufzeit oder Ausweichkopie.

Der Einstieg `--surface cowork` erzeugt deshalb ausschließlich einen Nichtausführungsbericht: `scanner_executed: false`, `scan_mode: content_review_only`. Er liest kein Prüfobjekt, selbst wenn der aufrufende Rechner Python ab 3.11 hat. Eine andere `--surface`-Angabe hebt die fachliche Zurückstellung nicht auf. Der Einstieg kann die echte Sitzung nicht selbst erkennen; die Profilwahl ist eine Selbstauskunft, keine technische Zugriffsbarriere.

## Begrenzte Inhaltsprüfung

1. Tatsächliche Sitzung, Werkzeuge und ausdrücklich freigegebenen Ordner feststellen. Keine Windows-/Linux-Pfade raten. Ein angezeigtes Arbeitsverzeichnis beweist keinen Zugriff auf den Host oder Nextcloud.
2. Nur bereits sichtbare Texte oder ausdrücklich bereitgestellte, kleine lesbare Dateien beurteilen. Bei fehlendem Zugriff oder „Workspace still downloading“ den betroffenen Schritt stoppen. Nicht automatisch über Kopier-, Staging- oder andere Umgebungswerkzeuge ausweichen.
3. Unbekannte Archive nicht außerhalb des Auditors entpacken. Keine Skripte, Plugins, Pakete oder MCP-Server starten; keine Installation und keine Rechteänderung.
4. Im Ergebnis den tatsächlich betrachteten Textumfang benennen. Scanner nicht ausgeführt; vollständige Prüfabdeckung nicht gegeben. Sichtbare rote Befunde bleiben bestehen. Danach der feste Abschluss „Wie geht es weiter?“ mit dem Hilfsprompt für fehlende Abdeckung.
5. Keine Bestandsübersicht anbieten, auch nicht bei freigegebenem Skill-Ordner: Ohne Scanner wäre sie nicht einlösbar.

## Spätere Wiederaufnahme – erst nach eigenem Auftrag

Eine neue lesende Geräteprüfung kann Python-Version, Interpreterpfad, Betriebssystem und Dateizugriff im selben tatsächlichen Gerätewerkzeug belegen. Kleine synthetische Datei verwenden; keine Suche nach privaten Dateien oder Geheimnissen. Python-Version beispielsweise mit dem bereits nachgewiesenen Interpreter und `-I -S -B -c "import sys,platform; print(sys.version); print(sys.executable); print(platform.system())"` abfragen. Vorhandensein allein beweist keinen Wartungsstand.

Zusätzlich nötig: bekannte Herkunft/Pflege, geeigneter Python-Stand, nachgewiesener Zugriff auf den Auditor-Kern und das Prüfobjekt in derselben Umgebung, funktionierende Prozesswächter, ungefährliche Testfälle und nachvollziehbarer Berichtsexport. Erst danach über eine Aufhebung der Cowork-Sperre entscheiden. Der Auditor installiert oder aktiviert dafür nichts.

## Bereitstellungsweg und Beweisgrenze

Laut [Claude-Dokumentation](https://code.claude.com/docs/en/skills#use-skills-in-cowork-and-cloud-sessions), gelesen am 2026-10-28, beziehen Cowork-Sitzungen aktivierte Konto-Skills zum Sitzungsstart. Der lokale Ordner `~/.claude/skills` ist dafür kein Nachweis. Sichtprobe vom 2026-11-08: Ein in Claude Desktop hochgeladener Konto-Skill `skill-auditor` war in Cowork aufrufbar; eine Prüfung wurde dabei nicht ausgeführt. Eine echte Bedienprobe in Cowork steht noch aus. Keine zusätzliche Plugin-Verpackung oder MCPB-Installation ableiten.
