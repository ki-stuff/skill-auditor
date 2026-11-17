"""Feste technische Diagnosen ohne Pfade oder Text aus dem Prüfobjekt."""
ERROR_MESSAGES = {
    'input_not_found': 'Prüfpfad oder benötigter Eingabebestandteil nicht vorhanden.',
    'input_access_denied': 'Lesezugriff auf die Eingabe verweigert.',
    'guard_unavailable': 'Prozesswächter nicht verfügbar; Prüfung abgebrochen.',
    'worker_timeout': 'Hartes Zeitbudget überschritten; Worker beendet.',
    'worker_failed': 'Worker abgebrochen; Speicherlimit oder Laufzeitfehler.',
    'worker_output_error': 'Worker-Ausgabe unvollständig oder ungültig; Prüfung abgebrochen.',
    'privacy_limit': 'Ausgabemaskierung überschreitet Grenze; Details zurückgehalten.',
}
