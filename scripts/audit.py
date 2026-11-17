#!/usr/bin/env python3
"""Eigenständiger skill-auditor-Einstieg; Implementierung im mitgelieferten auditor_core."""
import sys
import importlib.util
from pathlib import Path

_CORE = Path(__file__).resolve().parent / "auditor_core"
_existing = sys.modules.get("auditor_core")
if _existing is not None:
    if Path(_existing.__file__).resolve() != (_CORE / "__init__.py").resolve():
        raise ImportError("Fremder auditor_core bereits geladen")
else:
    _spec = importlib.util.spec_from_file_location(
        "auditor_core", _CORE / "__init__.py", submodule_search_locations=[str(_CORE)])
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["auditor_core"] = _module
    _spec.loader.exec_module(_module)

from auditor_core import SCANNER_VERSION, SCANNER_BASE_COMMIT
from auditor_core import rules as _rules, models as _models, scanner as _scanner
from auditor_core import reports as _reports, inventory as _inventory, cli as _cli

# Bestehende Python-Aufrufer behalten Funktionen und Konstanten aus audit.py.
for _part in (_rules, _models, _scanner, _reports, _inventory, _cli):
    for _name in dir(_part):
        if not _name.startswith("__"):
            globals()[_name] = getattr(_part, _name)

if __name__ == "__main__":
    if sys.platform == "win32":
        for _stream in (sys.stdout, sys.stderr):
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main(edition='claude'))
