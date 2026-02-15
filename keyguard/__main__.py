"""Allow running as ``python -m keyguard``."""

from __future__ import annotations

import sys
from pathlib import Path

# Support direct execution via file path (e.g., ``python keyguard/__main__.py``)
if __package__ in (None, ""):
    _project_root = Path(__file__).resolve().parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from keyguard.main import main

main()
