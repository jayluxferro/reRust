#!/usr/bin/env python3
"""Dev wrapper: the full repack pipeline lives in src/rerust/pipeline.py.

Kept for repo convention and muscle memory — `rerust patch` (installed wheel
or checkout) runs the exact same functions in-process via rerust.cli.cmd_patch.
The pipeline docstring there is the authoritative description of the steps:

    scripts/repack_apk.py app.apk --proxy http://10.0.2.2:8080 --out app.rerust.apk
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from rerust.pipeline import main  # noqa: E402  (path set above)

if __name__ == "__main__":
    sys.exit(main())
