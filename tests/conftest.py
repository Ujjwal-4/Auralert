"""Shared pytest setup: every test run uses an isolated temporary database.

DB_PATH is set at import time (before any test module imports ``scamshield.cases.service``,
which initializes the database on import) so tests never create or modify data/scamshield.db.
"""

import os
import tempfile
from pathlib import Path

_TMP_DIR = tempfile.mkdtemp(prefix="scamshield-tests-")
os.environ["DB_PATH"] = str(Path(_TMP_DIR) / "test_scamshield.db")

from scamshield.cases.db import init_db

init_db()
