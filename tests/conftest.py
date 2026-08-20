"""Shared test fixtures and import path setup.

Makes the ``src/`` package importable without an editable install, and
exposes the repository's raw/processed data paths to the data-quality tests.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def raw_csv(project_root):
    return project_root / "data" / "raw" / "canary_alerts_raw.csv"


@pytest.fixture(scope="session")
def processed_dir(project_root):
    return project_root / "data" / "processed"
