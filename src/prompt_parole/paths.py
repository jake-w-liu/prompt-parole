from __future__ import annotations

import os
from pathlib import Path


APP_DIR_ENV = "PROMPT_PAROLE_HOME"


def app_dir() -> Path:
    override = os.environ.get(APP_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".prompt-parole"


def config_path(base: Path | None = None) -> Path:
    return (base or app_dir()) / "config.json"


def secret_path(base: Path | None = None) -> Path:
    return (base or app_dir()) / "secret.json"


def state_path(base: Path | None = None) -> Path:
    return (base or app_dir()) / "state.json"


def events_path(base: Path | None = None) -> Path:
    return (base or app_dir()) / "events.jsonl"
