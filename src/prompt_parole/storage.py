from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass


def read_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_atomic(path: Path, data: Any, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        try:
            os.chmod(path, mode)
        except PermissionError:
            pass
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def append_event(path: Path, event: dict[str, Any]) -> None:
    ensure_private_dir(path.parent)
    clean = {"ts": now_iso(), **event}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(clean, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
