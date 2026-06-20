from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .app import PromptParole
from .errors import NotConfiguredError, PromptParoleError


SUPPORTED_AGENTS = {"claude-code", "codex"}


def format_dt(value: datetime | None) -> str:
    if value is None:
        return "the scheduled unlock time"
    return value.strftime("%Y-%m-%d %H:%M %Z").strip()


def block_reason(agent: str, locked_until: datetime | None) -> str:
    _ = agent
    return (
        "Prompt Parole: curfew is active until "
        f"{format_dt(locked_until)}. You can inspect progress, but new prompts need "
        "`prompt-parole unlock`."
    )


def hook_payload(agent: str, app: PromptParole | None = None) -> dict[str, Any] | None:
    if agent not in SUPPORTED_AGENTS:
        raise ValueError(f"Unsupported agent {agent!r}.")
    parole = app or PromptParole()
    decision = parole.decision()
    if decision.allowed:
        return None
    parole.record_block(agent, decision)
    payload: dict[str, Any] = {
        "decision": "block",
        "reason": block_reason(agent, decision.locked_until),
    }
    if agent == "claude-code":
        payload["suppressOriginalPrompt"] = True
    return payload


def hook_stdout(agent: str, app: PromptParole | None = None) -> str:
    try:
        payload = hook_payload(agent, app)
    except NotConfiguredError:
        return ""
    except PromptParoleError as exc:
        payload = {
            "decision": "block",
            "reason": f"Prompt Parole configuration error: {exc}",
        }
    if payload is None:
        return ""
    return json.dumps(payload, separators=(",", ":")) + "\n"
